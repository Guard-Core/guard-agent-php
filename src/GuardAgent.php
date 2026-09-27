<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardAgent;

use RenzoFranceschini\GuardAgent\Config\AgentConfig;
use RenzoFranceschini\GuardAgent\Config\AgentConfigResolver;
use RenzoFranceschini\GuardAgent\EventBuffer\EventBuffer;
use RenzoFranceschini\GuardAgent\Log\AgentLogger;
use RenzoFranceschini\GuardAgent\Log\DefaultAgentLogger;
use RenzoFranceschini\GuardAgent\Model\AgentStatus;
use RenzoFranceschini\GuardAgent\Model\DynamicRules;
use RenzoFranceschini\GuardAgent\Model\SecurityEvent;
use RenzoFranceschini\GuardAgent\Model\SecurityMetric;
use RenzoFranceschini\GuardAgent\Model\WireFormat;
use RenzoFranceschini\GuardAgent\Persistence\RedisHandler;
use RenzoFranceschini\GuardAgent\Persistence\StreamRedisClient;
use RenzoFranceschini\GuardAgent\Transport\HttpTransport;
use RenzoFranceschini\GuardAgent\Transport\TransportInterface;
use RenzoFranceschini\GuardAgent\Utils\Backoff;
use RenzoFranceschini\GuardAgent\Utils\ErrorHook;
use RenzoFranceschini\GuardAgent\Utils\HeadersRedactor;

/**
 * GuardAgent, the top-level telemetry client, mirroring guard_agent/client.py
 * (GuardAgentHandler) plus its mixin split: _client_ingest.py (send_event/
 * send_metric), _client_flush.py (flush_buffer with failure streaks and
 * backoff), _client_loops.py (flush/status loops), _client_status.py
 * (get_status/get_stats/health_check).
 *
 * PHP runtime model (deliberate deviation, documented in AGENTS.md/README):
 * PHP has no background threads. start() marks the agent running and loads
 * crash-recovery state; the flush and status loops are host-driven through
 * tick(). A long-running worker calls tick() from its own loop (pcntl-free);
 * a request-scoped application calls flushBuffer() from its shutdown hook.
 *
 * Failure policy (mirrored from Python):
 * - sendEvent/sendMetric NEVER throw and never block the request path beyond
 *   one buffer write (the "block" overflow policy being the one deliberate,
 *   opt-in exception, which drains inline).
 * - flushBuffer NEVER throws: transport failures requeue the batch in memory,
 *   retain its Redis keys for crash recovery, and back off per-kind
 *   (flushInterval * 2^(streak-1), capped at 300s) before the next attempt.
 * - tick/getStatus/getStats/healthCheck NEVER throw.
 * - start() may throw (bad config, failed transport init); stop() is
 *   idempotent and flushes what is buffered.
 */
final class GuardAgent
{
    /** Backoff ceiling between flush attempts after failures (Python: 300s). */
    private const PARTIAL_FAILURE_MAX_BACKOFF_SECONDS = 300.0;

    /** After this many consecutive loop failures, log at error level (Python: 3). */
    private const LOOP_ERROR_LOG_THRESHOLD = 3;

    /** Buffer occupancy ratio that reports a degraded status. */
    private const DEGRADED_BUFFER_RATIO = 0.9;

    /** Buffer occupancy ratio that fails the health check. */
    private const HEALTH_BUFFER_RATIO = 0.95;

    /** Lifetime failure rate above which the status reports degraded. */
    private const DEGRADED_FAILURE_RATE = 0.1;

    /** Lifetime failure rate above which the health check fails. */
    private const HEALTH_FAILURE_RATE_MAX = 0.5;

    public readonly AgentConfig $config;

    public readonly EventBuffer $buffer;

    public readonly TransportInterface $transport;

    private readonly AgentLogger $logger;

    private readonly float $startTime;

    private bool $running = false;

    private bool $closed = false;

    private ?RedisHandler $redisHandler = null;

    private bool $ownsRedisHandler = false;

    private int $inFlightFlushes = 0;

    public int $eventsSent = 0;

    public int $metricsSent = 0;

    public int $eventsFailed = 0;

    public int $metricsFailed = 0;

    private int $flushConsecutiveFailures = 0;

    private int $statusConsecutiveFailures = 0;

    private ?bool $lastStatusPushOk = null;

    private int $rulesConsecutiveFailures = 0;

    private ?float $nextRulesRefreshAt = null;

    private ?DynamicRules $cachedRules = null;

    private float $rulesLastUpdate = 0.0;

    public int $rulesFetched = 0;

    private int $eventsFailureStreak = 0;

    private int $metricsFailureStreak = 0;

    private float $eventsRetryAfter = 0.0;

    private float $metricsRetryAfter = 0.0;

    private ?float $nextStatusPushAt = null;

    /**
     * @param AgentConfig|array<string, mixed> $config resolved config or raw input
     *
     * @throws \RenzoFranceschini\GuardAgent\Exception\ConfigException
     */
    public function __construct(AgentConfig|array $config, ?TransportInterface $transport = null)
    {
        $this->config = is_array($config) ? AgentConfigResolver::resolve($config) : $config;
        $this->logger = $this->config->logger ?? new DefaultAgentLogger();
        $this->buffer = new EventBuffer($this->config);
        $this->buffer->drainCallback = function (): void {
            $this->flushBuffer();
        };
        $this->transport = $transport ?? new HttpTransport($this->config);
        $this->startTime = microtime(true);
        $this->logger->info('Guard Agent initialized');
    }

    // ------------------------------------------------------------------
    // Redis integration
    // ------------------------------------------------------------------

    /**
     * Attach a Redis handler used for durable buffering and load any pending
     * items persisted by a previous process (mirrors initialize_redis).
     */
    public function initializeRedis(RedisHandler $redisHandler): void
    {
        $this->redisHandler = $redisHandler;
        $this->ownsRedisHandler = false;
        $this->buffer->initializeRedis($redisHandler);
        $this->logger->info('Redis integration initialized');
    }

    public function redisHandler(): ?RedisHandler
    {
        return $this->redisHandler;
    }

    /**
     * Build a Redis handler from config.redis when no handler was injected.
     * Failure to connect degrades to memory-only buffering with a warning;
     * telemetry must never keep the host app from serving traffic.
     */
    private function ensureRedisPersistence(): void
    {
        $redisConfig = $this->config->redis;
        if ($redisConfig === null || $this->redisHandler !== null) {
            return;
        }
        try {
            $client = new StreamRedisClient(
                $redisConfig->url,
                $redisConfig->password,
                $redisConfig->db,
                $redisConfig->commandTimeoutMs / 1000.0,
            );
            $handler = new RedisHandler($client, $redisConfig->keyPrefix, $this->logger);
            $handler->ping();
            $this->initializeRedis($handler);
            $this->ownsRedisHandler = true;
        } catch (\Throwable $error) {
            $this->logger->warning(
                'Redis persistence disabled (connection failed): ' . ErrorHook::message($error)
            );
        }
    }

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    /**
     * Mark the agent running, load crash-recovery state, and initialize the
     * transport. Idempotent. This method may throw (mirroring Python start()).
     *
     * @throws \Throwable
     */
    public function start(): void
    {
        if ($this->running) {
            $this->logger->warning('Agent is already running');

            return;
        }

        try {
            $this->ensureRedisPersistence();
            $this->transport->initialize();

            $this->running = true;
            $this->nextStatusPushAt = microtime(true) + $this->config->statusInterval;
            $this->nextRulesRefreshAt = microtime(true) + $this->config->dynamicRuleInterval;

            $this->logger->info('Guard Agent started successfully');
        } catch (\Throwable $error) {
            $this->logger->error('Failed to start agent: ' . ErrorHook::message($error));
            $this->stop();
            throw $error;
        }
    }

    /**
     * Stop the agent: final flush, close the transport, release Redis.
     * Idempotent and never throws (mirrors stop/close).
     */
    public function stop(): void
    {
        if ($this->closed) {
            return;
        }
        $this->closed = true;
        $this->running = false;
        $this->nextStatusPushAt = null;
        $this->nextRulesRefreshAt = null;

        $this->flushBuffer();
        try {
            $this->transport->close();
        } catch (\Throwable $error) {
            $this->logger->warning('transport.close failed: ' . ErrorHook::message($error));
        }

        if ($this->ownsRedisHandler && $this->redisHandler !== null) {
            $handler = $this->redisHandler;
            $this->redisHandler = null;
            $this->ownsRedisHandler = false;
            try {
                $handler->close();
            } catch (\Throwable $error) {
                $this->logger->warning('redis close failed: ' . ErrorHook::message($error));
            }
        }

        $this->logger->info('Guard Agent stopped');
    }

    /** Alias for stop() (mirrors close). */
    public function close(): void
    {
        $this->stop();
    }

    public function isRunning(): bool
    {
        return $this->running;
    }

    // ------------------------------------------------------------------
    // Host-driven loops (PHP replacement for background tasks)
    // ------------------------------------------------------------------

    /**
     * Host-driven heartbeat: flush when the high-watermark or flush interval
     * triggers, push a status report when the status interval elapses, and
     * refresh the dynamic rules when the dynamic rule interval elapses. Call
     * this from your worker loop or once per request. Never throws.
     */
    public function tick(): void
    {
        try {
            if (!$this->running || $this->closed) {
                return;
            }
            $this->flushIfNeeded();
            $this->maybePushStatus();
            $this->maybeRefreshRules();
        } catch (\Throwable $error) {
            $this->logger->error('Error in agent tick: ' . ErrorHook::message($error));
        }
    }

    /**
     * Trigger a flush when the buffer is at the watermark or the flush
     * interval has elapsed, throttled by maxConcurrentFlushes (mirrors
     * _flush_if_needed). Never throws.
     */
    public function flushIfNeeded(): void
    {
        if ($this->inFlightFlushes >= $this->config->maxConcurrentFlushes) {
            return;
        }

        $bufferSize = $this->buffer->getBufferSize();
        if ($bufferSize === 0) {
            return;
        }

        $timeSinceLastFlush = $this->buffer->lastFlushTime === null
            ? $this->config->flushInterval + 1
            : microtime(true) - $this->buffer->lastFlushTime;

        $atWatermark = $bufferSize >= $this->config->bufferSize * $this->config->highWatermarkRatio;
        $timeElapsed = $timeSinceLastFlush >= $this->config->flushInterval;

        if (!$atWatermark && !$timeElapsed) {
            return;
        }

        $this->logger->debug("Triggering buffer flush - size: {$bufferSize}");
        $this->inFlightFlushes++;
        try {
            $this->flushBuffer();
        } finally {
            $this->inFlightFlushes--;
        }
    }

    /**
     * Push a status report when the status interval elapsed. In the Python
     * agent this is the status loop; here it is driven by tick().
     */
    private function maybePushStatus(): void
    {
        $now = microtime(true);
        if ($this->nextStatusPushAt === null || $now < $this->nextStatusPushAt) {
            return;
        }
        $this->nextStatusPushAt = $now + $this->config->statusInterval;

        $ok = false;
        try {
            $ok = $this->transport->sendStatus($this->getStatus());
        } catch (\Throwable $error) {
            $this->logger->error('Status push failed: ' . ErrorHook::message($error));
        }
        $this->lastStatusPushOk = $ok;
        if ($ok) {
            $this->statusConsecutiveFailures = 0;

            return;
        }
        $this->statusConsecutiveFailures++;
        $this->logLoopFailure('status loop', $this->statusConsecutiveFailures, 'send_status returned false');
    }

    private function logLoopFailure(string $loopName, int $count, string $cause): void
    {
        $message = "{$loopName} failed {$count} consecutive time(s); cause: {$cause}";
        if ($count >= self::LOOP_ERROR_LOG_THRESHOLD) {
            $this->logger->error($message);
        } else {
            $this->logger->warning($message);
        }
    }

    /**
     * Refresh the dynamic rules when the rules interval elapsed. In the
     * Python agent this is the rules loop; here it is driven by tick().
     * A null refresh counts as a consecutive loop failure (the transport
     * logs the underlying cause and returns null), mirroring the loop
     * failure bookkeeping of the other loops.
     */
    private function maybeRefreshRules(): void
    {
        $now = microtime(true);
        if ($this->nextRulesRefreshAt === null || $now < $this->nextRulesRefreshAt) {
            return;
        }
        $this->nextRulesRefreshAt = $now + $this->config->dynamicRuleInterval;

        $rules = $this->getDynamicRules();
        if ($rules !== null) {
            $this->rulesConsecutiveFailures = 0;

            return;
        }
        $this->rulesConsecutiveFailures++;
        $this->logLoopFailure('rules loop', $this->rulesConsecutiveFailures, 'fetch returned null');
    }

    // ------------------------------------------------------------------
    // Dynamic rules (never throws)
    // ------------------------------------------------------------------

    /**
     * Return the latest dynamic rules, or null when unavailable (mirrors
     * RulesMixin.get_dynamic_rules, guard_agent/_client_loops.py:19-38). The
     * cached copy is served while it is younger than its own ttl (seconds);
     * a failed fetch returns the previously fetched rules so an outage never
     * surfaces as a hard failure (the transport logs and returns null).
     */
    public function getDynamicRules(): ?DynamicRules
    {
        try {
            $currentTime = microtime(true);

            if (
                $this->cachedRules !== null
                && $currentTime - $this->rulesLastUpdate < $this->cachedRules->ttl
            ) {
                return $this->cachedRules;
            }

            $rules = $this->transport->fetchDynamicRules();
            if ($rules !== null) {
                $this->cachedRules = $rules;
                $this->rulesLastUpdate = $currentTime;
                $this->rulesFetched++;
                $this->logger->debug('Dynamic rules updated');

                return $rules;
            }

            return null;
        } catch (\Throwable $error) {
            $this->logger->error('Failed to fetch dynamic rules: ' . ErrorHook::message($error));

            return $this->cachedRules;
        }
    }

    // ------------------------------------------------------------------
    // Ingest path (never throws)
    // ------------------------------------------------------------------

    /**
     * Enqueue a security event for delivery. Accepts a SecurityEvent instance
     * or an array carrying the known fields (camelCase or snake_case).
     * Never blocks beyond a buffer write and never throws: failures are
     * logged and dropped.
     */
    public function sendEvent(mixed $input): void
    {
        if (!$this->config->enableEvents) {
            return;
        }
        try {
            $event = SecurityEvent::normalize($input);
            $redacted = $event->withMetadata(
                self::asMetadataArray(HeadersRedactor::sanitize($event->metadata, $this->config->sensitiveHeaders))
            );
            $this->buffer->addEvent($redacted);
            $this->logger->debug("Event buffered: {$redacted->eventType} from {$redacted->ipAddress}");
        } catch (\Throwable $error) {
            $this->logger->error('Failed to buffer event: ' . ErrorHook::message($error));
        }
    }

    /**
     * Enqueue a metric for delivery. Accepts a SecurityMetric instance or an
     * array carrying the known fields. Never throws.
     */
    public function sendMetric(mixed $input): void
    {
        if (!$this->config->enableMetrics) {
            return;
        }
        try {
            $metric = SecurityMetric::normalize($input);
            $redacted = $metric->withTags(
                self::asStringArray(HeadersRedactor::sanitize($metric->tags, $this->config->sensitiveHeaders))
            );
            $this->buffer->addMetric($redacted);
            $this->logger->debug("Metric buffered: {$redacted->metricType} = {$redacted->value}");
        } catch (\Throwable $error) {
            $this->logger->error('Failed to buffer metric: ' . ErrorHook::message($error));
        }
    }

    // ------------------------------------------------------------------
    // Flush path
    // ------------------------------------------------------------------

    /** Force an immediate send of any buffered events and metrics. Never throws. */
    public function flushBuffer(): void
    {
        try {
            $this->flushEvents();
            $this->flushMetrics();
            $this->flushConsecutiveFailures = 0;
        } catch (\Throwable $error) {
            // Mirror of the Python flush-loop catch: count consecutive loop
            // failures (the loop body itself is host-driven in this port).
            $this->flushConsecutiveFailures++;
            $this->logLoopFailure('flush loop', $this->flushConsecutiveFailures, ErrorHook::message($error));
        }
    }

    /**
     * Describe where unsent items wait for retry, based on whether a Redis
     * handler is attached to the buffer. Without Redis the items live only in
     * the in-memory buffer, so claiming Redis retention would be misleading
     * (mirrors Python _client_flush.FlushMixin._retention_description).
     */
    private function retentionDescription(string $kind): string
    {
        $hasRedis = $this->buffer->redisHandler() !== null;
        $memoryPart = 'requeued in memory';
        $redisPart = $hasRedis ? ' and retained in Redis' : '';

        return $memoryPart . $redisPart . ' (' . $kind . ')';
    }

    /**
     * Flush events with per-kind failure streaks and backoff, mirroring
     * _flush_events. On failure the batch is requeued in memory, its Redis
     * keys retained, and a per-kind gate enforced before the next attempt. A
     * transport exception is re-raised after the requeue (caught by
     * flushBuffer), mirroring the Python control flow.
     */
    private function flushEvents(): void
    {
        if (microtime(true) < $this->eventsRetryAfter) {
            return;
        }

        [$events, $keys] = $this->buffer->flushEventsWithKeys();
        if ($events === []) {
            return;
        }

        $success = false;
        $exception = null;
        try {
            $success = $this->transport->sendEvents($events);
        } catch (\Throwable $caught) {
            $success = false;
            $exception = $caught;
        }

        if ($success) {
            $this->buffer->confirmEventRedisKeys($keys);
            $this->eventsSent += count($events);
            $this->logger->debug('Flushed ' . count($events) . ' events');
            if ($this->eventsFailureStreak > 0) {
                $this->logger->warning(
                    'Events flush recovered after ' . $this->eventsFailureStreak . ' consecutive partial failure(s)'
                );
            }
            $this->eventsFailureStreak = 0;
            $this->eventsRetryAfter = 0.0;

            return;
        }

        $evictedKeys = $this->buffer->requeueEventsInMemory($events, $keys);
        if ($evictedKeys !== []) {
            $this->buffer->confirmEventRedisKeys($evictedKeys);
        }
        $this->eventsFailed += count($events);
        $this->eventsFailureStreak++;
        $delay = Backoff::calculate(
            $this->eventsFailureStreak - 1,
            (float) $this->config->flushInterval,
            self::PARTIAL_FAILURE_MAX_BACKOFF_SECONDS
        );
        $this->eventsRetryAfter = microtime(true) + $delay;
        if ($this->eventsFailureStreak === 1) {
            $this->logger->warning(
                'Failed to send ' . count($events) . ' events; ' .
                $this->retentionDescription('events') . ' for retry; ' .
                sprintf('backing off up to %.0fs between attempts', $delay)
            );
        }
        if ($exception !== null) {
            $this->logger->error('Transport raised sending events: ' . ErrorHook::message($exception));
            ErrorHook::fire($this->config->onError, $this->logger, 'flush_events', $exception, [
                'batchSize' => count($events),
            ]);
            throw $exception;
        }
    }

    /** Flush metrics; see flushEvents for the failure semantics. */
    private function flushMetrics(): void
    {
        if (microtime(true) < $this->metricsRetryAfter) {
            return;
        }

        [$metrics, $keys] = $this->buffer->flushMetricsWithKeys();
        if ($metrics === []) {
            return;
        }

        $success = false;
        $exception = null;
        try {
            $success = $this->transport->sendMetrics($metrics);
        } catch (\Throwable $caught) {
            $success = false;
            $exception = $caught;
        }

        if ($success) {
            $this->buffer->confirmMetricRedisKeys($keys);
            $this->metricsSent += count($metrics);
            $this->logger->debug('Flushed ' . count($metrics) . ' metrics');
            if ($this->metricsFailureStreak > 0) {
                $this->logger->warning(
                    'Metrics flush recovered after ' . $this->metricsFailureStreak . ' consecutive partial failure(s)'
                );
            }
            $this->metricsFailureStreak = 0;
            $this->metricsRetryAfter = 0.0;

            return;
        }

        $evictedKeys = $this->buffer->requeueMetricsInMemory($metrics, $keys);
        if ($evictedKeys !== []) {
            $this->buffer->confirmMetricRedisKeys($evictedKeys);
        }
        $this->metricsFailed += count($metrics);
        $this->metricsFailureStreak++;
        $delay = Backoff::calculate(
            $this->metricsFailureStreak - 1,
            (float) $this->config->flushInterval,
            self::PARTIAL_FAILURE_MAX_BACKOFF_SECONDS
        );
        $this->metricsRetryAfter = microtime(true) + $delay;
        if ($this->metricsFailureStreak === 1) {
            $this->logger->warning(
                'Failed to send ' . count($metrics) . ' metrics; ' .
                $this->retentionDescription('metrics') . ' for retry; ' .
                sprintf('backing off up to %.0fs between attempts', $delay)
            );
        }
        if ($exception !== null) {
            $this->logger->error('Transport raised sending metrics: ' . ErrorHook::message($exception));
            ErrorHook::fire($this->config->onError, $this->logger, 'flush_metrics', $exception, [
                'batchSize' => count($metrics),
            ]);
            throw $exception;
        }
    }

    // ------------------------------------------------------------------
    // Status / stats
    // ------------------------------------------------------------------

    /** Return a snapshot of the agent's current health (mirrors get_status). */
    public function getStatus(): AgentStatus
    {
        $uptime = microtime(true) - $this->startTime;
        $bufferSize = $this->buffer->getBufferSize();
        $transportStats = $this->transport->getStats();

        $status = 'healthy';
        $errors = [];

        if (($transportStats['circuitBreakerState'] ?? null) === 'OPEN') {
            $status = 'degraded';
            $errors[] = 'Transport circuit breaker is open';
        }

        if ($bufferSize >= $this->config->bufferSize * self::DEGRADED_BUFFER_RATIO) {
            $status = 'degraded';
            $errors[] = 'Buffer nearly full';
        }

        if ($this->eventsFailed + $this->metricsFailed > 0) {
            $failureRate = ($this->eventsFailed + $this->metricsFailed) /
                max(
                    1,
                    $this->eventsSent + $this->metricsSent + $this->eventsFailed + $this->metricsFailed
                );
            if ($failureRate > self::DEGRADED_FAILURE_RATE) {
                $status = 'degraded';
                $errors[] = sprintf('High failure rate: %.1f%%', $failureRate * 100);
            }
        }

        return new AgentStatus(
            timestamp: WireFormat::now(),
            status: $status,
            uptime: $uptime,
            eventsSent: $this->eventsSent,
            eventsFailed: $this->eventsFailed,
            bufferSize: $bufferSize,
            lastFlush: $this->buffer->lastFlushTime === null
                ? null
                : (new \DateTimeImmutable('@' . (string) (int) $this->buffer->lastFlushTime))->setTimezone(new \DateTimeZone('UTC')),
            errors: $errors,
        );
    }

    /**
     * Get aggregate agent statistics (mirrors get_stats).
     *
     * @return array<string, mixed>
     */
    public function getStats(): array
    {
        return [
            'running' => $this->running,
            'uptime' => microtime(true) - $this->startTime,
            'eventsSent' => $this->eventsSent,
            'metricsSent' => $this->metricsSent,
            'eventsFailed' => $this->eventsFailed,
            'metricsFailed' => $this->metricsFailed,
            'bufferStats' => $this->buffer->getStats(),
            'transportStats' => $this->transport->getStats(),
            'loopFailures' => [
                'flush' => $this->flushConsecutiveFailures,
                'status' => $this->statusConsecutiveFailures,
                'rules' => $this->rulesConsecutiveFailures,
            ],
            'lastStatusPushOk' => $this->lastStatusPushOk,
            'rulesFetched' => $this->rulesFetched,
            'cachedRules' => $this->cachedRules !== null,
            'rulesLastUpdate' => $this->rulesLastUpdate,
        ];
    }

    /**
     * True when the agent is running, the circuit breaker is closed, the
     * buffer is not nearly full, and the failure rate is acceptable
     * (mirrors health_check). Never throws.
     */
    public function healthCheck(): bool
    {
        if (!$this->running) {
            return false;
        }

        try {
            $transportStats = $this->transport->getStats();
            if (($transportStats['circuitBreakerState'] ?? null) === 'OPEN') {
                return false;
            }

            $bufferSize = $this->buffer->getBufferSize();
            if ($bufferSize >= $this->config->bufferSize * self::HEALTH_BUFFER_RATIO) {
                return false;
            }

            $totalAttempts = $this->eventsSent + $this->metricsSent + $this->eventsFailed + $this->metricsFailed;
            if ($totalAttempts > 0) {
                $failureRate = ($this->eventsFailed + $this->metricsFailed) / $totalAttempts;
                if ($failureRate > self::HEALTH_FAILURE_RATE_MAX) {
                    return false;
                }
            }

            return true;
        } catch (\Throwable $error) {
            $this->logger->error('Error during health check: ' . ErrorHook::message($error));

            return false;
        }
    }

    /**
     * @param mixed $value
     *
     * @return array<string, mixed>
     */
    private static function asMetadataArray(mixed $value): array
    {
        if (is_array($value)) {
            return $value;
        }

        return [];
    }

    /**
     * @param mixed $value
     *
     * @return array<string, string>
     */
    private static function asStringArray(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }
        $result = [];
        foreach ($value as $key => $item) {
            $result[(string) $key] = is_string($item) ? $item : (string) $item;
        }

        return $result;
    }
}
