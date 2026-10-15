<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardAgent\EventBuffer;

use RenzoFranceschini\GuardAgent\Config\AgentConfig;
use RenzoFranceschini\GuardAgent\Config\BufferOverflowPolicy;
use RenzoFranceschini\GuardAgent\Exception\BufferFullException;
use RenzoFranceschini\GuardAgent\Log\AgentLogger;
use RenzoFranceschini\GuardAgent\Log\DefaultAgentLogger;
use RenzoFranceschini\GuardAgent\Model\SecurityEvent;
use RenzoFranceschini\GuardAgent\Model\SecurityMetric;
use RenzoFranceschini\GuardAgent\Model\WireFormat;
use RenzoFranceschini\GuardAgent\Persistence\RedisHandler;
use RenzoFranceschini\GuardAgent\Utils\ErrorHook;
use RenzoFranceschini\GuardAgent\Utils\Json;
use RenzoFranceschini\GuardAgent\Utils\Uuid;

/**
 * EventBuffer, mirroring guard_agent/buffer.py and its mixin split:
 * _buffer_queue.py (add/flush/requeue), _buffer_overflow.py (drop/block/raise
 * policies), _buffer_redis.py (crash-recovery persistence).
 *
 * Semantics mirrored exactly:
 * - Per-kind bounded queues (events and metrics each capped at bufferSize).
 * - Overflow policies: "drop" evicts the oldest entry (default), "block"
 *   backpressures the caller until space frees, "raise" throws
 *   BufferFullException. A requeue after a failed send keeps its slot.
 *   The single-threaded PHP caveat: under "block" space only frees when a
 *   drain runs, so the buffer invokes its drainCallback (wired to the
 *   agent's flushBuffer) inline before each re-check; without a drain
 *   callback the wait can never end.
 * - High-watermark early flush: occupancy >= bufferSize * highWatermarkRatio
 *   marks the buffer flush-worthy; the host-driven flush (tick() in this
 *   port, a background task in the Python/TypeScript/Go ports) performs it.
 * - At-least-once handshake: flush*_with_keys drains and returns aligned
 *   Redis keys; confirm* deletes keys after a successful send; requeue*
 *   pushes unsent items back to the front, evicting from the tail when full
 *   and returning those evicted keys so the caller can confirm them.
 * - Redis persistence: every accepted item is written under a
 *   globally-unique key with a 3600s TTL; on attach the buffer reloads
 *   pending items from Redis.
 */
final class EventBuffer
{
    /** How long a "block" waiter re-checks for space (Python: 0.5s). */
    public const BLOCK_POLICY_POLL_INTERVAL_MICROS = 500_000;

    /** Log every Nth drop when the buffer overflows under "drop" policy. */
    public const DROP_LOG_INTERVAL = 100;

    /** TTL for persisted buffer entries in Redis (seconds). */
    public const REDIS_PERSIST_TTL_SECONDS = 3600;

    /** @var list<SecurityEvent> */
    private array $events = [];

    /** @var list<SecurityMetric> */
    private array $metrics = [];

    /** SecurityEvent -> short Redis key ('' never stored). */
    private \SplObjectStorage $eventKeys;

    /** SecurityMetric -> short Redis key ('' never stored). */
    private \SplObjectStorage $metricKeys;

    /** Events accepted but not yet written to Redis (see persistPending). */
    private \SplObjectStorage $pendingEventPersist;

    /** Metrics accepted but not yet written to Redis (see persistPending). */
    private \SplObjectStorage $pendingMetricPersist;

    private ?RedisHandler $redisHandler = null;

    private readonly int $maxSize;

    private readonly AgentLogger $logger;

    public int $eventsBuffered = 0;

    public int $metricsBuffered = 0;

    public int $eventsFlushed = 0;

    public int $metricsFlushed = 0;

    public int $eventsDropped = 0;

    public int $metricsDropped = 0;

    public int $redisPersistFailures = 0;

    public ?float $lastFlushTime = null;

    /**
     * Invoked (with no arguments) while a "block" waiter waits for space;
     * GuardAgent wires this to its flushBuffer. May be null for standalone
     * buffer users that never configure the block policy.
     */
    public ?\Closure $drainCallback = null;

    public function __construct(private readonly AgentConfig $config)
    {
        $this->eventKeys = new \SplObjectStorage();
        $this->metricKeys = new \SplObjectStorage();
        $this->pendingEventPersist = new \SplObjectStorage();
        $this->pendingMetricPersist = new \SplObjectStorage();
        $this->maxSize = $config->bufferSize;
        $this->logger = $config->logger ?? new DefaultAgentLogger();
    }

    // ------------------------------------------------------------------
    // Redis integration
    // ------------------------------------------------------------------

    /** Attach the durable backend and reload pending items from Redis. */
    public function initializeRedis(RedisHandler $redisHandler): void
    {
        $this->redisHandler = $redisHandler;
        $this->loadFromRedis();
    }

    public function redisHandler(): ?RedisHandler
    {
        return $this->redisHandler;
    }

    private function persistEventToRedis(RedisHandler $redis, SecurityEvent $event): ?string
    {
        try {
            $key = self::uniqueKey('event');
            $serialized = Json::encode($event->toWire());
            if (!$redis->setKey('agent_events', $key, $serialized, self::REDIS_PERSIST_TTL_SECONDS)) {
                $this->redisPersistFailures++;

                return null;
            }

            return $key;
        } catch (\Throwable $error) {
            $this->redisPersistFailures++;
            $this->logger->warning('Failed to persist event to Redis: ' . ErrorHook::message($error));

            return null;
        }
    }

    private function persistMetricToRedis(RedisHandler $redis, SecurityMetric $metric): ?string
    {
        try {
            $key = self::uniqueKey('metric');
            $serialized = Json::encode($metric->toWire());
            if (!$redis->setKey('agent_metrics', $key, $serialized, self::REDIS_PERSIST_TTL_SECONDS)) {
                $this->redisPersistFailures++;

                return null;
            }

            return $key;
        } catch (\Throwable $error) {
            $this->redisPersistFailures++;
            $this->logger->warning('Failed to persist metric to Redis: ' . ErrorHook::message($error));

            return null;
        }
    }

    /**
     * Load persisted events/metrics from Redis on startup and track their
     * keys, mirroring _load_from_redis (guard_agent/_buffer_redis.py:86-207).
     * Corrupt or missing records are warned about and skipped; the TTL
     * reclaims them.
     */
    private function loadFromRedis(): void
    {
        if ($this->redisHandler === null) {
            return;
        }

        try {
            $eventKeys = $this->redisHandler->keys('agent_events:*');
            foreach ($eventKeys as $fullKey) {
                $this->loadOneEventFromRedis($fullKey);
            }

            $metricKeys = $this->redisHandler->keys('agent_metrics:*');
            foreach ($metricKeys as $fullKey) {
                $this->loadOneMetricFromRedis($fullKey);
            }

            if ($this->events !== [] || $this->metrics !== []) {
                $this->logger->info(
                    'Loaded ' . count($this->events) . ' events and ' .
                    count($this->metrics) . ' metrics from Redis'
                );
            }
        } catch (\Throwable $error) {
            $this->logger->warning('Failed to load from Redis: ' . ErrorHook::message($error));
        }
    }

    private function loadOneEventFromRedis(string $fullKey): void
    {
        if ($this->redisHandler === null) {
            return;
        }
        try {
            $shortKey = self::shortKey($fullKey);
            $data = $this->redisHandler->getKey('agent_events', $shortKey);
            if ($data === null) {
                $this->logger->warning("Failed to load event from Redis key {$fullKey}: No data found for key");

                return;
            }
            $parsed = Json::decodeAssocOrNull($data);
            if ($parsed === null) {
                return;
            }
            $event = SecurityEvent::normalize($parsed);
            if ($this->isEventBufferFull()) {
                $this->forgetOldestEventKey();
            }
            $this->events[] = $event;
            $this->eventsBuffered++;
            $this->eventKeys[$event] = $shortKey;
        } catch (\Throwable $error) {
            $this->logger->warning("Failed to load event from Redis key {$fullKey}: " . ErrorHook::message($error));
        }
    }

    private function loadOneMetricFromRedis(string $fullKey): void
    {
        if ($this->redisHandler === null) {
            return;
        }
        try {
            $shortKey = self::shortKey($fullKey);
            $data = $this->redisHandler->getKey('agent_metrics', $shortKey);
            if ($data === null) {
                $this->logger->warning("Failed to load metric from Redis key {$fullKey}: No data found for key");

                return;
            }
            $parsed = Json::decodeAssocOrNull($data);
            if ($parsed === null) {
                return;
            }
            $metric = SecurityMetric::normalize($parsed);
            if ($this->isMetricBufferFull()) {
                $this->forgetOldestMetricKey();
            }
            $this->metrics[] = $metric;
            $this->metricsBuffered++;
            $this->metricKeys[$metric] = $shortKey;
        } catch (\Throwable $error) {
            $this->logger->warning("Failed to load metric from Redis key {$fullKey}: " . ErrorHook::message($error));
        }
    }

    /**
     * Write every buffered item that has no Redis record yet. Persistence is
     * deliberately NOT done when an item is added: that put the request path
     * behind a Redis round trip (up to the command timeout while Redis is
     * slow). The host calls this off the hot path (GuardAgent::flushBuffer
     * after the send attempt, so items that were just delivered are never
     * written, and tick() between flushes). A failed write is counted and
     * feeds the RedisHandler cooldown, exactly as before.
     */
    public function persistPending(): void
    {
        if ($this->redisHandler === null) {
            return;
        }
        foreach ($this->events as $event) {
            if (isset($this->pendingEventPersist[$event]) && !isset($this->eventKeys[$event])) {
                $key = $this->persistEventToRedis($this->redisHandler, $event);
                if ($key !== null) {
                    $this->eventKeys[$event] = $key;
                }
            }
        }
        $this->pendingEventPersist->removeAll($this->pendingEventPersist);
        foreach ($this->metrics as $metric) {
            if (isset($this->pendingMetricPersist[$metric]) && !isset($this->metricKeys[$metric])) {
                $key = $this->persistMetricToRedis($this->redisHandler, $metric);
                if ($key !== null) {
                    $this->metricKeys[$metric] = $key;
                }
            }
        }
        $this->pendingMetricPersist->removeAll($this->pendingMetricPersist);
    }

    /** Delete the given event keys from Redis after the transport confirms. */
    public function confirmEventRedisKeys(array $keys): void
    {
        if ($this->redisHandler === null) {
            return;
        }
        foreach ($keys as $key) {
            if ($key === '' || $key === null) {
                continue;
            }
            try {
                $this->redisHandler->delete('agent_events', (string) $key);
            } catch (\Throwable $error) {
                $this->logger->warning("Failed to delete confirmed event key {$key}: " . ErrorHook::message($error));
            }
        }
    }

    /** Delete the given metric keys from Redis after the transport confirms. */
    public function confirmMetricRedisKeys(array $keys): void
    {
        if ($this->redisHandler === null) {
            return;
        }
        foreach ($keys as $key) {
            if ($key === '' || $key === null) {
                continue;
            }
            try {
                $this->redisHandler->delete('agent_metrics', (string) $key);
            } catch (\Throwable $error) {
                $this->logger->warning("Failed to delete confirmed metric key {$key}: " . ErrorHook::message($error));
            }
        }
    }

    // ------------------------------------------------------------------
    // Overflow policy
    // ------------------------------------------------------------------

    private function isEventBufferFull(): bool
    {
        return count($this->events) >= $this->maxSize;
    }

    private function isMetricBufferFull(): bool
    {
        return count($this->metrics) >= $this->maxSize;
    }

    private function forgetOldestEventKey(): ?string
    {
        $oldest = $this->events[0] ?? null;
        if ($oldest !== null) {
            unset($this->pendingEventPersist[$oldest]);
        }
        if ($oldest === null || !isset($this->eventKeys[$oldest])) {
            return null;
        }
        $key = $this->eventKeys[$oldest];
        unset($this->eventKeys[$oldest]);

        return $key;
    }

    private function forgetOldestMetricKey(): ?string
    {
        $oldest = $this->metrics[0] ?? null;
        if ($oldest !== null) {
            unset($this->pendingMetricPersist[$oldest]);
        }
        if ($oldest === null || !isset($this->metricKeys[$oldest])) {
            return null;
        }
        $key = $this->metricKeys[$oldest];
        unset($this->metricKeys[$oldest]);

        return $key;
    }

    private function forgetNewestEventKey(): ?string
    {
        $newest = $this->events === [] ? null : $this->events[count($this->events) - 1];
        if ($newest !== null) {
            unset($this->pendingEventPersist[$newest]);
        }
        if ($newest === null || !isset($this->eventKeys[$newest])) {
            return null;
        }
        $key = $this->eventKeys[$newest];
        unset($this->eventKeys[$newest]);

        return $key;
    }

    private function forgetNewestMetricKey(): ?string
    {
        $newest = $this->metrics === [] ? null : $this->metrics[count($this->metrics) - 1];
        if ($newest !== null) {
            unset($this->pendingMetricPersist[$newest]);
        }
        if ($newest === null || !isset($this->metricKeys[$newest])) {
            return null;
        }
        $key = $this->metricKeys[$newest];
        unset($this->metricKeys[$newest]);

        return $key;
    }

    // ------------------------------------------------------------------
    // Queue operations
    // ------------------------------------------------------------------

    /**
     * Add a security event to the buffer honoring the configured overflow
     * policy. Under "block", the drain callback runs inline before each
     * 0.5s re-check.
     */
    public function addEvent(SecurityEvent $event): void
    {
        for (;;) {
            if (!$this->isEventBufferFull()) {
                $this->events[] = $event;
                $this->eventsBuffered++;
                if ($this->redisHandler !== null) {
                    $this->pendingEventPersist[$event] = true;
                }
                break;
            }

            $policy = $this->config->bufferOverflowPolicy;
            if ($policy === BufferOverflowPolicy::Raise) {
                throw new BufferFullException(
                    "Event buffer full at maxSize={$this->maxSize} and bufferOverflowPolicy='raise'"
                );
            }
            if ($policy === BufferOverflowPolicy::Block) {
                if ($this->drainCallback !== null) {
                    ($this->drainCallback)();
                }
                usleep(self::BLOCK_POLICY_POLL_INTERVAL_MICROS);
                continue;
            }

            $this->eventsDropped++;
            if ($this->eventsDropped % self::DROP_LOG_INTERVAL === 1) {
                $this->logger->warning(
                    "Event buffer full at maxSize={$this->maxSize}; dropping oldest event " .
                    "({$this->eventsDropped} dropped total)"
                );
            }
            $droppedKey = $this->forgetOldestEventKey();
            array_shift($this->events);
            if ($droppedKey !== null) {
                $this->confirmEventRedisKeys([$droppedKey]);
            }
            continue;
        }
    }

    /** Add a metric to the buffer; see addEvent for the overflow rules. */
    public function addMetric(SecurityMetric $metric): void
    {
        for (;;) {
            if (!$this->isMetricBufferFull()) {
                $this->metrics[] = $metric;
                $this->metricsBuffered++;
                if ($this->redisHandler !== null) {
                    $this->pendingMetricPersist[$metric] = true;
                }
                break;
            }

            $policy = $this->config->bufferOverflowPolicy;
            if ($policy === BufferOverflowPolicy::Raise) {
                throw new BufferFullException(
                    "Metric buffer full at maxSize={$this->maxSize} and bufferOverflowPolicy='raise'"
                );
            }
            if ($policy === BufferOverflowPolicy::Block) {
                if ($this->drainCallback !== null) {
                    ($this->drainCallback)();
                }
                usleep(self::BLOCK_POLICY_POLL_INTERVAL_MICROS);
                continue;
            }

            $this->metricsDropped++;
            if ($this->metricsDropped % self::DROP_LOG_INTERVAL === 1) {
                $this->logger->warning(
                    "Metric buffer full at maxSize={$this->maxSize}; dropping oldest metric " .
                    "({$this->metricsDropped} dropped total)"
                );
            }
            $droppedKey = $this->forgetOldestMetricKey();
            array_shift($this->metrics);
            if ($droppedKey !== null) {
                $this->confirmMetricRedisKeys([$droppedKey]);
            }
            continue;
        }
    }

    /**
     * Drain events plus their Redis keys; keys stay aligned with events so a
     * failed send can requeue correctly with or without Redis configured.
     * Each entry is the short Redis key, '' when the item was never persisted.
     *
     * @return array{0: list<SecurityEvent>, 1: list<string>}
     */
    public function flushEventsWithKeys(): array
    {
        $events = $this->events;
        $keys = array_map(function (SecurityEvent $event): string {
            return isset($this->eventKeys[$event]) ? $this->eventKeys[$event] : '';
        }, $events);
        $this->events = [];
        $this->eventKeys->removeAll($this->eventKeys);
        $this->pendingEventPersist->removeAll($this->pendingEventPersist);
        $this->eventsFlushed += count($events);
        $this->lastFlushTime = microtime(true);

        return [$events, $keys];
    }

    /**
     * Drain metrics plus their Redis keys; see flushEventsWithKeys.
     *
     * @return array{0: list<SecurityMetric>, 1: list<string>}
     */
    public function flushMetricsWithKeys(): array
    {
        $metrics = $this->metrics;
        $keys = array_map(function (SecurityMetric $metric): string {
            return isset($this->metricKeys[$metric]) ? $this->metricKeys[$metric] : '';
        }, $metrics);
        $this->metrics = [];
        $this->metricKeys->removeAll($this->metricKeys);
        $this->pendingMetricPersist->removeAll($this->pendingMetricPersist);
        $this->metricsFlushed += count($metrics);
        $this->lastFlushTime = microtime(true);

        return [$metrics, $keys];
    }

    /**
     * Push unsent events back to the FRONT of the buffer; keep Redis keys.
     * The tail is evicted when the buffer is full, so that is the side whose
     * key gets forgotten; the caller must confirm (delete) the returned keys
     * so their Redis records do not orphan (mirrors the Python agent's
     * appendleft-into-maxlen-deque eviction side).
     *
     * @param list<SecurityEvent> $events
     * @param list<string> $keys
     *
     * @return list<string> evicted keys to confirm
     */
    public function requeueEventsInMemory(array $events, array $keys): array
    {
        $evictedKeys = [];
        for ($i = count($events) - 1; $i >= 0; $i--) {
            $event = $events[$i] ?? null;
            if ($event === null) {
                continue;
            }
            $key = $keys[$i] ?? '';
            if ($this->isEventBufferFull()) {
                $this->eventsDropped++;
                $evictedKey = $this->forgetNewestEventKey();
                if ($evictedKey !== null) {
                    $evictedKeys[] = $evictedKey;
                }
                array_pop($this->events);
            }
            array_unshift($this->events, $event);
            if ($key !== '') {
                $this->eventKeys[$event] = $key;
            } elseif ($this->redisHandler !== null) {
                $this->pendingEventPersist[$event] = true;
            }
        }

        return $evictedKeys;
    }

    /**
     * Push unsent metrics back to the front of the buffer; see
     * requeueEventsInMemory for the eviction rule.
     *
     * @param list<SecurityMetric> $metrics
     * @param list<string> $keys
     *
     * @return list<string> evicted keys to confirm
     */
    public function requeueMetricsInMemory(array $metrics, array $keys): array
    {
        $evictedKeys = [];
        for ($i = count($metrics) - 1; $i >= 0; $i--) {
            $metric = $metrics[$i] ?? null;
            if ($metric === null) {
                continue;
            }
            $key = $keys[$i] ?? '';
            if ($this->isMetricBufferFull()) {
                $this->metricsDropped++;
                $evictedKey = $this->forgetNewestMetricKey();
                if ($evictedKey !== null) {
                    $evictedKeys[] = $evictedKey;
                }
                array_pop($this->metrics);
            }
            array_unshift($this->metrics, $metric);
            if ($key !== '') {
                $this->metricKeys[$metric] = $key;
            } elseif ($this->redisHandler !== null) {
                $this->pendingMetricPersist[$metric] = true;
            }
        }

        return $evictedKeys;
    }

    /**
     * Clear all buffers, including the Redis-key maps, and wipe the persisted
     * namespaces (mirroring clear_buffer).
     */
    public function clearBuffer(): void
    {
        $this->events = [];
        $this->eventKeys->removeAll($this->eventKeys);
        $this->pendingEventPersist->removeAll($this->pendingEventPersist);

        $this->metrics = [];
        $this->metricKeys->removeAll($this->metricKeys);
        $this->pendingMetricPersist->removeAll($this->pendingMetricPersist);

        if ($this->redisHandler !== null) {
            try {
                foreach ($this->redisHandler->keys('agent_events:*') as $fullKey) {
                    $this->redisHandler->delete('agent_events', self::shortKey($fullKey));
                }
                foreach ($this->redisHandler->keys('agent_metrics:*') as $fullKey) {
                    $this->redisHandler->delete('agent_metrics', self::shortKey($fullKey));
                }
                $this->logger->info('Cleared all Redis buffers');
            } catch (\Throwable $error) {
                $this->logger->warning('Failed to clear Redis buffers: ' . ErrorHook::message($error));
            }
        }
    }

    // ------------------------------------------------------------------
    // Introspection
    // ------------------------------------------------------------------

    /** Combined occupancy across both kinds. */
    public function getBufferSize(): int
    {
        return count($this->events) + count($this->metrics);
    }

    /**
     * True when the combined occupancy reached the high-watermark (the
     * early-flush trigger; the host-driven flush performs the work).
     */
    public function atHighWatermark(): bool
    {
        return $this->getBufferSize() >= $this->maxSize * $this->config->highWatermarkRatio;
    }

    /**
     * @return array<string, mixed>
     */
    public function getStats(): array
    {
        return [
            'eventsBuffered' => $this->eventsBuffered,
            'metricsBuffered' => $this->metricsBuffered,
            'eventsFlushed' => $this->eventsFlushed,
            'metricsFlushed' => $this->metricsFlushed,
            'eventsDropped' => $this->eventsDropped,
            'metricsDropped' => $this->metricsDropped,
            'currentEventBufferSize' => count($this->events),
            'currentMetricBufferSize' => count($this->metrics),
            'redisPersistFailures' => $this->redisPersistFailures,
            'durabilityDegraded' => $this->redisHandler !== null && $this->redisPersistFailures > 0,
            'lastFlushTime' => $this->lastFlushTime,
        ];
    }

    // ------------------------------------------------------------------
    // Keys
    // ------------------------------------------------------------------

    /**
     * Globally-unique short persistence key: {kind}_{unix nanos}_{8 hex},
     * mirroring guard_agent/_buffer_redis.py:47.
     */
    public static function uniqueKey(string $kind): string
    {
        $nanos = (string) hrtime(true);
        $rand = substr(Uuid::hex(), 0, 8);

        return $kind . '_' . $nanos . '_' . $rand;
    }

    /** Strip a full Redis key down to its short (per-item) segment. */
    public static function shortKey(string $fullKey): string
    {
        $parts = explode(':', $fullKey);

        return (string) ($parts[count($parts) - 1] ?? $fullKey);
    }
}
