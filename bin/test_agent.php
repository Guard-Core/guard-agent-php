<?php

/**
 * T-harness test suite for guard-agent-php, in the guard-core-php sibling
 * style. Run with: php bin/test_agent.php
 *
 * Integration modes:
 * - REDIS_HOST=host (default 127.0.0.1) runs the persistence tests against a
 *   real Redis on port 6379. REDIS_HOST=0 skips them (unit-only variant).
 * - The mock-server integration smoke is always run against `php -S` with
 *   tests/mock_server.php mirroring the ingestion contract.
 */

declare(strict_types=1);

use RenzoFranceschini\GuardAgent\Config\AgentConfig;
use RenzoFranceschini\GuardAgent\Config\AgentConfigResolver;
use RenzoFranceschini\GuardAgent\Config\BufferOverflowPolicy;
use RenzoFranceschini\GuardAgent\EventBuffer\EventBuffer;
use RenzoFranceschini\GuardAgent\Exception\BufferFullException;
use RenzoFranceschini\GuardAgent\Exception\ConfigException;
use RenzoFranceschini\GuardAgent\Exception\InvalidEventException;
use RenzoFranceschini\GuardAgent\Exception\PermanentClientException;
use RenzoFranceschini\GuardAgent\Encryption\PayloadEncryptor;
use RenzoFranceschini\GuardAgent\Exception\EncryptionConfigException;
use RenzoFranceschini\GuardAgent\Exception\EncryptionException;
use RenzoFranceschini\GuardAgent\Exception\SerializationException;
use RenzoFranceschini\GuardAgent\Utils\CanonicalJson;
use RenzoFranceschini\GuardAgent\GuardAgent;
use RenzoFranceschini\GuardAgent\Install\InstallId;
use RenzoFranceschini\GuardAgent\Log\AgentLogger;
use RenzoFranceschini\GuardAgent\Model\AgentStatus;
use RenzoFranceschini\GuardAgent\Model\DynamicRules;
use RenzoFranceschini\GuardAgent\Exception\InvalidRulesException;
use RenzoFranceschini\GuardAgent\Model\SecurityEvent;
use RenzoFranceschini\GuardAgent\Model\SecurityMetric;
use RenzoFranceschini\GuardAgent\Model\WireFormat;
use RenzoFranceschini\GuardAgent\Persistence\RedisClientInterface;
use RenzoFranceschini\GuardAgent\Persistence\RedisHandler;
use RenzoFranceschini\GuardAgent\Persistence\StreamRedisClient;
use RenzoFranceschini\GuardAgent\Transport\CircuitBreaker;
use RenzoFranceschini\GuardAgent\Transport\HttpTransport;
use RenzoFranceschini\GuardAgent\Transport\RateLimiter;
use RenzoFranceschini\GuardAgent\Transport\Signer;
use RenzoFranceschini\GuardAgent\Transport\TransportInterface;
use RenzoFranceschini\GuardAgent\Utils\Backoff;
use RenzoFranceschini\GuardAgent\Utils\BatchId;
use RenzoFranceschini\GuardAgent\Utils\HeadersRedactor;
use RenzoFranceschini\GuardAgent\Utils\IpHasher;
use RenzoFranceschini\GuardAgent\Utils\Json;
use RenzoFranceschini\GuardAgent\Utils\PayloadTruncator;
use RenzoFranceschini\GuardAgent\Utils\ResponseSummary;
use RenzoFranceschini\GuardAgent\Utils\RetryAfter;
use RenzoFranceschini\GuardAgent\Utils\Uuid;
use RenzoFranceschini\GuardAgent\Version;

require __DIR__ . '/../vendor/autoload.php';

final class T
{
    public int $passed = 0;

    public int $failed = 0;

    public function ok(bool $condition, string $label): void
    {
        if ($condition) {
            $this->passed++;
            echo "ok - {$label}\n";
        } else {
            $this->failed++;
            echo "FAIL - {$label}\n";
        }
    }

    public function same(mixed $expected, mixed $actual, string $label): void
    {
        if ($expected === $actual) {
            $this->passed++;
            echo "ok - {$label}\n";
        } else {
            $this->failed++;
            echo "FAIL - {$label}\n";
            echo '  expected: ' . var_export($expected, true) . "\n";
            echo '  actual:   ' . var_export($actual, true) . "\n";
        }
    }

    public function throws(string $class, callable $fn, string $label): void
    {
        try {
            $fn();
            $this->failed++;
            echo "FAIL - {$label}: no exception\n";
        } catch (Throwable $e) {
            $this->same($class, $e::class, $label);
        }
    }

    public function skip(string $label): void
    {
        echo "skip - {$label}\n";
    }

    public function section(string $name): void
    {
        echo "\n=== {$name} ===\n";
    }

    public function finish(): never
    {
        echo "\n=== summary ===\n";
        echo "passed: {$this->passed}\n";
        echo "failed: {$this->failed}\n";
        exit($this->failed === 0 ? 0 : 1);
    }
}

final class SilentLogger implements AgentLogger
{
    public function debug(string $message): void
    {
    }

    public function info(string $message): void
    {
    }

    public function warning(string $message): void
    {
    }

    public function error(string $message): void
    {
    }
}

/**
 * Recording logger double for log-content assertions.
 */
final class CaptureLogger implements AgentLogger
{
    /** @var list<string> */
    public array $warnings = [];

    public function debug(string $message): void
    {
    }

    public function info(string $message): void
    {
    }

    public function warning(string $message): void
    {
        $this->warnings[] = $message;
    }

    public function error(string $message): void
    {
    }
}

/**
 * In-memory Redis double for handshake tests: records TTLs and deletions.
 */
final class FakeRedisClient implements RedisClientInterface
{
    /** @var array<string, string> */
    public array $storage = [];

    /** @var array<string, int|null> */
    public array $ttls = [];

    /** @var list<string> */
    public array $deleted = [];

    private bool $failWrites = false;

    public function failWrites(bool $fail): void
    {
        $this->failWrites = $fail;
    }

    public function ping(): void
    {
    }

    public function get(string $key): ?string
    {
        return $this->storage[$key] ?? null;
    }

    public function set(string $key, string $value, ?int $ttlSeconds = null): bool
    {
        if ($this->failWrites) {
            return false;
        }
        $this->storage[$key] = $value;
        $this->ttls[$key] = $ttlSeconds;

        return true;
    }

    public function delete(string ...$keys): int
    {
        $count = 0;
        foreach ($keys as $key) {
            if (isset($this->storage[$key])) {
                unset($this->storage[$key]);
                $count++;
            }
            $this->deleted[] = $key;
        }

        return $count;
    }

    public function keys(string $pattern): array
    {
        $regex = '/^' . str_replace(['\*', '\?'], ['.*', '.'], preg_quote($pattern, '/')) . '$/';
        $result = [];
        foreach (array_keys($this->storage) as $key) {
            if (preg_match($regex, $key) === 1) {
                $result[] = $key;
            }
        }
        sort($result);

        return $result;
    }

    public function close(): void
    {
    }

    /**
     * @return list<string>
     */
    public function keysContaining(string $needle): array
    {
        $result = [];
        foreach (array_keys($this->storage) as $key) {
            if (str_contains($key, $needle)) {
                $result[] = $key;
            }
        }
        sort($result);

        return $result;
    }
}

/**
 * Scriptable transport double for the agent handshake tests. Outcomes are
 * consumed in order; each is a bool, or a Throwable to throw.
 */
final class RecordingTransport implements TransportInterface
{
    /** @var list<list<SecurityEvent>> */
    public array $eventBatches = [];

    /** @var list<list<SecurityMetric>> */
    public array $metricBatches = [];

    /** @var list<AgentStatus> */
    public array $statusCalls = [];

    public int $rulesRequests = 0;

    /** @var list<DynamicRules|null|Throwable> */
    public array $rulesOutcomes = [];

    public int $initialized = 0;

    public int $closed = 0;

    /** @var list<bool|Throwable> */
    public array $eventOutcomes = [];

    /** @var list<bool|Throwable> */
    public array $metricOutcomes = [];

    public function initialize(): void
    {
        $this->initialized++;
    }

    public function sendEvents(array $events): bool
    {
        $this->eventBatches[] = array_values($events);
        if ($this->eventOutcomes === []) {
            return true;
        }
        $outcome = array_shift($this->eventOutcomes);
        if ($outcome instanceof Throwable) {
            throw $outcome;
        }

        return $outcome;
    }

    public function sendMetrics(array $metrics): bool
    {
        $this->metricBatches[] = array_values($metrics);
        if ($this->metricOutcomes === []) {
            return true;
        }
        $outcome = array_shift($this->metricOutcomes);
        if ($outcome instanceof Throwable) {
            throw $outcome;
        }

        return $outcome;
    }

    public function fetchDynamicRules(): ?DynamicRules
    {
        $this->rulesRequests++;
        if ($this->rulesOutcomes === []) {
            return null;
        }
        $outcome = array_shift($this->rulesOutcomes);
        if ($outcome instanceof Throwable) {
            throw $outcome;
        }

        return $outcome;
    }

    public function sendStatus(AgentStatus $status): bool
    {
        $this->statusCalls[] = $status;

        return true;
    }

    /**
     * @return array<string, mixed>
     */
    public function getStats(): array
    {
        return [
            'requestsSent' => count($this->eventBatches) + count($this->metricBatches),
            'requestsFailed' => 0,
            'bytesSent' => 0,
            'circuitBreakerState' => 'CLOSED',
            'failureCount' => 0,
            'sessionClosed' => $this->closed > 0,
        ];
    }

    public function close(): void
    {
        $this->closed++;
    }
}

/**
 * @param array<string, mixed> $overrides
 */
function makeConfig(array $overrides = []): AgentConfig
{
    $defaults = [
        'apiKey' => 'test-api-key-123',
        'endpoint' => 'https://ingest.example.test',
        'projectId' => 'proj-1',
        'logger' => new SilentLogger(),
    ];

    return AgentConfigResolver::resolve(array_merge($defaults, $overrides));
}

/**
 * @param array<string, mixed> $overrides
 */
function makeEvent(array $overrides = []): SecurityEvent
{
    $defaults = [
        'event_type' => 'penetration_attempt',
        'ip_address' => '203.0.113.7',
        'timestamp' => WireFormat::now(),
    ];

    return SecurityEvent::normalize(array_merge($defaults, $overrides));
}

/**
 * @param array<string, mixed> $overrides
 */
function makeMetric(array $overrides = []): SecurityMetric
{
    $defaults = [
        'metric_type' => 'request_count',
        'value' => 1,
        'timestamp' => WireFormat::now(),
    ];

    return SecurityMetric::normalize(array_merge($defaults, $overrides));
}

function refl(object $object, string $property): ReflectionProperty
{
    $reflection = new ReflectionProperty($object::class, $property);
    $reflection->setAccessible(true);

    return $reflection;
}

/**
 * @param array<string, mixed> $overrides
 */
function makeAgent(array $overrides = [], ?TransportInterface $transport = null): GuardAgent
{
    return new GuardAgent(makeConfig($overrides), $transport);
}

/**
 * @param list<SecurityEvent> $events
 *
 * @return list<string>
 */
function eventTypes(array $events): array
{
    return array_map(static fn (SecurityEvent $event): string => $event->eventType, $events);
}

/**
 * @return array{0: resource, 1: int, 2: string, 3: string} proc, port, control file, state file
 */
function startMockServer(): array
{
    $sock = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
    if ($sock === false) {
        fwrite(STDERR, "cannot pick a port: {$errstr}\n");
        exit(1);
    }
    $name = (string) stream_socket_get_name($sock, false);
    $port = (int) substr($name, (int) strrpos($name, ':') + 1);
    fclose($sock);

    $controlFile = (string) tempnam(sys_get_temp_dir(), 'gaph-control');
    $stateFile = (string) tempnam(sys_get_temp_dir(), 'gaph-state');
    file_put_contents($controlFile, json_encode(['script' => new stdClass()]));
    file_put_contents($stateFile, '');

    $env = getenv();
    $env['MOCK_CONTROL_FILE'] = $controlFile;
    $env['MOCK_STATE_FILE'] = $stateFile;
    $proc = proc_open(
        [PHP_BINARY, '-S', "127.0.0.1:{$port}", __DIR__ . '/../tests/mock_server.php'],
        [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
        $pipes,
        dirname(__DIR__),
        $env
    );
    if ($proc === false) {
        fwrite(STDERR, "cannot start mock server\n");
        exit(1);
    }

    $ready = false;
    for ($i = 0; $i < 100; $i++) {
        $conn = @fsockopen('127.0.0.1', $port, $e, $es, 0.2);
        if ($conn !== false) {
            fclose($conn);
            $ready = true;
            break;
        }
        usleep(100_000);
    }
    if (!$ready) {
        fwrite(STDERR, "mock server did not become ready\n");
        exit(1);
    }

    return [$proc, $port, $controlFile, $stateFile];
}

/**
 * @param array<string, list<int|array<string, mixed>>> $script
 */
function setScript(string $controlFile, array $script, ?string $signatureSecret = null, bool $requireSigned = false): void
{
    $control = ['script' => $script === [] ? new stdClass() : $script];
    if ($signatureSecret !== null) {
        $control['signatureSecret'] = $signatureSecret;
        $control['requireSigned'] = $requireSigned;
    }
    file_put_contents($controlFile, json_encode($control));
}

/**
 * @return list<array<string, mixed>>
 */
function readMockState(string $stateFile): array
{
    $lines = file($stateFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    $records = [];
    foreach ($lines as $line) {
        $record = json_decode($line, true);
        if (is_array($record)) {
            $records[] = $record;
        }
    }

    return $records;
}

function flushState(string $stateFile): void
{
    file_put_contents($stateFile, '');
}

/**
 * @return list<array<string, mixed>>
 */
function stateFor(string $stateFile, string $path): array
{
    return array_values(array_filter(
        readMockState($stateFile),
        static fn (array $record): bool => ($record['path'] ?? '') === $path
    ));
}

/**
 * @param list<array<string, mixed>> $records
 *
 * @return list<int|string>
 */
function statuses(array $records): array
{
    return array_map(static fn (array $record): int|string => $record['status'], $records);
}

function redisUrl(): string
{
    $host = getenv('REDIS_HOST');
    if ($host === false || $host === '' || $host === '0') {
        return '';
    }

    return 'redis://' . $host . ':6379/0';
}

$t = new T();

// =====================================================================
// 1. Config validation and endpoint normalization
// =====================================================================
$t->section('config validation');

$t->throws(ConfigException::class, static fn () => makeConfig(['apiKey' => 'short']), 'short apiKey rejected');
$t->throws(ConfigException::class, static fn () => makeConfig(['endpoint' => 'ftp://x.example']), 'non-http endpoint rejected');
$t->throws(ConfigException::class, static fn () => AgentConfigResolver::normalizeEndpoint('', new SilentLogger()), 'empty endpoint rejected');
$t->throws(ConfigException::class, static fn () => makeConfig(['statusInterval' => 59]), 'statusInterval below 60 rejected');
$t->throws(ConfigException::class, static fn () => makeConfig(['dynamicRuleInterval' => 59]), 'dynamicRuleInterval below 60 rejected');
$t->throws(ConfigException::class, static fn () => makeConfig(['highWatermarkRatio' => 1.5]), 'highWatermarkRatio above 1 rejected');
$t->throws(ConfigException::class, static fn () => makeConfig(['retryAttempts' => -1]), 'negative retryAttempts rejected');
$t->throws(ConfigException::class, static fn () => makeConfig(['redis' => ['url' => 'mysql://x']]), 'non-redis url rejected');
$t->throws(ConfigException::class, static fn () => makeConfig(['bufferSize' => 0]), 'zero bufferSize rejected');
$t->throws(ConfigException::class, static fn () => makeConfig(['bufferOverflowPolicy' => 'nonsense']), 'unknown overflow policy rejected');

$config = makeConfig();
$t->same('https://ingest.example.test', $config->endpoint, 'endpoint kept as configured');
$t->same(100, $config->bufferSize, 'default bufferSize is 100');
$t->same(30, $config->flushInterval, 'default flushInterval is 30');
$t->same(300, $config->statusInterval, 'default statusInterval is 300');
$t->same(300, $config->dynamicRuleInterval, 'default dynamicRuleInterval is 300');
$t->same(BufferOverflowPolicy::Drop, $config->bufferOverflowPolicy, 'default overflow policy is drop');
$t->same(['authorization', 'proxy-authorization', 'cookie', 'x-api-key'], $config->sensitiveHeaders, 'default sensitive headers');
$t->same(30, $config->timeout, 'default timeout is 30s');
$t->same(3, $config->retryAttempts, 'default retryAttempts is 3');

$legacy = AgentConfigResolver::resolve([
    'apiKey' => 'test-api-key-123',
    'endpoint' => 'https://ingest.example.test/api/v1/',
    'logger' => new SilentLogger(),
]);
$t->same('https://ingest.example.test', $legacy->endpoint, 'legacy /api/v1 suffix stripped');

$snake = AgentConfigResolver::resolve([
    'apiKey' => 'test-api-key-123',
    'buffer_size' => 7,
    'buffer_overflow_policy' => 'block',
    'logger' => new SilentLogger(),
]);
$t->same(7, $snake->bufferSize, 'snake_case input keys accepted');
$t->same(BufferOverflowPolicy::Block, $snake->bufferOverflowPolicy, 'policy parsed from string');

$rulesIntervalSnake = AgentConfigResolver::resolve([
    'apiKey' => 'test-api-key-123',
    'dynamic_rule_interval' => 120,
    'logger' => new SilentLogger(),
]);
$t->same(120, $rulesIntervalSnake->dynamicRuleInterval, 'snake_case dynamic_rule_interval accepted');

$redisResolved = AgentConfigResolver::resolve([
    'apiKey' => 'test-api-key-123',
    'redis' => ['url' => 'redis://127.0.0.1:6379/0', 'password' => 'explicit-secret', 'commandTimeoutMs' => 1234],
    'logger' => new SilentLogger(),
]);
$t->same('guard:agent', $redisResolved->redis?->keyPrefix, 'redis keyPrefix default');
$t->same(1234.0, $redisResolved->redis?->commandTimeoutMs, 'redis commandTimeoutMs honored');
$t->same('explicit-secret', $redisResolved->redis?->password, 'redis explicit password honored');

$urlParts = new StreamRedisClient('redis://:url-secret@127.0.0.1:6379/2');
$t->same('127.0.0.1', refl($urlParts, 'host')->getValue($urlParts), 'stream client parses host from URL');
$t->same(6379, refl($urlParts, 'port')->getValue($urlParts), 'stream client parses port from URL');
$t->same('url-secret', refl($urlParts, 'password')->getValue($urlParts), 'stream client parses password from URL userinfo');
$t->same(2, refl($urlParts, 'db')->getValue($urlParts), 'stream client parses database from URL path');
$tlsParts = new StreamRedisClient('rediss://127.0.0.1:6380');
$t->same(true, refl($tlsParts, 'tls')->getValue($tlsParts), 'rediss scheme enables TLS');

// =====================================================================
// 2. Wire models
// =====================================================================
$t->section('models');

$event = makeEvent([
    'idempotency_key' => '123e4567-e89b-42d3-a456-426614174000',
    'metadata' => ['rule' => 'sqli'],
]);
$t->same('123e4567-e89b-42d3-a456-426614174000', $event->idempotencyKey, 'event idempotency key kept');
$t->same('penetration_attempt', $event->eventType, 'event_type normalized');
$t->same('', $event->actionTaken, 'action_taken defaults to empty string');
$t->same('', $event->reason, 'reason defaults to empty string');
$t->same('203.0.113.7', $event->ipAddress, 'ip_address snake_case key read');

$camelEvent = SecurityEvent::normalize(['eventType' => 'access_denied', 'ipAddress' => '198.51.100.9', 'timestamp' => WireFormat::now()]);
$t->same('access_denied', $camelEvent->eventType, 'camelCase eventType accepted');
$t->same('198.51.100.9', $camelEvent->ipAddress, 'camelCase ipAddress accepted');

$wire = $event->toWire();
$t->same('123e4567-e89b-42d3-a456-426614174000', $wire['idempotency_key'], 'wire uses snake_case keys');
$t->same('penetration_attempt', $wire['event_type'], 'wire event_type key');
$t->ok(is_string($wire['timestamp']) && str_ends_with((string) $wire['timestamp'], 'Z'), 'wire timestamp is ISO-8601 UTC');
$t->same('sqli', $wire['metadata']->rule ?? null, 'metadata preserved on wire');

$t->throws(InvalidEventException::class, static fn () => SecurityEvent::normalize(['event_type' => 'x', 'idempotency_key' => 'not-a-uuid']), 'non-uuid idempotency key rejected');
$t->throws(InvalidEventException::class, static fn () => SecurityEvent::normalize(['timestamp' => 'nope']), 'invalid timestamp rejected');
$t->throws(InvalidEventException::class, static fn () => SecurityEvent::normalize([]), 'missing event_type rejected');
$t->throws(InvalidEventException::class, static fn () => SecurityEvent::normalize('a string'), 'non-array event rejected');

$fromEpoch = SecurityEvent::normalize(['event_type' => 'x', 'timestamp' => 1700000000]);
$t->same(1700000000, $fromEpoch->timestamp->getTimestamp(), 'epoch seconds timestamp accepted');
$auto = makeEvent();
$t->ok(Uuid::isUuid($auto->idempotencyKey), 'idempotency key auto-generated as UUID v4');

$t->throws(InvalidEventException::class, static fn () => SecurityMetric::normalize(['metric_type' => 'not_a_type', 'value' => 1]), 'unknown metric_type rejected');
$t->throws(InvalidEventException::class, static fn () => SecurityMetric::normalize(['metric_type' => 'request_count']), 'missing metric value rejected');
$metric = makeMetric(['metric_type' => 'response_time', 'value' => '0.5', 'tags' => ['route' => 7]]);
$t->same('response_time', $metric->metricType, 'metric_type validated');
$t->same(0.5, $metric->value, 'string metric value coerced to float');
$t->same(['route' => '7'], $metric->tags, 'tag values coerced to strings');
$t->same('response_time', $metric->toWire()['metric_type'], 'metric wire key is snake_case');

$statusWire = (new AgentStatus(
    timestamp: WireFormat::now(),
    status: 'healthy',
    uptime: 1.5,
    eventsSent: 3,
    eventsFailed: 0,
    bufferSize: 0,
    lastFlush: null,
    errors: [],
))->toWire();
$t->same(
    ['timestamp', 'status', 'uptime', 'events_sent', 'events_failed', 'buffer_size', 'last_flush', 'errors'],
    array_keys($statusWire),
    'status wire payload keys'
);

// --- Dynamic rules model (mirrors DynamicRules, guard_agent/models.py) ---
$rules = DynamicRules::normalize([
    'rule_id' => 'rule-42',
    'version' => 7,
    'timestamp' => '2026-09-27T10:00:00+00:00',
    'expires_at' => '2026-09-28T10:00:00+00:00',
    'ttl' => 120,
    'ip_blacklist' => ['10.0.0.1', '10.0.0.2'],
    'ip_whitelist' => ['192.168.1.1'],
    'ip_ban_duration' => 7200,
    'blocked_countries' => ['CN', 'RU'],
    'whitelist_countries' => ['US'],
    'global_rate_limit' => 500,
    'global_rate_window' => 60,
    'endpoint_rate_limits' => ['/login' => [5, 60]],
    'blocked_cloud_providers' => ['AWS', 'AWS', 'GCP'],
    'blocked_user_agents' => ['curl/*'],
    'suspicious_patterns' => ['union select'],
    'enable_penetration_detection' => true,
    'enable_ip_banning' => false,
    'emergency_mode' => true,
    'emergency_whitelist' => ['203.0.113.9'],
    'emergency_whitelist_only' => true,
    'message' => 'lockdown',
]);
$t->same('rule-42', $rules->ruleId, 'rules: rule_id parsed');
$t->same(7, $rules->version, 'rules: version parsed');
$t->same('2026-09-27T10:00:00+00:00', $rules->timestamp?->format(DATE_ATOM), 'rules: ISO timestamp parsed');
$t->same('2026-09-28T10:00:00+00:00', $rules->expiresAt?->format(DATE_ATOM), 'rules: expires_at parsed');
$t->same(120, $rules->ttl, 'rules: ttl parsed (drives the cache)');
$t->same(['10.0.0.1', '10.0.0.2'], $rules->ipBlacklist, 'rules: ip_blacklist parsed');
$t->same(['192.168.1.1'], $rules->ipWhitelist, 'rules: ip_whitelist parsed');
$t->same(7200, $rules->ipBanDuration, 'rules: ip_ban_duration parsed');
$t->same(['CN', 'RU'], $rules->blockedCountries, 'rules: blocked_countries parsed');
$t->same(['US'], $rules->whitelistCountries, 'rules: whitelist_countries parsed');
$t->same(500, $rules->globalRateLimit, 'rules: global_rate_limit parsed');
$t->same(60, $rules->globalRateWindow, 'rules: global_rate_window parsed');
$t->same(['/login' => [5, 60]], $rules->endpointRateLimits, 'rules: endpoint_rate_limits parsed as [requests, window] pairs');
$t->same(['AWS', 'GCP'], $rules->blockedCloudProviders, 'rules: blocked_cloud_providers deduped like the Python set');
$t->same(['curl/*'], $rules->blockedUserAgents, 'rules: blocked_user_agents parsed');
$t->same(['union select'], $rules->suspiciousPatterns, 'rules: suspicious_patterns parsed');
$t->same(true, $rules->enablePenetrationDetection, 'rules: enable_penetration_detection parsed');
$t->same(false, $rules->enableIpBanning, 'rules: enable_ip_banning parsed');
$t->same(null, $rules->enableRateLimiting, 'rules: absent override stays null');
$t->same(null, $rules->autoBanThreshold, 'rules: absent auto_ban_threshold stays null');
$t->same(true, $rules->emergencyMode, 'rules: emergency_mode parsed');
$t->same(true, $rules->emergencyWhitelistOnly, 'rules: emergency_whitelist_only parsed');
$t->same('lockdown', $rules->message, 'rules: message parsed');

$defaultRules = DynamicRules::normalize(['unknown_field' => 'ignored', 'another' => ['x']]);
$t->same('default-rule', $defaultRules->ruleId, 'rules: default rule_id');
$t->same(1, $defaultRules->version, 'rules: default version');
$t->ok($defaultRules->timestamp !== null, 'rules: timestamp defaults to now');
$t->same(null, $defaultRules->expiresAt, 'rules: expires_at defaults to null');
$t->same(300, $defaultRules->ttl, 'rules: default ttl 300');
$t->same([], $defaultRules->ipBlacklist, 'rules: empty ip_blacklist default');
$t->same([], $defaultRules->endpointRateLimits, 'rules: empty endpoint_rate_limits default');
$t->same([], $defaultRules->blockedCloudProviders, 'rules: empty blocked_cloud_providers default');
$t->same(3600, $defaultRules->ipBanDuration, 'rules: default ip_ban_duration 3600');
$t->same(false, $defaultRules->emergencyMode, 'rules: default emergency_mode false');
$t->same(null, $defaultRules->message, 'rules: default message null');
$t->ok(!isset($defaultRules->unknown_field), 'rules: unknown fields ignored');

$camelRules = DynamicRules::normalize(['ruleId' => 'camel-1', 'ipBlacklist' => ['10.0.0.3'], 'ttl' => 1]);
$t->same('camel-1', $camelRules->ruleId, 'rules: camelCase keys accepted');
$t->same(['10.0.0.3'], $camelRules->ipBlacklist, 'rules: camelCase ipBlacklist accepted');

$t->throws(InvalidRulesException::class, static fn () => DynamicRules::normalize('a string'), 'rules: non-array payload rejected');
$t->throws(InvalidRulesException::class, static fn () => DynamicRules::normalize(['ip_blacklist' => 'not-a-list']), 'rules: scalar ip_blacklist rejected');
$t->throws(InvalidRulesException::class, static fn () => DynamicRules::normalize(['ip_blacklist' => [1]]), 'rules: non-string ip_blacklist entry rejected');
$t->throws(InvalidRulesException::class, static fn () => DynamicRules::normalize(['endpoint_rate_limits' => ['/x' => [5]]]), 'rules: one-element endpoint pair rejected');
$t->throws(InvalidRulesException::class, static fn () => DynamicRules::normalize(['endpoint_rate_limits' => 'nope']), 'rules: scalar endpoint_rate_limits rejected');
$t->throws(InvalidRulesException::class, static fn () => DynamicRules::normalize(['enable_ip_banning' => 'yes']), 'rules: non-boolean override rejected');
$t->throws(InvalidRulesException::class, static fn () => DynamicRules::normalize(['auto_ban_threshold' => 0]), 'rules: auto_ban_threshold below 1 rejected (ge=1)');
$t->throws(InvalidRulesException::class, static fn () => DynamicRules::normalize(['auto_ban_duration' => 0]), 'rules: auto_ban_duration below 1 rejected (ge=1)');
$t->throws(InvalidRulesException::class, static fn () => DynamicRules::normalize(['timestamp' => 'nope']), 'rules: invalid timestamp rejected');
$t->same(0, DynamicRules::normalize(['version' => 0])->version, 'rules: version 0 kept (no ge constraint in the pydantic model)');

// =====================================================================
// 3. Shared utilities
// =====================================================================
$t->section('utils');

$t->same(1.0, Backoff::calculate(0), 'backoff attempt 0');
$t->same(4.0, Backoff::calculate(2), 'backoff doubles per attempt');
$t->same(60.0, Backoff::calculate(10), 'backoff capped at default 60s');
$t->same(300.0, Backoff::calculate(10, 30.0, 300.0), 'per-kind backoff capped at 300s');

$t->same(60.0, RetryAfter::parse(null), 'missing Retry-After defaults to 60');
$t->same(120.0, RetryAfter::parse('120'), 'numeric Retry-After parsed');
$t->same(60.0, RetryAfter::parse('junk'), 'junk Retry-After falls back to default');
$t->same(0.0, RetryAfter::parse('-5'), 'negative Retry-After clamps to 0');

$t->ok(preg_match('/^\d{13}-[0-9a-f]{8}$/', BatchId::generate()) === 1, 'batch id is epoch-millis + 8 hex');
$t->ok(Uuid::isUuid(Uuid::v4()), 'uuid v4 is canonical');
$t->ok(!Uuid::isUuid('12345'), 'non-uuid rejected');

$t->same('a b c', ResponseSummary::summarize("  a\n\t b   c  "), 'summary collapses whitespace');
$t->ok(str_contains(ResponseSummary::summarize(str_repeat('x', 400)), '[truncated, 400 chars total]'), 'summary truncates with indicator');

$t->same('abc', PayloadTruncator::truncate('abc', 10), 'truncate keeps short payload intact');
$t->same('ab...[TRUNCATED]', PayloadTruncator::truncate('abcdef', 2), 'truncate appends the TRUNCATED indicator');
$t->same(str_repeat('x', 5), PayloadTruncator::truncate(str_repeat('x', 5), 5), 'truncate at the boundary keeps the payload');
$t->same(substr(hash('sha256', '1.2.3.4'), 0, 16), IpHasher::hash('1.2.3.4'), 'hash_ip is sha256 hex truncated to 16 chars');
$t->same(substr(hash('sha256', '1.2.3.4pepper'), 0, 16), IpHasher::hash('1.2.3.4', 'pepper'), 'hash_ip mixes in the salt');
$t->ok(!str_contains(IpHasher::hash('1.2.3.4'), '1.2.3.4'), 'hash_ip does not leak the address');

$redacted = HeadersRedactor::sanitize(
    ['Authorization' => 'Bearer abc', 'nested' => ['COOKIE' => 'session=1'], 'keep' => 'yes'],
    ['authorization', 'cookie']
);
$t->same('[REDACTED]', $redacted['Authorization'], 'sensitive header redacted case-insensitively');
$t->same('[REDACTED]', $redacted['nested']['COOKIE'], 'redaction recurses into nested arrays');
$t->same('yes', $redacted['keep'], 'non-sensitive values kept');
$t->same('plain', HeadersRedactor::sanitize('plain', ['authorization']), 'plain string untouched');
$t->same(
    Json::encode(['authorization' => '[REDACTED]', 'plain' => 'value']),
    HeadersRedactor::sanitize('{"authorization":"secret","plain":"value"}', ['authorization']),
    'JSON-looking strings sanitized and re-encoded'
);

$t->same(null, Json::decodeAssocOrNull('not json'), 'invalid JSON decodes to null');
$t->same(['a' => 1], Json::decodeAssocOrNull('{"a":1}'), 'JSON object decodes to array');
$t->throws(SerializationException::class, static fn () => Json::encode(fopen('php://memory', 'rb')), 'unserializable value raises SerializationException');

// =====================================================================
// 4. Payload signing (HMAC over the uncompressed body)
// =====================================================================
$t->section('signing');

$body = '{"hello":"world"}';
// The signature is v1= + HMAC-SHA256 over the exact uncompressed body bytes,
// the same primitive the server uses when it verifies post-decompression.
// The end-to-end pin is the mock-server smoke below, which runs with
// requireSigned=true: a signature over the wrong bytes (e.g. post-gzip) is
// rejected with 401, so the contract cannot silently drift.
$t->same(
    'v1=' . hash_hmac('sha256', $body, 'test-secret'),
    Signer::signPayload($body, 'test-secret'),
    'signature matches hash_hmac over the uncompressed body'
);
$signature = (string) Signer::signPayload($body, 'test-secret');
$t->ok(preg_match('/^v1=[0-9a-f]{64}$/', $signature) === 1, 'signature is v1= plus 64 lowercase hex characters');
$t->same(null, Signer::signPayload($body, null), 'no secret, no signature header');
$t->same(null, Signer::signPayload($body, ''), 'empty secret, no signature header');

// =====================================================================
// 5. Buffer semantics
// =====================================================================
$t->section('buffer');

$buffer = new EventBuffer(makeConfig(['bufferSize' => 3, 'highWatermarkRatio' => 0.8]));
$buffer->addEvent(makeEvent(['event_type' => 'a']));
$buffer->addEvent(makeEvent(['event_type' => 'b']));
$buffer->addEvent(makeEvent(['event_type' => 'c']));
$t->same(3, $buffer->getBufferSize(), 'buffer holds all three events');
$t->ok($buffer->atHighWatermark(), 'high-watermark reached at the 80 percent ratio');

[$drained, $keys] = $buffer->flushEventsWithKeys();
$t->same(['a', 'b', 'c'], eventTypes($drained), 'drain preserves order');
$t->same(['', '', ''], $keys, 'keys empty without persistence');
$t->same(0, $buffer->getBufferSize(), 'drain empties the buffer');
$t->same(3, $buffer->getStats()['eventsFlushed'], 'flush counter tracks drained events');

$buffer->addEvent(makeEvent(['event_type' => 'a']));
$buffer->addEvent(makeEvent(['event_type' => 'b']));
$buffer->addEvent(makeEvent(['event_type' => 'c']));
$buffer->addEvent(makeEvent(['event_type' => 'd']));
$t->same(['b', 'c', 'd'], eventTypes($buffer->flushEventsWithKeys()[0]), 'drop policy evicts the oldest entry');
$t->same(1, $buffer->eventsDropped, 'drop counter incremented');

$raiseBuffer = new EventBuffer(makeConfig(['bufferSize' => 1, 'bufferOverflowPolicy' => 'raise']));
$raiseBuffer->addEvent(makeEvent(['event_type' => 'a']));
$t->throws(BufferFullException::class, static fn () => $raiseBuffer->addEvent(makeEvent(['event_type' => 'b'])), 'raise policy throws BufferFullException');

$blockBuffer = new EventBuffer(makeConfig(['bufferSize' => 1, 'bufferOverflowPolicy' => 'block']));
$blockBuffer->addEvent(makeEvent(['event_type' => 'a']));
$drains = 0;
$blockBuffer->drainCallback = function () use (&$drains, $blockBuffer): void {
    $drains++;
    $blockBuffer->flushEventsWithKeys();
};
$blockBuffer->addEvent(makeEvent(['event_type' => 'b']));
$t->ok($drains >= 1, 'block policy drained inline while waiting for space');
$t->same(['b'], eventTypes($blockBuffer->flushEventsWithKeys()[0]), 'block policy admitted the new item after the drain');

// Requeue keeps order without persistence.
$buffer = new EventBuffer(makeConfig(['bufferSize' => 5]));
$buffer->addEvent(makeEvent(['event_type' => 'resident']));
[$drained, $keys] = $buffer->flushEventsWithKeys();
$evicted = $buffer->requeueEventsInMemory($drained, $keys);
$t->same([], $evicted, 'requeue without persistence evicts nothing');
$t->same(['resident'], eventTypes($buffer->flushEventsWithKeys()[0]), 'requeued batch restored to the front');

// Requeue under pressure evicts from the tail and returns those keys.
$prefix = 'guard:agent:test:' . bin2hex(random_bytes(4));
$fake = new FakeRedisClient();
$buffer = new EventBuffer(makeConfig(['bufferSize' => 3]));
$buffer->initializeRedis(new RedisHandler($fake, $prefix, new SilentLogger()));
$resident = makeEvent(['event_type' => 'resident']);
$buffer->addEvent($resident);
[$drained, $residentKeys] = $buffer->flushEventsWithKeys();
$t->same(1, count($fake->storage), 'enqueue persisted the resident event');
$requeue = [
    $resident,
    makeEvent(['event_type' => 'n1']),
    makeEvent(['event_type' => 'n2']),
    makeEvent(['event_type' => 'n3']),
    makeEvent(['event_type' => 'n4']),
];
$evicted = $buffer->requeueEventsInMemory($requeue, [$residentKeys[0], 'k1', 'k2', 'k3', 'k4']);
$t->same(2, count($evicted), 'requeue under pressure returns the evicted tail keys');
$t->same(['k4', 'k3'], $evicted, 'tail eviction forgets the newest keys first');
$t->same(['resident', 'n1', 'n2'], eventTypes($buffer->flushEventsWithKeys()[0]), 'requeue evicted the newest items, kept the front');
$t->same(2, $buffer->eventsDropped, 'requeue evictions counted as drops');

// clearBuffer wipes both memory and the Redis namespaces.
$buffer = new EventBuffer(makeConfig());
$buffer->initializeRedis(new RedisHandler($fake, $prefix, new SilentLogger()));
$buffer->addEvent(makeEvent(['event_type' => 'a']));
$buffer->addMetric(makeMetric());
$buffer->clearBuffer();
$t->same(0, $buffer->getBufferSize(), 'clearBuffer empties memory');
$t->same([], $fake->storage, 'clearBuffer wipes persisted records');

// Metrics persistence uses its own namespace and TTL.
$buffer = new EventBuffer(makeConfig());
$buffer->initializeRedis(new RedisHandler($fake, $prefix, new SilentLogger()));
$buffer->addMetric(makeMetric(['metric_type' => 'error_rate', 'value' => 0.25]));
$metricKeys = $fake->keysContaining(':agent_metrics:metric_');
$t->same(1, count($metricKeys), 'metric persisted under the agent_metrics namespace');
$t->same(3600, $fake->ttls[$metricKeys[0]] ?? null, 'metric persistence TTL is 3600 seconds');

// =====================================================================
// 6. Install ID
// =====================================================================
$t->section('install id');

$t->same('override-id', InstallId::resolve(sys_get_temp_dir() . '/unused-install-id', 'override-id', new SilentLogger()), 'override wins');
$tmpIdFile = sys_get_temp_dir() . '/gaph-install-' . bin2hex(random_bytes(4));
$generated = InstallId::resolve($tmpIdFile, null, new SilentLogger());
$t->ok(Uuid::isUuid($generated), 'fresh install id is a UUID');
$t->same($generated, InstallId::resolve($tmpIdFile, null, new SilentLogger()), 'install id cached on disk');
$t->ok(is_file($tmpIdFile), 'install id file written');
$t->ok(str_ends_with(InstallId::defaultPath(), '/.guard-agent/install-id'), 'default path is ~/.guard-agent/install-id');

// =====================================================================
// 7. Circuit breaker and rate limiter
// =====================================================================
$t->section('circuit breaker and rate limiter');

$breaker = new CircuitBreaker(5, 60.0);
$boom = new RuntimeException('boom');
for ($i = 0; $i < 5; $i++) {
    try {
        $breaker->call(static function () use ($boom): void {
            throw $boom;
        });
    } catch (RuntimeException) {
    }
}
$t->same('OPEN', $breaker->state, 'breaker opens after 5 consecutive failures');
$t->same(5, $breaker->failureCount, 'failure count tracked');
$t->throws(\RenzoFranceschini\GuardAgent\Exception\GuardAgentException::class, static fn () => $breaker->call(static fn (): null => null), 'open breaker rejects calls');
refl($breaker, 'lastFailureTime')->setValue($breaker, microtime(true) - 61.0);
$entered = false;
try {
    $breaker->call(static function () use (&$entered, $boom): void {
        $entered = true;
        throw $boom;
    });
} catch (RuntimeException) {
}
$t->ok($entered, 'breaker half-opens after the recovery timeout and lets the probe through');
$t->same('OPEN', $breaker->state, 'failed half-open probe reopens the breaker');
refl($breaker, 'lastFailureTime')->setValue($breaker, microtime(true) - 61.0);
$breaker->call(static fn (): null => null);
$t->same('CLOSED', $breaker->state, 'success closes the breaker');
$t->same(0, $breaker->failureCount, 'failure count reset on success');

$permBreaker = new CircuitBreaker(5, 60.0);
try {
    $permBreaker->call(static function (): void {
        throw new PermanentClientException(400, 'bad');
    });
} catch (PermanentClientException) {
}
$t->same(0, $permBreaker->failureCount, 'permanent client errors exempt from the breaker');
$t->same('CLOSED', $permBreaker->state, 'permanent client errors leave the breaker closed');

$limiter = new RateLimiter(2, 60.0);
$t->ok($limiter->acquire(), 'rate limiter first call allowed');
$t->ok($limiter->acquire(), 'rate limiter second call allowed');
$t->ok(!$limiter->acquire(), 'rate limiter third call denied');
$t->ok($limiter->getRetryAfter() > 0.0, 'rate limiter reports retry-after');

// =====================================================================
// 8. Agent handshake with a scriptable transport
// =====================================================================
$t->section('agent handshake');

$transport = new RecordingTransport();
$agent = makeAgent(['flushInterval' => 30], $transport);
$agent->sendEvent(makeEvent(['event_type' => 'a']));
$agent->sendEvent(makeEvent(['event_type' => 'b']));
$agent->sendEvent(['event_type' => 42, 'timestamp' => 'nope']);
$agent->sendMetric(makeMetric());
$t->same(2, $agent->buffer->getStats()['currentEventBufferSize'], 'invalid event logged and dropped, not buffered');
$t->same(1, $agent->buffer->getStats()['currentMetricBufferSize'], 'metric buffered');

$agent->flushBuffer();
$t->same(1, count($transport->eventBatches), 'one event batch sent');
$t->same(1, count($transport->metricBatches), 'one metric batch sent');
$t->same(2, $agent->eventsSent, 'events counted as sent');
$t->same(1, $agent->metricsSent, 'metrics counted as sent');
$t->same(0, $agent->buffer->getBufferSize(), 'buffer empty after a successful flush');
$agent->start();
$agent->start();
$t->same(1, $transport->initialized, 'start initializes the transport once (idempotent)');
$t->ok($agent->healthCheck(), 'healthy agent passes the health check');
$t->same('healthy', $agent->getStatus()->status, 'healthy status reported');
$t->ok($agent->getStats()['uptime'] >= 0.0, 'stats expose uptime');

// Sensitive metadata redacted on the ingest path.
$transport = new RecordingTransport();
$agent = makeAgent([], $transport);
$agent->sendEvent(makeEvent(['event_type' => 'redact', 'metadata' => ['Authorization' => 'Bearer secret', 'keep' => 'v']]));
[$buffered] = $agent->buffer->flushEventsWithKeys();
$t->same('[REDACTED]', $buffered[0]->metadata['Authorization'], 'sensitive metadata redacted on ingest');
$t->same('v', $buffered[0]->metadata['keep'], 'non-sensitive metadata kept');

// Failure: requeue, streak, and the per-kind gate.
$transport = new RecordingTransport();
$agent = makeAgent(['flushInterval' => 30], $transport);
$agent->sendEvent(makeEvent(['event_type' => 'a']));
$agent->sendEvent(makeEvent(['event_type' => 'b']));
$transport->eventOutcomes = [false];
$agent->flushBuffer();
$t->same(0, $agent->eventsSent, 'failed flush sends nothing');
$t->same(2, $agent->eventsFailed, 'failed flush counts every event as failed');
$t->same(2, $agent->buffer->getBufferSize(), 'failed batch requeued');
$agent->flushBuffer();
$t->same(1, count($transport->eventBatches), 'per-kind gate skips the immediate retry');
$gate = refl($agent, 'eventsRetryAfter')->getValue($agent);
$t->ok($gate > microtime(true) + 29.0 && $gate <= microtime(true) + 31.0, 'streak 1 gates for flushInterval seconds');
$t->same(['a', 'b'], eventTypes($agent->buffer->flushEventsWithKeys()[0]), 'requeued batch keeps its original order');

// A throwing transport requeues, counts a loop failure, and never escapes.
$transport = new RecordingTransport();
$agent = makeAgent(['flushInterval' => 30], $transport);
$agent->sendEvent(makeEvent(['event_type' => 'a']));
$transport->eventOutcomes = [new RuntimeException('down')];
$agent->flushBuffer();
$t->same(1, $agent->buffer->getBufferSize(), 'throwing transport requeues');
$t->same(1, $agent->getStats()['loopFailures']['flush'], 'flush loop failure counted');
$t->same(1, $agent->eventsFailed, 'throwing transport counts a failed flush');

// Partial 200 (sendEvents false) requeues the whole batch: at-least-once.
$transport = new RecordingTransport();
$agent = makeAgent(['flushInterval' => 30], $transport);
$agent->sendEvent(makeEvent(['event_type' => 'a']));
$agent->sendEvent(makeEvent(['event_type' => 'b']));
$transport->eventOutcomes = [false];
$agent->flushBuffer();
$t->same(2, $agent->buffer->getBufferSize(), 'partial failure requeues all items');
refl($agent, 'eventsRetryAfter')->setValue($agent, 0.0);
$agent->flushBuffer();
$t->same(2, $agent->eventsSent, 'retry after a partial failure delivers the whole batch');

// The partial-failure warning must describe where unsent items actually wait:
// memory only without Redis, memory plus Redis with a Redis handler attached.
$logger = new CaptureLogger();
$transport = new RecordingTransport();
$agent = makeAgent(['flushInterval' => 30, 'logger' => $logger], $transport);
$agent->sendEvent(makeEvent(['event_type' => 'a']));
$transport->eventOutcomes = [false];
$agent->flushBuffer();
$t->same(1, count($logger->warnings), 'first flush failure logs one warning');
$t->ok(str_contains($logger->warnings[0] ?? '', 'requeued in memory (events) for retry'), 'warning without Redis says memory only');
$t->ok(!str_contains($logger->warnings[0] ?? '', 'retained in Redis'), 'warning without Redis does not claim Redis retention');

$logger = new CaptureLogger();
$transport = new RecordingTransport();
$agent = makeAgent(['flushInterval' => 30, 'logger' => $logger], $transport);
$agent->initializeRedis(new RedisHandler(new FakeRedisClient(), 'gatest', new SilentLogger()));
$agent->sendEvent(makeEvent(['event_type' => 'a']));
$transport->eventOutcomes = [false];
$agent->flushBuffer();
$t->ok(str_contains($logger->warnings[0] ?? '', 'requeued in memory and retained in Redis (events) for retry'), 'warning with Redis mentions Redis retention');

// Per-kind isolation: events fail, metrics succeed.
$transport = new RecordingTransport();
$transport->eventOutcomes = [false];
$agent = makeAgent(['flushInterval' => 30], $transport);
$agent->sendEvent(makeEvent());
$agent->sendMetric(makeMetric());
$agent->flushBuffer();
$t->same(1, $agent->metricsSent, 'metrics unaffected by an event failure');
$t->same(1, $agent->eventsFailed, 'events failed independently');
$t->same(1, $agent->buffer->getBufferSize(), 'only the failed kind is requeued');

// Overflow policies through the agent.
$agent = makeAgent(['bufferSize' => 1], new RecordingTransport());
$agent->sendEvent(makeEvent(['event_type' => 'first']));
$agent->sendEvent(makeEvent(['event_type' => 'second']));
$t->same(['second'], eventTypes($agent->buffer->flushEventsWithKeys()[0]), 'drop policy keeps the newest event');

$agent = makeAgent(['bufferSize' => 1, 'bufferOverflowPolicy' => 'raise'], new RecordingTransport());
$agent->sendEvent(makeEvent(['event_type' => 'first']));
$agent->sendEvent(makeEvent(['event_type' => 'second']));
$t->same(1, $agent->buffer->getBufferSize(), 'sendEvent swallows BufferFullException under raise policy');

// Status degradation thresholds.
$agent = makeAgent(['bufferSize' => 10, 'flushInterval' => 30], new RecordingTransport());
for ($i = 0; $i < 9; $i++) {
    $agent->sendEvent(makeEvent(['event_type' => "e{$i}"]));
}
$t->same('degraded', $agent->getStatus()->status, 'buffer at 90 percent reports degraded');
$t->same(['Buffer nearly full'], $agent->getStatus()->errors, 'degradation reason reported');

$transport = new RecordingTransport();
$transport->eventOutcomes = [false];
$agent = makeAgent(['flushInterval' => 30], $transport);
$agent->sendEvent(makeEvent());
$agent->flushBuffer();
$status = $agent->getStatus();
$t->same('degraded', $status->status, 'failure rate above 10 percent reports degraded');
$t->ok(count($status->errors) === 0 || is_string($status->errors[0]), 'status errors are strings');
$agent->start();
$t->ok(!$agent->healthCheck(), 'health check fails at a 100 percent failure rate');

// tick() pushes status only after start, on the status interval.
$transport = new RecordingTransport();
$agent = makeAgent(['statusInterval' => 60], $transport);
$agent->tick();
$t->same(0, count($transport->statusCalls), 'tick before start does nothing');
$agent->start();
refl($agent, 'nextStatusPushAt')->setValue($agent, microtime(true) - 1.0);
$agent->tick();
$t->same(1, count($transport->statusCalls), 'tick pushes status when the interval elapsed');
$t->same(true, refl($agent, 'lastStatusPushOk')->getValue($agent), 'status push recorded ok');
$agent->tick();
$t->same(1, count($transport->statusCalls), 'status push not repeated before the next interval');

// tick() flushes when the flush interval elapsed.
$transport = new RecordingTransport();
$agent = makeAgent(['flushInterval' => 1], $transport);
$agent->start();
$agent->sendEvent(makeEvent());
refl($agent, 'nextStatusPushAt')->setValue($agent, microtime(true) + 3600.0);
usleep(1_100_000);
$agent->tick();
$t->same(1, count($transport->eventBatches), 'tick flushes once the flush interval elapsed');

// stop() is idempotent and flushes what is buffered.
$transport = new RecordingTransport();
$agent = makeAgent(['flushInterval' => 30], $transport);
$agent->start();
$agent->sendEvent(makeEvent());
$agent->stop();
$agent->stop();
$t->same(1, count($transport->eventBatches), 'stop performs the final flush');
$t->same(1, $transport->closed, 'stop closes the transport once');
$t->ok(!$agent->isRunning(), 'agent no longer running after stop');

// flushIfNeeded respects the high-watermark.
$transport = new RecordingTransport();
$agent = makeAgent(['bufferSize' => 4, 'highWatermarkRatio' => 0.5, 'flushInterval' => 3600], $transport);
$agent->sendEvent(makeEvent());
$agent->sendEvent(makeEvent());
$agent->flushIfNeeded();
$t->same(1, count($transport->eventBatches), 'flushIfNeeded fires at the high-watermark');
$agent->sendEvent(makeEvent());
$agent->sendEvent(makeEvent());
$agent->flushIfNeeded();
$t->same(2, count($transport->eventBatches), 'flushIfNeeded fires again above the watermark');

// =====================================================================
// 9. Persistence handshake (in-memory fake)
// =====================================================================
$t->section('persistence handshake (fake redis)');

$prefix = 'guard:agent:test:' . bin2hex(random_bytes(4));
$fake = new FakeRedisClient();
$transport = new RecordingTransport();
$agent = makeAgent(['flushInterval' => 30], $transport);
$agent->initializeRedis(new RedisHandler($fake, $prefix, new SilentLogger()));
$agent->sendEvent(makeEvent(['event_type' => 'a']));
$eventKeys = $fake->keysContaining(':agent_events:event_');
$t->same(1, count($eventKeys), 'event persisted on enqueue');
$t->ok(str_starts_with($eventKeys[0], $prefix . ':agent_events:event_'), 'persistence key is prefixed and globally unique');
$t->same(3600, $fake->ttls[$eventKeys[0]] ?? null, 'persistence TTL is 3600 seconds');

$fake->failWrites(true);
$agent->sendEvent(makeEvent(['event_type' => 'b']));
$t->same(1, $agent->buffer->getStats()['redisPersistFailures'], 'persist failure counted');
$t->ok($agent->buffer->getStats()['durabilityDegraded'], 'durability reported degraded after a persist failure');
$fake->failWrites(false);

$transport->eventOutcomes = [false, true];
$agent->flushBuffer();
$t->same(0, $agent->eventsSent, 'first flush failed');
$t->same(2, $agent->eventsFailed, 'failed flush counts both events');
$t->ok($fake->storage !== [], 'failed flush retains the Redis records');
refl($agent, 'eventsRetryAfter')->setValue($agent, 0.0);
$agent->flushBuffer();
$t->same(2, $agent->eventsSent, 'second flush delivers both events');
$t->same([], $fake->storage, 'confirmed flush deletes the Redis records');

// Startup reload: a second agent picks up persisted records.
$fake = new FakeRedisClient();
$handler = new RedisHandler($fake, $prefix, new SilentLogger());
$agentA = makeAgent(['flushInterval' => 30], new RecordingTransport());
$agentA->initializeRedis($handler);
$agentA->sendEvent(makeEvent(['event_type' => 'persisted']));
$t->same(1, count($fake->storage), 'agent A persisted the event');
$transportB = new RecordingTransport();
$agentB = makeAgent(['flushInterval' => 30], $transportB);
$agentB->initializeRedis($handler);
$t->same(1, $agentB->buffer->getBufferSize(), 'startup reload restores the persisted event');
[$reloaded, $reloadedKeys] = $agentB->buffer->flushEventsWithKeys();
$t->same(['persisted'], eventTypes($reloaded), 'reloaded event is intact');
$t->ok($reloadedKeys[0] !== '', 'reloaded event keeps its persistence key');
$agentB->buffer->requeueEventsInMemory($reloaded, $reloadedKeys);
$transportB->eventOutcomes = [true];
$agentB->flushBuffer();
$t->same(1, $agentB->eventsSent, 'reloaded event delivered');
$t->same([], $fake->storage, 'reloaded event confirmed and deleted after the send');

// Corrupt persisted records are skipped, not fatal.
$fake = new FakeRedisClient();
$fake->set($prefix . ':agent_events:event_corrupt', '{not json', 3600);
$agent = makeAgent([], new RecordingTransport());
$agent->initializeRedis(new RedisHandler($fake, $prefix, new SilentLogger()));
$t->same(0, $agent->buffer->getBufferSize(), 'corrupt persisted record skipped');

// Fail-open cooldown after consecutive write failures.
$deadClient = new StreamRedisClient('redis://127.0.0.1:1/0', null, null, 0.2);
$deadHandler = new RedisHandler($deadClient, $prefix, new SilentLogger());
$t->same(false, $deadHandler->setKey('agent_events', 'k1', 'v', 3600), 'write to a dead redis fails open');
$t->same(false, $deadHandler->setKey('agent_events', 'k2', 'v', 3600), 'second write fails open');
$t->same(false, $deadHandler->setKey('agent_events', 'k3', 'v', 3600), 'third write fails open');
$before = $deadHandler->failureCount();
$started = microtime(true);
$deadHandler->setKey('agent_events', 'k4', 'v', 3600);
$elapsed = microtime(true) - $started;
$t->same($before + 1, $deadHandler->failureCount(), 'cooldown write counted without a connect attempt');
$t->ok($elapsed < 0.1, 'cooldown write fails fast');
$t->same([], $deadHandler->keys('agent_events:*'), 'keys against a dead redis return empty');

// =====================================================================
// 10. Real Redis integration (skipped with REDIS_HOST=0)
// =====================================================================
$t->section('persistence integration (real redis)');

$redisUrl = redisUrl();
$realClient = null;
if ($redisUrl === '') {
    $t->skip('REDIS_HOST=0, persistence integration skipped');
} else {
    try {
        $realClient = new StreamRedisClient($redisUrl, null, null, 2.0);
        $realClient->ping();
    } catch (Throwable $error) {
        $realClient = null;
        $t->skip('redis unreachable at ' . $redisUrl . ': ' . $error->getMessage());
    }
}
if ($realClient !== null) {
    $t->ok(true, 'stream client pings the real redis');
    $namespace = 'guard:agent:test:' . bin2hex(random_bytes(4));
    $realClient->set($namespace . ':probe', 'v', 60);
    $t->same('v', $realClient->get($namespace . ':probe'), 'stream client set/get round trip');
    $t->same(null, $realClient->get($namespace . ':missing'), 'stream client get miss returns null');
    $t->same([$namespace . ':probe'], $realClient->keys($namespace . ':probe'), 'stream client keys');
    $t->same(1, $realClient->delete($namespace . ':probe'), 'stream client delete');

    $transportA = new RecordingTransport();
    $agentA = new GuardAgent(makeConfig(['flushInterval' => 30, 'installId' => 'install-real']), $transportA);
    $agentA->initializeRedis(new RedisHandler($realClient, $namespace, new SilentLogger()));
    $agentA->sendEvent(makeEvent(['event_type' => 'durable']));
    $t->same(1, count($realClient->keys($namespace . ':agent_events:*')), 'event persisted to the real redis on enqueue');

    $transportB = new RecordingTransport();
    $agentB = new GuardAgent(makeConfig(['flushInterval' => 30, 'installId' => 'install-real']), $transportB);
    $agentB->initializeRedis(new RedisHandler($realClient, $namespace, new SilentLogger()));
    $t->same(1, $agentB->buffer->getBufferSize(), 'startup reload from the real redis');
    $transportB->eventOutcomes = [true];
    $agentB->flushBuffer();
    $t->same(1, $agentB->eventsSent, 'reloaded batch delivered');
    $t->same([], $realClient->keys($namespace . ':agent_events:*'), 'confirmed keys deleted from the real redis');
}

// =====================================================================
// 11. Integration smoke against the mock ingestion API
// =====================================================================
$t->section('integration smoke (mock ingestion API)');

[$proc, $port, $controlFile, $stateFile] = startMockServer();

$secret = 'it-signing-secret';
$baseOverrides = [
    'endpoint' => "http://127.0.0.1:{$port}",
    'apiKey' => 'test-api-key-123',
    'projectId' => 'proj-smoke',
    'payloadSigningSecret' => $secret,
    'installId' => 'install-smoke-1',
    'compressionEnabled' => true,
    'compressionThreshold' => 1024,
    'retryAttempts' => 1,
    'backoffFactor' => 0.01,
    'timeout' => 10,
];

// Happy path: gzip body, valid uncompressed-body signature, required headers.
flushState($stateFile);
setScript($controlFile, [], $secret, true);
$agent = new GuardAgent(makeConfig($baseOverrides));
$agent->start();
$agent->sendEvent(makeEvent(['event_type' => 'suspicious_request', 'metadata' => ['note' => str_repeat('x', 2000)]]));
$agent->sendEvent(makeEvent(['event_type' => 'rate_limited']));
$agent->flushBuffer();
$t->same(2, $agent->eventsSent, 'smoke: batch accepted with a valid signature');
$records = stateFor($stateFile, '/api/v1/events');
$t->same(1, count($records), 'smoke: both events in a single request');
$record = $records[0] ?? [];
$t->same(200, $record['status'] ?? null, 'smoke: request accepted');
$t->same('gzip', $record['content_encoding'] ?? null, 'smoke: body gzipped above the threshold');
$t->same('test-api-key-123', $record['x_api_key'] ?? null, 'smoke: X-API-Key header sent');
$t->same('proj-smoke', $record['x_project_id'] ?? null, 'smoke: X-Project-Id header sent');
$t->same('install-smoke-1', $record['x_agent_install_id'] ?? null, 'smoke: X-Agent-Install-Id header sent');
$t->same(Version::USER_AGENT, $record['user_agent'] ?? null, 'smoke: User-Agent header sent');

// The mock runs with requireSigned=true, so a signature computed over the gzip
// bytes would have been rejected with 401; 200 proves the HMAC covers the
// uncompressed body exactly as the server verifies it.
$t->same('POST', $record['method'] ?? null, 'smoke: request method is POST');
$t->same('/api/v1/events', $record['path'] ?? null, 'smoke: versioned events path used');

// Small body stays uncompressed, signature still verifies.
flushState($stateFile);
setScript($controlFile, [], $secret, true);
$agent = new GuardAgent(makeConfig($baseOverrides));
$agent->sendEvent(makeEvent(['event_type' => 'tiny']));
$agent->flushBuffer();
$records = stateFor($stateFile, '/api/v1/events');
$t->same('', $records[0]['content_encoding'] ?? 'missing', 'smoke: small body left uncompressed');
$t->same(200, $records[0]['status'] ?? null, 'smoke: signature valid on the uncompressed body');

// Metrics go to their own endpoint.
flushState($stateFile);
$agent = new GuardAgent(makeConfig($baseOverrides));
$agent->sendMetric(makeMetric(['metric_type' => 'response_time', 'value' => 0.023]));
$agent->flushBuffer();
$t->same(1, $agent->metricsSent, 'smoke: metric accepted');
$t->same(1, count(stateFor($stateFile, '/api/v1/metrics')), 'smoke: metrics endpoint used');

// Status reports go to the status endpoint.
flushState($stateFile);
$statusTransport = new HttpTransport(makeConfig($baseOverrides));
$t->ok($statusTransport->sendStatus(new AgentStatus(
    timestamp: WireFormat::now(),
    status: 'healthy',
    uptime: 1.0,
    eventsSent: 0,
    eventsFailed: 0,
    bufferSize: 0,
    lastFlush: null,
    errors: [],
)), 'smoke: status report accepted');
$t->same(1, count(stateFor($stateFile, '/api/v1/status')), 'smoke: status endpoint used');

// 200 partial failure requeues, then the retry is accepted.
flushState($stateFile);
setScript($controlFile, ['events' => [
    ['status' => 200, 'body' => ['success' => false, 'errors' => ['item 2 rejected']]],
    200,
]], $secret, true);
$agent = new GuardAgent(makeConfig($baseOverrides));
$agent->sendEvent(makeEvent(['event_type' => 'p1']));
$agent->sendEvent(makeEvent(['event_type' => 'p2']));
$agent->flushBuffer();
$t->same(2, $agent->eventsFailed, 'smoke: partial 200 counts failures');
$t->ok($agent->buffer->getBufferSize() > 0, 'smoke: partial 200 requeued the batch');
refl($agent, 'eventsRetryAfter')->setValue($agent, 0.0);
$agent->flushBuffer();
$t->same(2, $agent->eventsSent, 'smoke: retry after the partial failure delivered the batch');
$t->same(0, $agent->buffer->getBufferSize(), 'smoke: buffer drained after the retry');
$t->same([200, 200], statuses(stateFor($stateFile, '/api/v1/events')), 'smoke: exactly two events requests observed');

// 413 split-or-drop: the mock enforces the real 262144-byte decompressed cap.
flushState($stateFile);
$agent = new GuardAgent(makeConfig($baseOverrides));
$blob = str_repeat('y', 120 * 1024);
$agent->sendEvent(makeEvent(['event_type' => 'big1', 'metadata' => ['blob' => $blob]]));
$agent->sendEvent(makeEvent(['event_type' => 'big2', 'metadata' => ['blob' => $blob]]));
$agent->sendEvent(makeEvent(['event_type' => 'big3', 'metadata' => ['blob' => $blob]]));
$agent->flushBuffer();
$t->same(3, $agent->eventsSent, 'smoke: 413 split re-sent the halves successfully');
$t->same([413, 200, 200], statuses(stateFor($stateFile, '/api/v1/events')), 'smoke: 413 then two accepted halves');
$t->same(0, $agent->buffer->getBufferSize(), 'smoke: split batch fully drained');

// 413 on a singleton drops the batch durably.
flushState($stateFile);
$agent = new GuardAgent(makeConfig($baseOverrides));
$agent->sendEvent(makeEvent(['event_type' => 'huge', 'metadata' => ['blob' => str_repeat('z', 300 * 1024)]]));
$agent->flushBuffer();
$t->same(1, $agent->eventsSent, 'smoke: singleton 413 drop confirmed, not requeued');
$t->same([413], statuses(stateFor($stateFile, '/api/v1/events')), 'smoke: singleton 413 observed once');
$t->same(0, $agent->buffer->getBufferSize(), 'smoke: singleton 413 not requeued');

// 429 honors Retry-After before retrying.
flushState($stateFile);
setScript($controlFile, ['events' => [['status' => 429, 'retryAfter' => 1], 200]], $secret, true);
$agent = new GuardAgent(makeConfig($baseOverrides));
$agent->sendEvent(makeEvent());
$started = microtime(true);
$agent->flushBuffer();
$elapsed = microtime(true) - $started;
$t->ok($elapsed >= 0.9, 'smoke: Retry-After of 1s honored before the retry');
$t->same(1, $agent->eventsSent, 'smoke: retry after 429 accepted');
$t->same([429, 200], statuses(stateFor($stateFile, '/api/v1/events')), 'smoke: 429 then 200');

// 400 permanent rejection: dropped, not retried, breaker untouched.
flushState($stateFile);
setScript($controlFile, ['events' => [400]], $secret, true);
$agent = new GuardAgent(makeConfig($baseOverrides));
$agent->sendEvent(makeEvent());
$agent->flushBuffer();
$t->same(0, $agent->buffer->getBufferSize(), 'smoke: permanently rejected batch dropped');
$t->same([400], statuses(stateFor($stateFile, '/api/v1/events')), 'smoke: 400 observed exactly once');
$circuitState = $agent->transport instanceof HttpTransport ? $agent->transport->circuitBreaker->state : 'CLOSED';
$t->same('CLOSED', $circuitState, 'smoke: permanent rejection exempt from the circuit breaker');

// 401 retries with backoff, then succeeds.
flushState($stateFile);
setScript($controlFile, ['events' => [401, 200]], $secret, true);
$agent = new GuardAgent(makeConfig($baseOverrides));
$agent->sendEvent(makeEvent());
$agent->flushBuffer();
$t->same([401, 200], statuses(stateFor($stateFile, '/api/v1/events')), 'smoke: auth failure retried like a transient error');
$t->same(1, $agent->eventsSent, 'smoke: retry after 401 accepted');

// Endpoint down: flushBuffer never throws and the batch is retained.
$downConfig = makeConfig(array_merge($baseOverrides, [
    'endpoint' => 'http://127.0.0.1:9',
    'retryAttempts' => 0,
    'backoffFactor' => 0.01,
]));
$agent = new GuardAgent($downConfig);
$agent->sendEvent(makeEvent());
$agent->sendMetric(makeMetric());
$threw = false;
try {
    $agent->flushBuffer();
} catch (Throwable) {
    $threw = true;
}
$t->ok(!$threw, 'smoke: flush against a dead endpoint never throws');
$t->same(2, $agent->buffer->getBufferSize(), 'smoke: dead endpoint retains the batch');
$t->same(0, $agent->getStats()['loopFailures']['flush'], 'smoke: contained transport failure is not a loop failure');
$t->ok(!$agent->healthCheck(), 'smoke: agent not running, health check false');

// The circuit breaker opens after 5 consecutive transport failures and then
// fails fast without touching the network.
for ($i = 0; $i < 5; $i++) {
    $agent->buffer->clearBuffer();
    refl($agent, 'eventsRetryAfter')->setValue($agent, 0.0);
    refl($agent, 'metricsRetryAfter')->setValue($agent, 0.0);
    $agent->sendEvent(makeEvent());
    $agent->flushBuffer();
}
$downStats = $agent->transport instanceof HttpTransport ? $agent->transport->getStats() : [];
$t->same('OPEN', $downStats['circuitBreakerState'] ?? null, 'smoke: breaker opens after 5 consecutive failures');
$sentBefore = $downStats['requestsSent'] ?? -1;
$agent->buffer->clearBuffer();
refl($agent, 'eventsRetryAfter')->setValue($agent, 0.0);
$agent->sendEvent(makeEvent());
$agent->flushBuffer();
$downStats = $agent->transport instanceof HttpTransport ? $agent->transport->getStats() : [];
$t->same($sentBefore, $downStats['requestsSent'] ?? -2, 'smoke: open breaker rejects without a request');


// ------------------------------------------------------------------
// AES-256-GCM encrypted ingest (H1 parity with the Python agent)
// ------------------------------------------------------------------

$t->section('encryption: PayloadEncryptor');

$vectors = json_decode((string) file_get_contents(__DIR__ . '/../tests/fixtures/encryption_vectors.json'), true);
$t->ok(is_array($vectors) && count($vectors) === 4, 'encryption: python vector fixtures load');

foreach ($vectors as $index => $vector) {
    $encryptor = new PayloadEncryptor($vector['key_b64']);
    $decrypted = $encryptor->decrypt($vector['ciphertext_b64'], $vector['aad'] ?? null);
    $t->same(
        json_decode($vector['plaintext_json'], true),
        $decrypted,
        "encryption: decrypts python-generated vector #{$index}"
    );
}

$t->throws(
    EncryptionException::class,
    static fn () => new PayloadEncryptor(''),
    'encryption: empty key rejected'
);
$t->throws(
    EncryptionException::class,
    static fn () => new PayloadEncryptor('AAAA'),
    'encryption: wrong key size rejected'
);
$t->same(null, PayloadEncryptor::create(null), 'encryption: factory returns null without a key');
$t->ok(PayloadEncryptor::create($vectors[0]['key_b64']) instanceof PayloadEncryptor, 'encryption: factory returns encryptor with a key');

$encryptor = new PayloadEncryptor($vectors[0]['key_b64']);
$t->throws(
    EncryptionException::class,
    static fn () => $encryptor->decrypt($vectors[0]['tampered_ciphertext_b64']),
    'encryption: tampered ciphertext rejected (GCM auth)'
);
$t->throws(
    EncryptionException::class,
    static fn () => $encryptor->decrypt($vectors[3]['ciphertext_b64'], 'wrong-aad'),
    'encryption: AAD mismatch rejected'
);

$roundTrip = [
    'events' => [['event_type' => 'rate_limit', 'ip_address' => '1.2.3.4']],
    'metrics' => [['metric_type' => 'request_count', 'value' => 100]],
    'zeta' => 1,
    'unicode' => "h\u{e9}llo w\u{f6}rld \u{4f60}\u{597d}",
];
$ciphertext = $encryptor->encrypt($roundTrip);
// Decryption returns sorted-key order, so compare canonical encodings.
$t->same(CanonicalJson::encode($roundTrip), CanonicalJson::encode($encryptor->decrypt($ciphertext)), 'encryption: encrypt -> decrypt round trip');
$t->same(0, strlen($ciphertext) % 4, 'encryption: output is padded urlsafe base64');
$t->ok((bool) preg_match('#^[A-Za-z0-9_-]+=*$#', $ciphertext), 'encryption: output uses the urlsafe alphabet');
$t->ok($encryptor->verifyKey(), 'encryption: verifyKey passes for a valid key');

$t->ok(
    CanonicalJson::encode(json_decode($vectors[2]['plaintext_json'], true)) === $vectors[2]['plaintext_json'],
    'encryption: canonical JSON byte-identical to python json.dumps (unicode vector)'
);
$t->ok(
    CanonicalJson::encode(json_decode($vectors[1]['plaintext_json'], true)) === $vectors[1]['plaintext_json'],
    'encryption: canonical JSON byte-identical (batch vector)'
);

$t->throws(
    EncryptionConfigException::class,
    static function (): void {
        $transport = new HttpTransport(makeConfig([
            'endpoint' => 'https://ingest.example.test',
            'projectEncryptionKey' => 'not-a-valid-key',
        ]));
        $transport->initialize();
    },
    'encryption: invalid key fails startup without plaintext fallback'
);

$t->section('encryption: encrypted ingest against the mock server');

$encControlFile = (string) tempnam(sys_get_temp_dir(), 'gaph-control');
$encStateFile = (string) tempnam(sys_get_temp_dir(), 'gaph-state');
file_put_contents($encControlFile, json_encode(['script' => new stdClass()]));
file_put_contents($encStateFile, '');
$encEnv = getenv();
$encEnv['MOCK_CONTROL_FILE'] = $encControlFile;
$encEnv['MOCK_STATE_FILE'] = $encStateFile;
$encPort = 18000 + random_int(0, 2000);
$encProc = proc_open(
    [PHP_BINARY, '-S', "127.0.0.1:{$encPort}", __DIR__ . '/../tests/mock_server.php'],
    [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
    $pipes,
    dirname(__DIR__),
    $encEnv
);
$encReady = false;
for ($i = 0; $i < 100; $i++) {
    $conn = @fsockopen('127.0.0.1', $encPort, $e, $es, 0.2);
    if ($conn !== false) {
        fclose($conn);
        $encReady = true;
        break;
    }
    usleep(100_000);
}
$t->ok($encReady, 'encryption: mock server ready');

$encConfig = makeConfig([
    'endpoint' => "http://127.0.0.1:{$encPort}",
    'retryAttempts' => 0,
    'projectEncryptionKey' => $vectors[0]['key_b64'],
]);
$encTransport = new HttpTransport($encConfig);
$encTransport->sendEvents([makeEvent()]);
$encRecords = stateFor($encStateFile, '/api/v1/events/encrypted');
$t->same(1, count($encRecords), 'encryption: events batch routed to /api/v1/events/encrypted');
$t->same(0, count(stateFor($encStateFile, '/api/v1/events')), 'encryption: plaintext events endpoint untouched');
if (isset($encRecords[0])) {
    $envelope = $encRecords[0]['body_json'] ?? [];
    $t->same(
        ['encrypted_payload', 'batch_id', 'agent_version', 'guard_version', 'guard_core_version'],
        array_keys($envelope),
        'encryption: envelope carries the python fields'
    );
    $inner = (new PayloadEncryptor($vectors[0]['key_b64']))->decrypt((string) $envelope['encrypted_payload']);
    $t->same(['events', 'metrics'], array_keys($inner), 'encryption: envelope decrypts to events+metrics');
    $t->same('penetration_attempt', $inner['events'][0]['event_type'] ?? null, 'encryption: decrypted event survives the round trip');
}

flushState($encStateFile);
$encTransport->sendMetrics([makeMetric()]);
$t->same(1, count(stateFor($encStateFile, '/api/v1/events/encrypted')), 'encryption: metrics batch routed to the encrypted endpoint');

flushState($encStateFile);
$encTransport->sendStatus(new AgentStatus(
    new \DateTimeImmutable(),
    'healthy',
    1.0,
    0,
    0,
    0,
    null,
    []
));
$t->same(1, count(stateFor($encStateFile, '/api/v1/status')), 'encryption: status report stays plaintext');
$t->same(0, count(stateFor($encStateFile, '/api/v1/events/encrypted')), 'encryption: status not encrypted');

flushState($encStateFile);
$plainConfig = makeConfig([
    'endpoint' => "http://127.0.0.1:{$encPort}",
    'retryAttempts' => 0,
]);
$plainTransport = new HttpTransport($plainConfig);
$plainTransport->sendEvents([makeEvent()]);
$t->same(1, count(stateFor($encStateFile, '/api/v1/events')), 'encryption: no key configured keeps plaintext events');
$t->same(0, count(stateFor($encStateFile, '/api/v1/events/encrypted')), 'encryption: no key configured skips encrypted endpoint');

proc_terminate($encProc);
proc_close($encProc);
@unlink($encControlFile);
@unlink($encStateFile);

// =====================================================================
// Dynamic rules: transport GET, TTL cache, host-driven loop, stats
// =====================================================================
$t->section('dynamic rules (transport + agent)');

[$rulesProc, $rulesPort, $rulesControlFile, $rulesStateFile] = startMockServer();
$rulesOverrides = [
    'endpoint' => "http://127.0.0.1:{$rulesPort}",
    'retryAttempts' => 2,
    'backoffFactor' => 0.01,
    'timeout' => 10,
];
$rulesPayload = [
    'rule_id' => 'rule-e2e',
    'ttl' => 300,
    'ip_blacklist' => ['203.0.113.100'],
    'endpoint_rate_limits' => ['/api/login' => [10, 60]],
    'blocked_cloud_providers' => ['AWS'],
];
$serveRules = static function () use ($rulesControlFile, $rulesPayload): void {
    setScript($rulesControlFile, ['rules' => [['status' => 200, 'body' => $rulesPayload]]]);
};

// Happy path: GET /api/v1/rules, normalized into DynamicRules.
flushState($rulesStateFile);
$serveRules();
$rulesTransport = new HttpTransport(makeConfig($rulesOverrides));
$fetched = $rulesTransport->fetchDynamicRules();
$t->ok($fetched instanceof DynamicRules, 'transport: fetchDynamicRules returns DynamicRules');
$t->same('rule-e2e', $fetched?->ruleId, 'transport: payload normalized');
$t->same(['203.0.113.100'], $fetched?->ipBlacklist, 'transport: rules fields survive the round trip');
$rulesRecords = stateFor($rulesStateFile, '/api/v1/rules');
$t->same(1, count($rulesRecords), 'transport: single GET request');
$t->same('GET', $rulesRecords[0]['method'] ?? null, 'transport: rules fetched with GET');
$t->same(1, $rulesTransport->requestsSent, 'transport: successful dict 200 counts requestsSent');

// Transient failure retried, then success.
flushState($rulesStateFile);
setScript($rulesControlFile, ['rules' => [500, ['status' => 200, 'body' => $rulesPayload]]]);
$retryTransport = new HttpTransport(makeConfig($rulesOverrides));
$fetched = $retryTransport->fetchDynamicRules();
$t->same('rule-e2e', $fetched?->ruleId, 'transport: retry succeeds after a transient 500');
$t->same([500, 200], statuses(stateFor($rulesStateFile, '/api/v1/rules')), 'transport: exactly two GET attempts observed');

// All attempts fail: null result, failed-request bookkeeping.
flushState($rulesStateFile);
setScript($rulesControlFile, ['rules' => [500, 500, 500]]);
$failTransport = new HttpTransport(makeConfig(['retryAttempts' => 2] + $rulesOverrides));
$t->same(null, $failTransport->fetchDynamicRules(), 'transport: null when all attempts fail');
$t->same([500, 500, 500], statuses(stateFor($rulesStateFile, '/api/v1/rules')), 'transport: initial attempt plus two retries');
$t->same(1, $failTransport->requestsFailed, 'transport: giveup records a failed request (exhaustion path)');

// 429 honors Retry-After (0s here so the test does not sleep).
flushState($rulesStateFile);
setScript($rulesControlFile, ['rules' => [['status' => 429, 'retryAfter' => 0], ['status' => 200, 'body' => $rulesPayload]]]);
$limitedTransport = new HttpTransport(makeConfig($rulesOverrides));
$fetched = $limitedTransport->fetchDynamicRules();
$t->same('rule-e2e', $fetched?->ruleId, 'transport: 429 Retry-After is honored and retried');

// 200 with a non-dict body is not a rules document: failed attempts, null.
flushState($rulesStateFile);
setScript($rulesControlFile, ['rules' => [['status' => 200, 'body' => ['a-list-not-a-dict']]]]);
$listTransport = new HttpTransport(makeConfig(['retryAttempts' => 0] + $rulesOverrides));
$t->same(null, $listTransport->fetchDynamicRules(), 'transport: non-dict 200 yields null');

// Malformed rules payload surfaces null (the transport catches and logs).
flushState($rulesStateFile);
setScript($rulesControlFile, ['rules' => [['status' => 200, 'body' => ['ip_blacklist' => 5]]]]);
$badTransport = new HttpTransport(makeConfig(['retryAttempts' => 0] + $rulesOverrides));
$t->same(null, $badTransport->fetchDynamicRules(), 'transport: malformed rules payload yields null');

// Agent TTL cache: within the ttl the cached copy is served.
$cacheTransport = new RecordingTransport();
$cacheTransport->rulesOutcomes = [DynamicRules::normalize(['rule_id' => 'cached-1', 'ttl' => 300])];
$cacheAgent = makeAgent([], $cacheTransport);
$cached = $cacheAgent->getDynamicRules();
$t->same('cached-1', $cached?->ruleId, 'agent: first call fetches and returns the rules');
$t->same(1, $cacheTransport->rulesRequests, 'agent: first call hit the transport');
$cached = $cacheAgent->getDynamicRules();
$t->same('cached-1', $cached?->ruleId, 'agent: cached copy served within the ttl');
$t->same(1, $cacheTransport->rulesRequests, 'agent: no transport hit within the ttl');
$stats = $cacheAgent->getStats();
$t->same(1, $stats['rulesFetched'], 'stats: rulesFetched counted on refresh');
$t->same(true, $stats['cachedRules'], 'stats: cachedRules true while a copy is held');
$t->ok($stats['rulesLastUpdate'] > 0, 'stats: rulesLastUpdate stamped');

// After the ttl expires the next call refetches.
refl($cacheAgent, 'rulesLastUpdate')->setValue($cacheAgent, microtime(true) - 301);
$cacheTransport->rulesOutcomes = [DynamicRules::normalize(['rule_id' => 'cached-2', 'ttl' => 300])];
$refreshed = $cacheAgent->getDynamicRules();
$t->same('cached-2', $refreshed?->ruleId, 'agent: refetch after the ttl expired');
$t->same(2, $cacheTransport->rulesRequests, 'agent: refetch hit the transport');
$t->same(2, $cacheAgent->getStats()['rulesFetched'], 'stats: rulesFetched counted per refresh');

// A failed refresh returns null but keeps the last good rules cached.
refl($cacheAgent, 'rulesLastUpdate')->setValue($cacheAgent, microtime(true) - 301);
$cacheTransport->rulesOutcomes = [null];
$t->same(null, $cacheAgent->getDynamicRules(), 'agent: failed refresh surfaces null');
$cached = refl($cacheAgent, 'cachedRules')->getValue($cacheAgent);
$t->same('cached-2', $cached?->ruleId, 'agent: last good rules stay cached through the failure');
$stats = $cacheAgent->getStats();
$t->same(2, $stats['rulesFetched'], 'stats: rulesFetched not bumped by a failed refresh');

// A thrown transport error returns the cached rules (Python catch branch).
refl($cacheAgent, 'rulesLastUpdate')->setValue($cacheAgent, microtime(true) - 301);
$cacheTransport->rulesOutcomes = [new RuntimeException('boom')];
$cached = $cacheAgent->getDynamicRules();
$t->same('cached-2', $cached?->ruleId, 'agent: thrown fetch error falls back to the cached rules');

// No cache and a failed fetch: null, no throw.
$freshTransport = new RecordingTransport();
$freshTransport->rulesOutcomes = [null];
$freshAgent = makeAgent([], $freshTransport);
$t->same(null, $freshAgent->getDynamicRules(), 'agent: null when there is no cache and the fetch fails');

// Host-driven rules loop via tick(): polls on the interval, counts
// consecutive failures through the stats surface.
$loopTransport = new RecordingTransport();
$loopTransport->rulesOutcomes = [DynamicRules::normalize(['rule_id' => 'loop-1', 'ttl' => 0])];
$loopAgent = makeAgent(['dynamicRuleInterval' => 60], $loopTransport);
$loopAgent->start();
$loopAgent->tick();
$t->same(0, $loopTransport->rulesRequests, 'loop: nothing fetched before the interval elapses');
refl($loopAgent, 'nextRulesRefreshAt')->setValue($loopAgent, microtime(true) - 1);
$loopAgent->tick();
$t->same(1, $loopTransport->rulesRequests, 'loop: rules fetched once the interval elapsed');
$t->same(0, $loopAgent->getStats()['loopFailures']['rules'], 'loop: success resets the failure counter');

// Failed polls increment the consecutive counter like the other loops.
for ($i = 0; $i < 3; $i++) {
    refl($loopAgent, 'nextRulesRefreshAt')->setValue($loopAgent, microtime(true) - 1);
    $loopAgent->tick();
}
$stats = $loopAgent->getStats();
$t->same(3, $stats['loopFailures']['rules'], 'loop: consecutive failures counted in loopFailures.rules');
$t->same(1, $stats['rulesFetched'], 'loop: no successful refresh during the failure streak');
$loopAgent->stop();

proc_terminate($rulesProc);
proc_close($rulesProc);
@unlink($rulesControlFile);
@unlink($rulesStateFile);

proc_terminate($proc);
proc_close($proc);

@unlink($controlFile);
@unlink($stateFile);

$t->finish();
