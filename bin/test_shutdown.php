<?php

/**
 * Process-termination proof for guard-agent-php. Run with: php bin/test_shutdown.php
 *
 * The parent spawns a child php per termination mode. The child starts an
 * agent with Redis persistence, buffers one event (never flushing, never
 * ticking) and ends in the given way. The parent then checks whether the
 * event reached a real Redis (REDIS_HOST, default 127.0.0.1, port 6379).
 * Every key lives under a unique prefix that only this run deletes.
 *
 * Modes where PHP can still run code (end, exit, exception, fatal, oom,
 * timeout) must persist. SIGKILL cannot run any code and must lose the event
 * (documented, unfixable). SIGTERM without a handler also skips shutdown
 * functions in PHP, so it loses the event as well (also documented). With
 * ext-pcntl, a host handler that calls exit() on SIGTERM makes it durable; the
 * agent deliberately installs no signal handler of its own (it would override
 * the host's).
 */

declare(strict_types=1);

use RenzoFranceschini\GuardAgent\GuardAgent;
use RenzoFranceschini\GuardAgent\Persistence\StreamRedisClient;

require __DIR__ . '/../vendor/autoload.php';

if (($argv[1] ?? '') === '--child') {
    $mode = $argv[2];
    $agent = new GuardAgent([
        'apiKey' => 'test-api-key-123',
        'endpoint' => 'http://127.0.0.1:9',
        'installId' => 'install-shutdown',
        'redis' => ['url' => $argv[3], 'keyPrefix' => $argv[4]],
    ]);
    $agent->start();
    $agent->sendEvent(['event_type' => 'shutdown-proof', 'ip_address' => '203.0.113.9', 'timestamp' => time()]);
    if ($agent->buffer->getBufferSize() !== 1) {
        fwrite(STDERR, "child setup failed: event not buffered\n");
        exit(8);
    }

    switch ($mode) {
        case 'end':
            return;
        case 'exit':
            exit(3);
        case 'exception':
            throw new RuntimeException('boom');
        case 'fatal':
            // A compile-time E_ERROR (not an exception): no catch can intercept it.
            eval('class ShutdownProofAbstract { abstract function f(); }');
            return;
        case 'oom':
            ini_set('memory_limit', '32M');
            $hog = [];
            for (;;) {
                $hog[] = str_repeat('x', 1024 * 1024);
            }
        case 'timeout':
            ini_set('max_execution_time', '1');
            for (;;) {
                hash('sha256', 'spin');
            }
        case 'sigterm-handler':
            // What a host that wants SIGTERM durability installs itself.
            pcntl_async_signals(true);
            pcntl_signal(15, static function (): never {
                exit(0);
            });
            // no break
        case 'sigkill':
        case 'sigterm':
            fwrite(STDOUT, "ready\n");
            fflush(STDOUT);
            sleep(30);
            return;
    }
    exit(9);
}

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
}

$host = getenv('REDIS_HOST');
if ($host === false || $host === '') {
    $host = '127.0.0.1';
}
if ($host === '0') {
    echo "skip - REDIS_HOST=0, shutdown persistence proof skipped\n";
    exit(0);
}
$url = 'redis://' . $host . ':6379/0';
$client = new StreamRedisClient($url, null, null, 2.0);
$client->ping();

$prefix = 'guard:agent:shutdowntest:' . bin2hex(random_bytes(4));
$pattern = $prefix . ':agent_events:*';
$t = new T();

/** @return array{0: string, 1: int, 2: string} exit code, keys left in redis, stderr */
function runChild(StreamRedisClient $client, string $url, string $prefix, string $mode, ?int $signal = null): array
{
    $cmd = [PHP_BINARY, '-d', 'display_errors=stderr', __FILE__, '--child', $mode, $url, $prefix];
    $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if ($signal !== null) {
        // The agent logs to stdout too: wait for the child's own marker.
        while (($line = fgets($pipes[1])) !== false && trim($line) !== 'ready') {
        }
        $signaled = proc_terminate($proc, $signal);
        if (!$signaled) {
            throw new RuntimeException('signal not delivered');
        }
    }
    $stderr = (string) stream_get_contents($pipes[2]);
    do {
        $status = proc_get_status($proc);
        usleep(10000);
    } while ($status['running']);
    proc_close($proc);
    $code = $status['signaled'] ? 'signal ' . $status['termsig'] : 'exit ' . $status['exitcode'];

    return [$code, count($client->keys($prefix . ':agent_events:*')), $stderr];
}

function clean(StreamRedisClient $client, string $pattern): void
{
    foreach ($client->keys($pattern) as $key) {
        $client->delete($key);
    }
}

try {
    foreach (['end', 'exit', 'exception', 'fatal', 'oom', 'timeout'] as $mode) {
        clean($client, $pattern);
        [$code, $keys, $stderr] = runChild($client, $url, $prefix, $mode);
        $t->ok($keys === 1, "{$mode}: event persisted to redis at shutdown ({$code}, keys {$keys})");
    }

    foreach ([['sigkill', 9], ['sigterm', 15]] as [$mode, $signal]) {
        clean($client, $pattern);
        [$code, $keys] = runChild($client, $url, $prefix, $mode, $signal);
        $t->ok($keys === 0, "{$mode}: no PHP code runs, event is not in redis ({$code}, keys {$keys})");
    }
    if (function_exists('pcntl_signal')) {
        clean($client, $pattern);
        [$code, $keys] = runChild($client, $url, $prefix, 'sigterm-handler', 15);
        $t->ok($keys === 1, "sigterm with a host pcntl handler that calls exit(): shutdown runs, event persisted ({$code}, keys {$keys})");
    }
} finally {
    clean($client, $pattern);
}

echo "\npassed: {$t->passed}\nfailed: {$t->failed}\n";
exit($t->failed === 0 ? 0 : 1);
