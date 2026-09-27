# guard-agent-php

PHP telemetry agent for the [guard-core](https://github.com/rennf93/guard-core) ecosystem. It buffers security events, performance metrics, and agent status in memory (optionally persisted to Redis) and ships them to the Guard Core App ingestion API with at-least-once delivery semantics: nothing acknowledged is lost, nothing unacknowledged is forgotten.

Docs: <https://rennf93.github.io/guard-agent-php/>

This completes the agent-per-language lineup: [guard-agent](https://github.com/rennf93/guard-agent) (Python), guardagent (TypeScript), guard-agent-rs (Rust), guard-agent-go (Go), and now guard-agent-php (PHP). Like the other ports it is a library, not a process: it never throws into the host request path, and every telemetry failure is a log line plus a counter bump.

## Install

```bash
composer require rennf93/guard-agent-php
```

Requires PHP `^8.2`, `ext-json`, and `ext-curl`. Crash-recovery persistence to Redis works out of the box through a built-in stream client (no extra extension needed); if you already run `ext-redis` or `predis/predis`, adapters for both are provided.

## Usage

The agent is host-driven: PHP has no background threads, so flush timers run when you call the agent, not behind your back.

```php
use RenzoFranceschini\GuardAgent\Config\AgentConfigResolver;
use RenzoFranceschini\GuardAgent\GuardAgent;

$agent = new GuardAgent(AgentConfigResolver::resolve([
    'apiKey' => $_ENV['GUARD_API_KEY'],
    'endpoint' => 'https://api.guard-core.com',
    'projectId' => 'my-project',
    'payloadSigningSecret' => $_ENV['GUARD_SIGNING_SECRET'] ?? null,
]));

$agent->start();

// From anywhere in your request path: never throws, never blocks (default drop policy).
$agent->sendEvent([
    'event_type' => 'penetration_attempt',
    'ip_address' => $clientIp,
    'endpoint' => '/login',
    'method' => 'POST',
    'metadata' => ['rule' => 'sqli-union-select'],
]);

$agent->sendMetric([
    'metric_type' => 'response_time',
    'value' => 0.023,
    'endpoint' => '/login',
]);

// Ship telemetry at the end of the request (kernel.terminate in Symfony,
// register_shutdown_function in plain PHP, terminate in Laravel).
register_shutdown_function(static function () use ($agent): void {
    $agent->flushBuffer();
    $agent->stop();
});
```

### Long-running workers (CLI daemons, RoadRunner, Swoole-style loops)

Do not reach for `pcntl_alarm` or extension timers: drive the agent from your own loop with `tick()`, which flushes when the high-watermark or the flush interval is reached and pushes status reports on the status interval.

```php
$agent->start();
while (true) {
    $agent->tick();   // cheap: no network I/O unless a trigger fires
    doWork();
    usleep(1_000_000);
}
$agent->stop();       // final flush, releases Redis
```

## Reliability semantics

- **At-least-once handshake**: `flushBuffer()` drains each kind, sends it, and only on success confirms the batch (deleting any Redis records). Transient failures requeue the batch at the front of the buffer in its original order; under pressure the tail (newest items) is evicted and its records confirmed.
- **Per-kind backoff**: after a failed flush the kind is gated for `min(flushInterval * 2^(streak - 1), 300)` seconds before the next attempt.
- **Circuit breaker**: 5 consecutive transport failures in 60 seconds open the circuit; `400/404/413/422` rejections are exempt (they are batch-level, not health signals). `429` counts; `Retry-After` is honored up to a 300s cap.
- **Permanent rejection**: `400/404/422` drop the batch (logged and counted, never retried, never thrown). A `413` splits the batch in half and retries each half; a singleton that still exceeds the cap is dropped.
- **Partial success is failure**: a `200` with `success: false` or a non-empty `errors[]` requeues the whole batch.
- **Degraded state**: the status report reads `degraded` when the circuit breaker is open, the buffer is at or above 90 percent occupancy, or the lifetime failure rate exceeds 10 percent.
- **Failure isolation**: no public method ever throws into the host path (the one deliberate, opt-in exception is the `block` overflow policy). See `AGENTS.md` for the full contract.

### The uncompressed-signature note

When `payloadSigningSecret` is set, the transport sends `X-Payload-Signature: v1=<hex>` where `<hex>` is `hash_hmac('sha256', <uncompressed JSON body>, <secret>)`. The Guard Core App ingestion API verifies the signature **after** decompressing the body (its `GzipRequestMiddleware` inflates `Content-Encoding: gzip` request bodies before the telemetry router runs), so the HMAC must always cover the uncompressed JSON bytes. This differs from the Python/TypeScript/Go agents, which sign the post-gzip bytes and silently fail verification whenever compression kicks in; the PHP agent signs what the server actually verifies.

## Encryption

When `projectEncryptionKey` is set (a urlsafe-base64-encoded 256-bit key issued by the core backend), event and metric batches are encrypted with AES-256-GCM and POSTed to `/api/v1/events/encrypted` as `{encrypted_payload, batch_id, agent_version, guard_version, guard_core_version}`; the wire format is byte-compatible with the Python agent (canonical JSON plaintext with `sort_keys` and `ensure_ascii`, 12-byte nonce prefix, 16-byte auth tag, padded urlsafe base64). An invalid key raises `EncryptionConfigException` at startup; the agent never falls back to plaintext. Signing and compression apply to the envelope body exactly as they do to plaintext batches.

## Persistence

With `redis` configured, every accepted item is written to Redis under a globally-unique key (`{prefix}:agent_events:event_<nanos>_<8hex>`, TTL 3600s) on enqueue; on `start()` the buffer reloads whatever a previous process left behind. Every Redis failure is fail-open: logged, counted, and after 3 consecutive write failures paused for a 30s cooldown, so an unhealthy Redis cannot tax the request path. The TTL is the backstop: at worst a lost confirmation duplicates a reload, it never loses data.

## Documentation

- `AGENTS.md` (mirrored byte-identically in `CLAUDE.md`): architecture, configuration reference, reliability semantics, testing.
- `src/.agents/skills/guard-agent-php/SKILL.md`: agent-oriented quick reference.

## Related projects

- [guard-core](https://github.com/rennf93/guard-core): the framework-agnostic engine library.
- [guard-agent](https://github.com/rennf93/guard-agent) (Python), guardagent (TypeScript), guard-agent-rs (Rust), guard-agent-go (Go): sibling agents.
- [guard-core-app](https://github.com/rennf93/guard-core-app): the SaaS platform this agent reports to.

## License

MIT. See [LICENSE](LICENSE).
