# Usage

## Lifecycle

```php
$agent = new GuardAgent($configOrArray); // validates config, restores install id
$agent->start();      // marks running, loads crash-recovery state (may throw)
$agent->sendEvent($event);   // ingest: never throws
$agent->sendMetric($metric); // ingest: never throws
$agent->tick();       // host-driven loop body: flush triggers + status push + rules refresh
$agent->flushBuffer();// force a flush cycle (never throws)
$agent->getStatus();  // AgentStatus snapshot
$agent->healthCheck();// true when the ingestion API is reachable and healthy
$agent->getDynamicRules(); // SaaS dynamic rules (TTL-cached, null on outage)
$agent->getStats();   // buffer occupancy, drops, retries, rules counters
$agent->stop();       // final flush, stop loops, release Redis (never throws)
```

## Dynamic rules

`getDynamicRules()` fetches `GET /api/v1/rules` (retry, circuit breaker, and
`Retry-After` semantics shared with the batch sends) and returns a
`DynamicRules` value object mirroring the Python agent's pydantic model
(snake_case wire keys). The copy is cached in memory and served while it is
younger than its own `ttl`; a failed fetch returns `null` and keeps the last
good rules cached, and `tick()` refreshes the cache every
`dynamicRuleInterval` seconds (default 300, minimum 60). Counters live in
`getStats()`: `rulesFetched`, `cachedRules`, `rulesLastUpdate`, and
`loopFailures.rules`.

PHP has no background threads, so the flush, status, and rules loops of the
Python/TypeScript/Go agents are host-driven. Long-running workers call
`tick()` from their own loop; request-scoped apps call `flushBuffer()` from
`kernel.terminate` or `register_shutdown_function`. Only `start()` may
throw; everything else is a log line plus a counter.

## Events and metrics

`SecurityEvent` and `SecurityMetric` mirror the ingestion API's
`BatchTelemetryRequest` payload. Input accepts camelCase or snake_case keys;
timestamps accept `DateTimeInterface`, epoch seconds, or parseable strings
and are normalized to ISO-8601 UTC with milliseconds at the wire boundary.
An `IdempotencyKey` (UUID) is generated when omitted and deduplicates
retries server-side. Field-by-field descriptions live on the model classes
in `src/Model/`.

## Buffering and overflow

Each kind (events, metrics) has its own bounded buffer (`bufferSize`,
default 100). When a buffer fills, `bufferOverflowPolicy` decides:

| Policy | Behavior |
|---|---|
| `drop` (default) | evicts the oldest item of the same kind, confirms its Redis record, counts a drop |
| `block` | waits for a flush to free a slot; durability over the new writer (the one opt-in blocking behavior) |
| `raise` | the agent swallows the `BufferFullException` and counts a drop |

A combined occupancy at or above `highWatermarkRatio` (default 0.8) triggers
an early flush.

## Delivery semantics

- Flushes run on `flushInterval` (default 30s), on watermark, and on demand
- A failed batch retries up to `retryAttempts` with exponential backoff
  (`backoffFactor`), honoring `Retry-After` on 429 (default 60s, capped at
  300s)
- A 413 splits the batch or drops its oldest item rather than retrying a
  permanently oversized payload
- 400, 404, and 422 are permanent: the batch is dropped, not retried
- A 200 with `success: false` or a non-empty `errors[]` requeues the whole
  batch in original order (at-least-once: duplicates are possible, losses
  are not)
- The circuit breaker opens after 5 consecutive non-permanent failures and
  half-opens to probe recovery (429 and network errors count; 400/404/413/422
  are exempt)

## Signing

When `payloadSigningSecret` is set, every request carries
`X-Payload-Signature: v1=<hex hmac-sha256>`. The signature covers the
UNCOMPRESSED JSON body; the server verifies after decompression. Gzip
(`compressionEnabled`) only affects the wire bytes.

## Redis persistence

With `redis` configured, every buffered item is persisted under
`{keyPrefix}:{namespace}:{key}` (TTL 3600s) before the send attempt and
confirmed (deleted) on success, so a crash between buffer and network loses
nothing; `start()` reloads what a previous process left behind. Every Redis
failure is fail-open: logged, counted, and after 3 consecutive write
failures writes pause for 30s. See [Configuration](configuration.md).
