# AGENTS.md
Guidance for AI agents (including Claude Code) working in this repository.

## Project Overview

rennf93/guard-agent-php (https://github.com/Guard-Core/guard-agent-php) is the PHP telemetry agent for the guard-core ecosystem. It buffers security events, performance metrics, and agent status in memory (optionally persisted to Redis for crash recovery) and ships them to the Guard Core App ingestion API with at-least-once delivery semantics: nothing acknowledged is lost, nothing unacknowledged is forgotten.

- Composer package `rennf93/guard-agent-php`, type `library`, license MIT. No `version` field in composer.json (the laravel-guard/symfony-guard convention); versions come from git tags and are reported to the server as `agent_version` from `RenzoFranceschini\GuardAgent\Version::VERSION` (`0.1.0` at the time of writing). Shipped tags: none yet.
- This package contains NO security logic. It reports what a host adapter already decided; detection, rate limiting, bans, and verdicts all live in guard-core (and guard-core-php).
- PHP `^8.2`. Requires `ext-json` and `ext-curl` only. Redis persistence works with zero extra dependencies through a built-in RESP2 stream client; `ext-redis` and `predis/predis` adapters are provided and listed under `suggest`.
- Autoload is PSR-4: `RenzoFranceschini\GuardAgent\` maps to `src/`. Every file is `declare(strict_types=1)`. There is no PSR-7/PSR-15 anything: this is a client library, not middleware.
- The semantic source of truth is the Python guard-agent (guard_agent/), with the TypeScript (guardagent src/) and Go (guard-agent-go) ports as two verified mappings. The wire contract is defined by guard-core-app's ingestion API (`backend/guard-core-api/guard_core_api/api/routers/telemetry_router.py`).

## Ecosystem Position

- `guard-core` is the engine library; the framework adapters (fastapi-guard, flaskapi-guard, djapi-guard, tornadoapi-guard) wire it into frameworks; `guard-agent` (Python), guardagent (TS), guard-agent-rs (Rust), and guard-agent-go (Go) are the sibling telemetry agents; `guard-core-app` is the SaaS this agent reports to.
- The ingestion contract, verified against guard-core-api source:
  - `POST {endpoint}/api/v1/events`, `/api/v1/metrics`, `/api/v1/status`.
  - Headers: `X-API-Key` (required), `X-Project-Id` (optional), `X-Agent-Install-Id` (install tracking, telemetry_router.py:194), `User-Agent` (`guard-agent/<version>`), optional `X-Payload-Signature`.
  - Bodies above `compressionThreshold` bytes are gzipped with `Content-Encoding: gzip`. The server's `GzipRequestMiddleware` inflates the body BEFORE the router runs.
  - `X-Payload-Signature: v1=<hex>` where `<hex>` is HMAC-SHA256 over the UNCOMPRESSED body bytes: `_verify_signature_or_warn` (telemetry_router.py:110-126) hashes `request.body()` after the middleware already decompressed it, so the signature must always cover the plain JSON bytes. This differs from the Python/TS/Go agents, which sign the post-gzip bytes and fail verification whenever compression applies.
  - `413` when the decompressed body exceeds 262144 bytes (`services/payload_size_guard.py`); `429` carries `Retry-After`; `200` with `success: false` or non-empty `errors[]` is a partial failure.
- This package does NOT import guard-core-php, any framework, or any composer dependency. Guard adapters that need telemetry embed this agent directly.

## Architecture

All of `src/`, namespace `RenzoFranceschini\GuardAgent`:

- `GuardAgent.php`: the client. `__construct(AgentConfig|array $config, ?TransportInterface $transport = null)` (the second parameter is the test seam). `start()` / `stop()` / `close()` lifecycle (start idempotent and may throw; stop idempotent and never throws); `sendEvent()` / `sendMetric()` ingest path (never throw, normalize + redact + buffer); `flushBuffer()` (never throws); `tick()` and `flushIfNeeded()` (host-driven loop, see Runtime model below); `getDynamicRules()` (TTL-cached rules fetch, never throws); `getStatus()` / `getStats()` / `healthCheck()`. Per-kind failure streaks with backoff gates (`eventsRetryAfter` / `metricsRetryAfter`), `flushConsecutiveFailures` / `statusConsecutiveFailures` / `rulesConsecutiveFailures` loop counters, `lastStatusPushOk`, `rulesFetched` / `cachedRules` / `rulesLastUpdate`.
- `Config/AgentConfig.php`: readonly resolved config (camelCase, mirroring the TS port naming; defaults identical to the Python agent). `Config/AgentConfigResolver.php`: `resolve(array $input)` (accepts camelCase and snake_case keys), `validate()` (returns the error list), `normalizeEndpoint()` (strips trailing slashes and a legacy `/api/v1` suffix with a one-time warning, mirroring guard_agent/models.py:176-205). `Config/BufferOverflowPolicy.php`: `drop` / `block` / `raise` enum. `Config/RedisConfig.php`: url, keyPrefix (`guard:agent`), password, db, commandTimeoutMs (5000).
- `EventBuffer/EventBuffer.php`: per-kind bounded queues with `SplObjectStorage` key maps; overflow policies; `flushEventsWithKeys()` / `flushMetricsWithKeys()` / `requeueEventsInMemory()` / `requeueMetricsInMemory()` (front requeue, tail eviction returns the evicted keys); `confirmEventRedisKeys()` / `confirmMetricRedisKeys()`; persist-on-enqueue with TTL 3600; `initializeRedis()` reloads persisted items at startup; `clearBuffer()`; `atHighWatermark()`.
- `Transport/HttpTransport.php`: cURL implementation of `TransportInterface`. Retry loop (`retryAttempts + 1` tries, local `RateLimiter` 100/60, `CircuitBreaker` 5 failures/60s), response classification, gzip compression, `Signer` HMAC, 413 split-or-drop, permanent-rejection drops, `RetryAfter` parsing (default 60s, honored up to 300s), `BatchId`, response-body summaries. `Transport/TransportInterface.php`: the seam (`sendEvents`/`sendMetrics`/`sendStatus` return bool; true = accepted or intentionally dropped, false = transient, caller requeues; `fetchDynamicRules()` returns `?DynamicRules` and never throws). `getWithRetry()` implements the GET path for `GET /api/v1/rules` with the same retry/circuit-breaker/Retry-After machinery as the POST loop (mirrors `_get_with_retry`, `_transport_send.py:238-289`). `Transport/CircuitBreaker.php`, `Transport/RateLimiter.php`, `Transport/Signer.php`.
- `Persistence/RedisClientInterface.php`: the client seam (ping/get/set/delete/keys/close). `Persistence/StreamRedisClient.php`: dependency-free RESP2 client over `stream_socket_client` (PING, AUTH, SELECT, GET, SET EX, DEL, KEYS; command timeout via `stream_set_timeout`). `Persistence/PredisRedisClient.php` and `Persistence/ExtRedisClient.php`: optional adapters over injected `\Predis\ClientInterface`-shaped and `\Redis` instances. `Persistence/RedisHandler.php`: namespaced facade (`{keyPrefix}:{namespace}:{short}`) with the Go port's fail-open policy: 3 consecutive write failures pause writes for 30s.
- `Model/SecurityEvent.php`, `Model/SecurityMetric.php`, `Model/AgentStatus.php`: readonly wire models with `normalize()` (camelCase or snake_case input, `InvalidEventException` on bad input) and `toWire()` (snake_case, ISO-8601 UTC with milliseconds). `Model/KnownTypes.php`: the advisory event-type list and the enforced metric-type list. `Model/DynamicRules.php`: the SaaS rules surface (mirrors DynamicRules, guard_agent/models.py:250-324, snake_case wire keys with camelCase properties, `normalize()` raising `InvalidRulesException`; `ttl` drives the client cache, `blocked_cloud_providers` deduped like the Python set, `ge=1` enforced only on the `auto_ban_*` fields). `Model/WireFormat.php`: timestamp parsing (DateTimeInterface, epoch SECONDS, or parseable string) and `isoUtc()`.
- `Install/InstallId.php`: file-backed install ID at `~/.guard-agent/install-id` (override parameter, uuid v4, all filesystem failures warn and fall back to an in-memory UUID).
- `Log/AgentLogger.php` interface + `Log/DefaultAgentLogger.php` (streams in CLI SAPI, `error_log` in web SAPI; `GUARD_AGENT_DEBUG` enables debug).
- `Utils/`: `Json` (Python-json.dumps-compatible bytes: unescaped slashes, escaped non-ASCII; `SerializationException`), `Backoff` (`base * 2^attempt` capped), `RetryAfter`, `BatchId`, `Uuid` (v4 without ext-uuid), `HeadersRedactor` (recursive `[REDACTED]` with a JSON-string scan, depth cap 10), `ResponseSummary`, `ErrorHook` (stages `transport_send` / `flush_events` / `flush_metrics`; a throwing hook is caught and logged).
- `Exception/`: `GuardAgentException` base with `ConfigException`, `BufferFullException`, `InvalidEventException`, `SerializationException`, `InvalidRulesException`, `RateLimitedException` (carries `retryAfterSeconds`), `PermanentClientException` (400/404/422; `statusCode` + `detail`), `PayloadTooLargeException` (413, extends PermanentClientException, so both are circuit-breaker exempt), `RedisException`.
- `examples/basic_usage/`: minimal wiring demonstration (engine `onBlock` payload to `SecurityEvent`, agent from env, host-driven `tick()` loop, final flush on shutdown; `basic_usage.php` + `README.md`).
- `mkdocs.yml`: mkdocs-material site definition (docs/ sources).
- `docs/`: documentation site sources: `index.md`, `usage.md`, `configuration.md`.

Runtime model (deliberate PHP deviation, documented in the README): PHP has no background threads, so the flush and status loops of the Python/TS/Go agents are host-driven. `start()` only marks the agent running, loads crash-recovery state, and initializes the transport. `tick()` is the loop body: it flushes when the high-watermark or flush interval triggers, pushes a status report when the status interval elapses, and refreshes the dynamic rules when the dynamic rule interval elapses (mirroring `_rules_loop`; a null refresh counts a consecutive `rules loop` failure like the other loops). Long-running workers call `tick()` from their own loop (pcntl-free, no signal handlers); request-scoped apps call `flushBuffer()` from `kernel.terminate` / `register_shutdown_function`. Under the `block` overflow policy the buffer invokes the agent's flush inline while waiting (the one opt-in exception to failure isolation), because in single-threaded PHP nothing else can free the space.

Neither former "dropped" entry remains: `project_encryption_key` is implemented (see `Encryption\PayloadEncryptor`) and the `/api/v1/rules` dynamic-rules surface is implemented (`Model/DynamicRules.php`, `HttpTransport::fetchDynamicRules()`, the tick-driven rules refresh with `dynamicRuleInterval`).

Key invariants an agent must preserve when editing:

1. The handshake is always drain, then send, then confirm (delete persisted records) or requeue at the FRONT in the original order; under buffer pressure during requeue the TAIL (newest items) is evicted and its records confirmed.
2. The HMAC signature covers the UNCOMPRESSED JSON body even when the wire bytes are gzipped; the server verifies after decompression. Any change here must update the pinned HMAC vector and the mock server together.
3. The host-facing methods (`sendEvent`, `sendMetric`, `flushBuffer`, `tick`, `getStatus`, `getStats`, `healthCheck`, `stop`) never throw into the host path; every failure is a log line plus a counter. Only `start()` may throw.
4. Per-kind state (queues, failure streaks, backoff gates) stays independent: one kind failing must never stall the other.
5. Redis failures are fail-open: log, count, keep going (plus the 30s write cooldown after 3 consecutive write failures).
6. Community workflows (`issue-link`, `stale`, `sync-labels`) stay byte-identical to the Go family's (gin-guard and siblings); `greetings`, `summary`, and `labeler`/`labels` carry repo-specific text (agent subsystems, not adapter middleware) and must not drift in structure.

## Quick Start

This machine has NO `php` and NO `composer` binary. Run everything through Docker (`php:8.2-cli` / `php:8.3-cli` / `php:8.4-cli` for tests, `composer:2` for composer), or let CI execute. The host Redis on 6379 is reachable from containers as `host.docker.internal`.

```
docker run --rm -v "$PWD":/app -w /app composer:2 composer install --no-interaction --no-progress
docker run --rm -v "$PWD":/app -w /app -e REDIS_HOST=0 php:8.3-cli php bin/test_agent.php          # unit-only
docker run --rm -v "$PWD":/app -w /app -e REDIS_HOST=host.docker.internal php:8.3-cli php bin/test_agent.php  # full
docker run --rm -v "$PWD":/app -w /app composer:2 composer validate --strict
```

The CI-verified path (from `.github/workflows/ci.yml`): checkout, `shivammathur/setup-php` from the matrix (8.2/8.3/8.4, `mbstring` extension, coverage none), `composer install --no-interaction --no-progress`, the `php -l` sweep, then `REDIS_HOST=127.0.0.1 php bin/test_agent.php` against a `redis:7-alpine` service on port 6379, plus a `composer audit` job.

## Configuration

Every field except `apiKey` is optional; `AgentConfigResolver::resolve()` fills defaults, validates, and throws `ConfigException` listing every problem. Both camelCase and snake_case keys are accepted.

| Field | Default | Constraint |
| --- | --- | --- |
| `apiKey` | required | at least 10 characters; sent as `X-API-Key` |
| `endpoint` | `https://api.guard-core.com` | http/https URL; trailing `/api/v1` stripped with a one-time warning |
| `projectId` | null | sent as `X-Project-Id` and as batch `project_id` (falls back to `"default"` on the wire) |
| `bufferSize` | 100 | per-kind in-memory capacity, > 0 |
| `flushInterval` | 30 (s) | > 0; time-based flush trigger and per-kind backoff base |
| `dynamicRuleInterval` | 300 (s) | >= 60; dynamic-rules poll cadence (tick-driven refresh) |
| `statusInterval` | 300 (s) | >= 60; status report cadence |
| `highWatermarkRatio` | 0.8 | in (0, 1]; occupancy fraction that triggers an early flush |
| `maxConcurrentFlushes` | 1 | >= 1; bounds re-entrant flushes (single-threaded PHP: effectively a re-entrancy guard) |
| `bufferOverflowPolicy` | `drop` | `drop` (evict oldest) / `block` (drain inline + poll) / `raise` |
| `enableMetrics` / `enableEvents` | true | false disables that ingest kind entirely |
| `retryAttempts` | 3 | transport retries per batch (total tries = attempts + 1), >= 0 |
| `timeout` | 30 (s) | per-request cURL timeout, > 0 |
| `backoffFactor` | 1.0 | transport retry backoff base, capped at 60s |
| `sensitiveHeaders` | authorization, proxy-authorization, cookie, x-api-key | redacted from metadata/tags at ingest and again at the transport boundary |
| `maxPayloadSize` | 1024 | advisory truncate helper for adapter metadata |
| `guardVersion` / `guardCoreVersion` | null | reported in every batch for server-side attribution |
| `compressionEnabled` | true | gzip above `compressionThreshold` |
| `compressionThreshold` | 1024 (bytes) | >= 0 |
| `installId` | null | overrides the file-backed install ID |
| `installIdPath` | `~/.guard-agent/install-id` | override the cache file location |
| `payloadSigningSecret` | null | enables `X-Payload-Signature` over the UNCOMPRESSED body |
| `onError` | null | `Closure(string $stage, Throwable $error, array $context): void`, never allowed to throw |
| `logger` | DefaultAgentLogger | any `AgentLogger` implementation |
| `redis` | null | `RedisConfig` array: url (`redis://` or `rediss://`), keyPrefix, password, db, commandTimeoutMs |

## Reliability Semantics

- **Failure isolation**: `sendEvent`, `sendMetric`, `flushBuffer`, `tick`, `getStatus`, `getStats`, `healthCheck`, and `stop` never throw into the host path; every failure is a log line plus a counter. Only `start()` may throw, and only the standalone `EventBuffer` surfaces `BufferFullException` (the agent swallows it under the `raise` policy). The `block` policy is the one documented, opt-in blocking exception.
- **At-least-once handshake**: drain (keys aligned with items) -> send -> on success confirm (delete Redis records); on failure requeue at the FRONT in original order, retain Redis records, arm the per-kind gate for `min(flushInterval * 2^(streak - 1), 300)` seconds. Under pressure the requeue evicts the TAIL (newest items) and the caller confirms those evicted keys so nothing orphans.
- **Response classification** (mirroring `_handle_response`): 200 with a JSON dict is evaluated (`success: false` or non-empty `errors[]` means partial failure -> whole batch requeued); 200 with an unparseable body is retried; 200 non-dict and 201 are accepted; 429 raises `RateLimitedException` with Retry-After (default 60s, honored up to 300s); 401/403 are generic retried errors; 400/404/422 are `PermanentClientException` (batch dropped, counted, never retried); 413 is `PayloadTooLargeException` (split in half recursively; a singleton that still exceeds the cap is dropped); 5xx retry with backoff; any other 4xx is logged and retried.
- **Circuit breaker**: 5 consecutive non-permanent failures open it for 60s, then HALF_OPEN probes. 400/404/413/422 are exempt (batch-level rejections, not health signals); 429 and curl errors count.
- **Persistence**: persist-on-enqueue under a globally-unique key `{prefix}:agent_events:event_<nanos>_<8hex>` (or `agent_metrics`), TTL 3600s. Startup reload restores items oldest-first; corrupt or missing records are warned and skipped (the TTL reclaims them). Every Redis failure is fail-open: logged, counted in `redisPersistFailures` (`durabilityDegraded`), and after 3 consecutive write failures writes pause for 30s.
- **Degraded status**: circuit OPEN, or buffer >= 90 percent occupancy, or lifetime failure rate > 10 percent. `healthCheck()` additionally fails at >= 95 percent occupancy or > 50 percent failure rate, and when not running.

## Development Commands

| Command | What it runs |
| --- | --- |
| `composer test` | `php bin/test_agent.php` |
| `composer lint` | `for f in $(find src bin -name '*.php'); do php -l "$f" > /dev/null \|\| exit 1; done && echo LINT_OK` (example files are linted with `php -l` directly) |
| `composer validate --strict` | composer.json hygiene (no version field, valid schema) |
| `pip install mkdocs-material && mkdocs build --strict` | Build the documentation site (CI deploys it on `main`) |

Docker equivalents are in Quick Start. There is no Makefile (the sibling PHP repos do not use one either).

## Testing Guidelines

- The suite is `bin/test_agent.php`, a T-harness in the guard-core-php sibling style (plain `ok - / FAIL -` lines, exit code 0 only when everything passed). No PHPUnit, no test framework dependency.
- `REDIS_HOST` controls the persistence leg: `REDIS_HOST=0` skips the real-Redis integration (unit-only), any hostname runs it against port 6379. The fake-Redis handshake tests always run.
- The mock-server integration smoke spawns `php -S` with `tests/mock_server.php`, which mirrors the ingestion contract: size-based 413 (decompressed body > 262144 bytes), signature verification over the uncompressed body with an optional `requireSigned` mode, scripted per-path responses from a control file (status, body, Retry-After), and a JSON state log the tests assert against.
- Pinned HMAC vector: `Signer::signPayload('{"hello":"world"}', 'test-secret')` must equal `v1=84cc33df716ed0b0598f07437c94069ace3730358778a592bd6bbd1423d111f3`.
- Coverage expectations when editing: config validation (all constraint branches), buffer overflow policies and requeue eviction, the handshake order (drain -> send -> confirm/requeue/gate), retry classification (200 partial, 429, 400, 401, 413 split and singleton drop, 5xx, dead endpoint), breaker open/exempt/half-open, persistence (persist-on-enqueue, TTL, reload, confirm deletes, fail-open cooldown), and the smoke contract assertions (headers, gzip, signature, endpoints).
- `vendor/` is never committed; `composer.lock` is (zero-dependency lock, generated with the `composer:2` image).

## Best Practices

1. Never widen the public throwing surface: the host-facing methods must keep never throwing. New failure modes get logged and counted.
2. Keep the wire format byte-faithful to the Python agent (`model_dump()` snake_case) and the server contract; when Python, TS, and Go disagree, Python is normative for agent semantics and the guard-core-api source is normative for the wire.
3. Any change to signature or compression behavior must update the pinned HMAC test and the mock server together.
4. Edit the async-of-nothing source directly: there is no unasync mirror here (unlike guard-core); the whole package is synchronous by design.
5. Keep `declare(strict_types=1)` on every file and PHP 8.2 compatibility (no 8.3+ syntax; `readonly` classes and enums are fine).
6. No em-dashes or en-dashes anywhere in this repository.
7. Run the three PHP-version legs plus `composer validate --strict` before pushing; the release gate re-runs the same matrix at tags.
8. Never merge into `main` and never create tags without an explicit instruction; the working branch pattern is `feat/...` with a draft PR.

## Related Projects

- guard-core (engine): https://github.com/Guard-Core/guard-core
- guard-agent (Python, semantic reference): https://github.com/Guard-Core/guard-agent
- guard-agent-go (Go port): https://github.com/Guard-Core/guard-agent-go
- guardagent (TypeScript port): https://github.com/Guard-Core/guard-agent-ts
- guard-core-php (PHP engine port): https://github.com/Guard-Core/guard-core-php
- guard-core-app (SaaS ingestion API): https://github.com/Guard-Core/guard-core-app
