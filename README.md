<p align="center">
    <a href="https://guard-core.github.io/guard-core/latest/">
        <img src="https://guard-core.github.io/guard-core/latest/assets/guard_core_legend.svg" alt="Guard Core">
    </a>
</p>

___

<p align="center">
    <strong>PHP telemetry agent for the [guard-core](https://github.com/Guard-Core/guard-core) ecosystem. It buffers security events, performance metrics, and agent status in memory (optionally persisted to Redis) and ships them to the Guard Core App ingestion API with at-least-once delivery semantics: nothing acknowledged is lost, nothing unacknowledged is forgotten.</strong>
</p>

<p align="center">
    <a href="https://packagist.org/packages/rennf93/guard-agent-php">
        <img src="https://img.shields.io/packagist/v/rennf93/guard-agent-php?color=0080ff" alt="Packagist version">
    </a>
    <a href="https://guard-core.github.io/guard-agent-php/latest/">
        <img src="https://img.shields.io/badge/docs-latest-0080ff.svg" alt="Docs">
    </a>
    <a href="https://github.com/Guard-Core/guard-agent-php/actions/workflows/release.yml">
        <img src="https://github.com/Guard-Core/guard-agent-php/actions/workflows/release.yml/badge.svg" alt="Release">
    </a>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    </a>
    <a href="https://github.com/Guard-Core/guard-agent-php/actions/workflows/ci.yml">
        <img src="https://github.com/Guard-Core/guard-agent-php/actions/workflows/ci.yml/badge.svg" alt="CI">
    </a>
</p>

<p align="center">
    <a href="https://github.com/Guard-Core/guard-agent-php/actions/workflows/pages/pages-build-deployment">
        <img src="https://github.com/Guard-Core/guard-agent-php/actions/workflows/pages/pages-build-deployment/badge.svg?branch=gh-pages" alt="PagesBuildDeployment">
    </a>
    <a href="https://github.com/Guard-Core/guard-agent-php/actions/workflows/docs.yml">
        <img src="https://github.com/Guard-Core/guard-agent-php/actions/workflows/docs.yml/badge.svg" alt="DocsUpdate">
    </a>
    <img src="https://img.shields.io/github/last-commit/Guard-Core/guard-agent-php?style=flat&amp;logo=git&amp;logoColor=white&amp;color=0080ff" alt="last-commit">
</p>

<p align="center">
    <img src="https://img.shields.io/badge/PHP-777BB4.svg?style=flat&logo=php&logoColor=white" alt="PHP"> <img src="https://img.shields.io/badge/Redis-FF4438.svg?style=flat&logo=redis&logoColor=white" alt="Redis">
    <a href="https://packagist.org/packages/rennf93/guard-agent-php">
        <img src="https://img.shields.io/packagist/dm/rennf93/guard-agent-php" alt="Downloads">
    </a>
</p>

<p align="center">
    <a href="https://guard-core.com">Website</a> &middot;
    <a href="https://guard-core.github.io/guard-agent-php/latest/">Docs</a> &middot;
    <a href="https://playground.guard-core.com">Playground</a> &middot;
    <a href="https://app.guard-core.com">Dashboard</a> &middot;
    <a href="https://discord.gg/ZW7ZJbjMkK">Discord</a>
</p>

---


## Ecosystem

Guard Core is the Python engine. Framework adapters are thin wrappers that translate native request/response types into Guard Core's protocols. The telemetry agents ship security events and metrics to the monitoring backend. Parallel engine implementations exist for Go, PHP, TypeScript (on npm), and Rust (on crates.io) - all ports of the same reference semantics, conformance-tested against the shared adversarial corpus.

### Python

| Package | Role | PyPI |
|---|---|---|
| [guard-core](https://github.com/Guard-Core/guard-core) | Framework-agnostic security engine | [![PyPI](https://img.shields.io/pypi/v/guard-core)](https://pypi.org/project/guard-core/) |
| [guard-agent](https://github.com/Guard-Core/guard-agent) | Telemetry agent | [![PyPI](https://img.shields.io/pypi/v/guard-agent)](https://pypi.org/project/guard-agent/) |
| [fastapi-guard](https://github.com/Guard-Core/fastapi-guard) | FastAPI / Starlette adapter | [![PyPI](https://img.shields.io/pypi/v/fastapi-guard)](https://pypi.org/project/fastapi-guard/) |
| [flaskapi-guard](https://github.com/Guard-Core/flaskapi-guard) | Flask adapter | [![PyPI](https://img.shields.io/pypi/v/flaskapi-guard)](https://pypi.org/project/flaskapi-guard/) |
| [djapi-guard](https://github.com/Guard-Core/djapi-guard) | Django adapter | [![PyPI](https://img.shields.io/pypi/v/djapi-guard)](https://pypi.org/project/djapi-guard/) |
| [tornadoapi-guard](https://github.com/Guard-Core/tornadoapi-guard) | Tornado adapter | [![PyPI](https://img.shields.io/pypi/v/tornadoapi-guard)](https://pypi.org/project/tornadoapi-guard/) |

### Go

Go modules published via GitHub releases. **Production-ready.**

| Package | Role | Release |
|---|---|---|
| [guard-core-go](https://github.com/Guard-Core/guard-core-go) | Go engine | [![release](https://img.shields.io/github/v/tag/Guard-Core/guard-core-go?label=tag)](https://github.com/Guard-Core/guard-core-go/releases) |
| [nethttp-guard](https://github.com/Guard-Core/nethttp-guard) | net/http adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/nethttp-guard?label=tag)](https://github.com/Guard-Core/nethttp-guard/releases) |
| [gin-guard](https://github.com/Guard-Core/gin-guard) | Gin adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/gin-guard?label=tag)](https://github.com/Guard-Core/gin-guard/releases) |
| [echo-guard](https://github.com/Guard-Core/echo-guard) | Echo (v4) adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/echo-guard?label=tag)](https://github.com/Guard-Core/echo-guard/releases) |
| [fiber-guard](https://github.com/Guard-Core/fiber-guard) | Fiber (v3) adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/fiber-guard?label=tag)](https://github.com/Guard-Core/fiber-guard/releases) |
| [guard-agent-go](https://github.com/Guard-Core/guard-agent-go) | Telemetry agent | [![release](https://img.shields.io/github/v/tag/Guard-Core/guard-agent-go?label=tag)](https://github.com/Guard-Core/guard-agent-go/releases) |

### PHP

Published on [Packagist](https://packagist.org/) under the `rennf93` vendor. **Production-ready.**

| Package | Role | Packagist |
|---|---|---|
| [guard-core-php](https://github.com/Guard-Core/guard-core-php) | PHP engine | [![Packagist](https://img.shields.io/packagist/v/rennf93/guard-core-php)](https://packagist.org/packages/rennf93/guard-core-php) |
| [laravel-guard](https://github.com/Guard-Core/laravel-guard) | Laravel adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/laravel-guard)](https://packagist.org/packages/rennf93/laravel-guard) |
| [symfony-guard](https://github.com/Guard-Core/symfony-guard) | Symfony adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/symfony-guard)](https://packagist.org/packages/rennf93/symfony-guard) |
| [psr15-guard](https://github.com/Guard-Core/psr15-guard) | PSR-15 adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/psr15-guard)](https://packagist.org/packages/rennf93/psr15-guard) |
| [slim-guard](https://github.com/Guard-Core/slim-guard) | Slim 4 adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/slim-guard)](https://packagist.org/packages/rennf93/slim-guard) |
| [guard-agent-php](https://github.com/Guard-Core/guard-agent-php) | Telemetry agent | [![Packagist](https://img.shields.io/packagist/v/rennf93/guard-agent-php)](https://packagist.org/packages/rennf93/guard-agent-php) |

### TypeScript / JavaScript

Published under the [`@guardcore`](https://www.npmjs.com/org/guardcore) npm scope; source in the [guard-core-ts](https://github.com/Guard-Core/guard-core-ts) monorepo. **Production-ready.**

| Package | Role | npm |
|---|---|---|
| | [@guardcore/core](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/core) | Core engine | [![npm](https://img.shields.io/npm/v/@guardcore%2Fcore)](https://www.npmjs.com/package/@guardcore/core) |
| [@guardcore/express](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/express) | Express adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Fexpress)](https://www.npmjs.com/package/@guardcore/express) |
| [@guardcore/nestjs](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/nestjs) | NestJS adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Fnestjs)](https://www.npmjs.com/package/@guardcore/nestjs) |
| [@guardcore/fastify](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/fastify) | Fastify adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Ffastify)](https://www.npmjs.com/package/@guardcore/fastify) |
| [@guardcore/hono](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/hono) | Hono (edge) adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Fhono)](https://www.npmjs.com/package/@guardcore/hono) |
| [guardagent](https://github.com/Guard-Core/guard-agent-ts) | Telemetry agent | [![npm](https://img.shields.io/npm/v/guardagent)](https://www.npmjs.com/package/guardagent) |

### Rust

Published on crates.io. **Production-ready.**

| Package | Role | crates.io |
|---|---|---|
| [guard-core-engine](https://github.com/Guard-Core/guard-core-rs) | Core engine crate | [![crates.io](https://img.shields.io/crates/v/guard-core-engine)](https://crates.io/crates/guard-core-engine) |
| [guard-core-rs](https://github.com/Guard-Core/guard-core-rs) | Facade crate (consumer entry point) | [![crates.io](https://img.shields.io/crates/v/guard-core-rs)](https://crates.io/crates/guard-core-rs) |
| [actix-guard-rs](https://github.com/Guard-Core/actix-guard-rs) | Actix Web adapter | [![crates.io](https://img.shields.io/crates/v/actix-guard-rs)](https://crates.io/crates/actix-guard-rs) |
| [axum-guard-rs](https://github.com/Guard-Core/axum-guard-rs) | Axum adapter | [![crates.io](https://img.shields.io/crates/v/axum-guard-rs)](https://crates.io/crates/axum-guard-rs) |
| [tower-guard-rs](https://github.com/Guard-Core/tower-guard-rs) | Tower adapter | [![crates.io](https://img.shields.io/crates/v/tower-guard-rs)](https://crates.io/crates/tower-guard-rs) |
| [rocket-guard-rs](https://github.com/Guard-Core/rocket-guard-rs) | Rocket adapter | [![crates.io](https://img.shields.io/crates/v/rocket-guard-rs)](https://crates.io/crates/rocket-guard-rs) |
| [guard-agent-rs](https://github.com/Guard-Core/guard-agent-rs) | Telemetry agent | [![crates.io](https://img.shields.io/crates/v/guard-agent-rs)](https://crates.io/crates/guard-agent-rs) |

### AI Coding Agents

| Package | Role | PyPI |
|---|---|---|
| [guard-core-mcp](https://github.com/Guard-Core/guard-core-mcp) | MCP server: config validation, docs search, detection sandbox | [![PyPI](https://img.shields.io/pypi/v/guard-core-mcp)](https://pypi.org/project/guard-core-mcp/) |

___

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

Do not reach for `pcntl_alarm` or extension timers: drive the agent from your own loop with `tick()`, which flushes when the high-watermark or the flush interval is reached, pushes status reports on the status interval, and refreshes the dynamic rules on the dynamic rule interval.

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

## Dynamic rules

`getDynamicRules()` returns the SaaS rule document from `GET /api/v1/rules` as a `DynamicRules` value object (snake_case wire keys, mirroring the Python agent's pydantic model). The fetched copy is cached in memory and served while it is younger than its own `ttl` (seconds, default 300); a failed fetch returns `null` while the last good rules stay cached for the next poll, and a thrown transport error falls back to the cached copy, so a rules outage never surfaces as a hard failure. The `tick()` loop refreshes the cache every `dynamicRuleInterval` seconds (default 300, minimum 60). Fetch statistics surface in `getStats()` as `rulesFetched`, `cachedRules`, `rulesLastUpdate`, and `loopFailures.rules`.

## Encryption

When `projectEncryptionKey` is set (a urlsafe-base64-encoded 256-bit key issued by the core backend), event and metric batches are encrypted with AES-256-GCM and POSTed to `/api/v1/events/encrypted` as `{encrypted_payload, batch_id, agent_version, guard_version, guard_core_version}`; the wire format is byte-compatible with the Python agent (canonical JSON plaintext with `sort_keys` and `ensure_ascii`, 12-byte nonce prefix, 16-byte auth tag, padded urlsafe base64). An invalid key raises `EncryptionConfigException` at startup; the agent never falls back to plaintext. Signing and compression apply to the envelope body exactly as they do to plaintext batches.

## Persistence

With `redis` configured, every accepted item is written to Redis under a globally-unique key (`{prefix}:agent_events:event_<nanos>_<8hex>`, TTL 3600s) on enqueue; on `start()` the buffer reloads whatever a previous process left behind. Every Redis failure is fail-open: logged, counted, and after 3 consecutive write failures paused for a 30s cooldown, so an unhealthy Redis cannot tax the request path. The TTL is the backstop: at worst a lost confirmation duplicates a reload, it never loses data.

## Documentation

- `AGENTS.md` (mirrored byte-identically in `CLAUDE.md`): architecture, configuration reference, reliability semantics, testing.
- `src/.agents/skills/guard-agent-php/SKILL.md`: agent-oriented quick reference.

## Related projects

- [guard-core](https://github.com/Guard-Core/guard-core): the framework-agnostic engine library.
- [guard-agent](https://github.com/Guard-Core/guard-agent) (Python), guardagent (TypeScript), guard-agent-rs (Rust), guard-agent-go (Go): sibling agents.
- [guard-core-app](https://github.com/Guard-Core/guard-core-app): the SaaS platform this agent reports to.

## License

MIT. See [LICENSE](LICENSE).
