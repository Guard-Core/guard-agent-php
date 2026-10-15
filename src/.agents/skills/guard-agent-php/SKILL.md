---
name: guard-agent-php
description: Use when an agent works in rennf93/guard-agent-php or embeds the PHP telemetry agent: PHP port of the guard-agent spec that buffers security events, metrics, and agent status and ships them to the Guard Core App ingestion API with at-least-once semantics; covers AgentConfigResolver validation and endpoint normalization, GuardAgent lifecycle (start/stop, host-driven tick loops, no background threads), overflow policies (drop/block/raise), the flush handshake with per-kind backoff gates, HttpTransport classification (200 partial, 429 Retry-After, 400/404/422 permanent, 413 split-or-drop, circuit breaker 5/60s), HMAC signing over the UNCOMPRESSED body, Redis persistence (built-in stream client, TTL 3600, fail-open cooldown), composer scripts (composer lint, composer test), and the T-harness runner bin/test_agent.php with REDIS_HOST modes.
---

# guard-agent-php

## Quick Reference

- Package `rennf93/guard-agent-php`; PSR-4 namespace `RenzoFranceschini\GuardAgent\` mapped to `src/`; PHP `^8.2`, `ext-json`, `ext-curl`; zero composer dependencies; `ext-redis` / `predis/predis` are optional (`suggest`).
- Entry point: `new GuardAgent(AgentConfigResolver::resolve([...]))`. `start()` loads crash-recovery state; `sendEvent()` / `sendMetric()` never throw; `flushBuffer()` never throws; `tick()` is the host-driven loop body (flush + status cadence); `stop()` is idempotent and performs the final flush.
- Failure isolation: host-facing methods never throw into the request path. The only opt-in exception is `bufferOverflowPolicy: 'block'`, which drains inline.
- Wire contract: `POST /api/v1/events|metrics|status`, `X-API-Key` + `X-Project-Id` + `X-Agent-Install-Id`, gzip above `compressionThreshold`, `X-Payload-Signature: v1=<hash_hmac('sha256', UNCOMPRESSED body, secret)>` (the server verifies post-decompression).
- Semantics: per-kind backoff `min(flushInterval * 2^(streak - 1), 300s)`; circuit breaker 5 failures/60s with 400/404/413/422 exempt; 429 Retry-After honored to 300s; Redis persistence TTL 3600s, deferred persist (persistPending at flush/tick, never on add, plus a shutdown function registered once with Redis, so normal end, exit(), uncaught exception, fatal, out of memory and max_execution_time persist; only SIGKILL and an unhandled SIGTERM lose events because PHP runs no code), startup reload, fail-open with a 30s cooldown after 3 write failures.
- Commands: `composer lint` (php -l sweep over `src` and `bin`), `composer test` (`php bin/test_agent.php`). CI runs the matrix php 8.2/8.3/8.4 with `REDIS_HOST=127.0.0.1`, plus `composer audit`.

## Installation

```bash
composer require rennf93/guard-agent-php
```

## Minimal usage

```php
use RenzoFranceschini\GuardAgent\AgentConfigResolver;
use RenzoFranceschini\GuardAgent\GuardAgent;

$agent = new GuardAgent(AgentConfigResolver::resolve([
    'apiKey' => $key,
    'projectId' => 'my-project',
]));
$agent->sendEvent(['event_type' => 'penetration_attempt', 'ip_address' => $ip]);
register_shutdown_function(static function () use ($agent): void {
    $agent->flushBuffer();
    $agent->stop();
});
```

Long-running workers: call `$agent->tick()` inside your own loop (pcntl-free); never rely on timers this package does not own.

## Detailed Reference

Read `AGENTS.md` (mirrored byte-identically in `CLAUDE.md`) for the full architecture map, the configuration table, the response-classification list, and the reliability-semantics contract. The semantic source of truth is the Python guard-agent; the TS and Go ports are the verified mappings; `guard-core-app/backend/guard-core-api/guard_core_api/api/routers/telemetry_router.py` is the wire authority.
