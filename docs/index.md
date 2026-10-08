# guard-agent-php

`guard-agent-php` is the PHP telemetry agent of the Guard ecosystem. It
buffers security events, metrics, and status reports produced by your
application (typically through a guard-core adapter's block hooks) and ships
them to the [guard-core-app](https://github.com/Guard-Core/guard-core-app)
ingestion API with at-least-once delivery.

It is a port of the normative [guard-agent](https://github.com/Guard-Core/guard-agent)
(Python) semantics: per-kind buffers, overflow policies, retry with backoff,
413 batch split-or-drop, Retry-After honoring, a circuit breaker, optional
Redis-backed queue persistence, and a persisted install id. Unlike the
Python, TypeScript, and Go agents it has no background threads: flush and
status loops are host-driven through `tick()` and `flushBuffer()`.

## Installation

```bash
composer require rennf93/guard-agent-php
```

Requires PHP 8.2 or later with `ext-json` and `ext-curl`. Redis persistence
works out of the box through a built-in stream client (no extra extension);
adapters for `ext-redis` and `predis/predis` are provided under `suggest`.

## Quick start

```php
use RenzoFranceschini\GuardAgent\Config\AgentConfigResolver;
use RenzoFranceschini\GuardAgent\GuardAgent;

$agent = new GuardAgent(AgentConfigResolver::resolve([
    'apiKey' => getenv('GUARD_AGENT_API_KEY'),
    'projectId' => getenv('GUARD_AGENT_PROJECT_ID'),
    'payloadSigningSecret' => getenv('GUARD_AGENT_SIGNING_SECRET') ?: null,
]));

$agent->start();

// From anywhere in your request path: never throws, never blocks
// under the default drop policy.
$agent->sendEvent([
    'event_type' => 'suspicious_request',
    'ip_address' => '203.0.113.7',
    'endpoint' => '/api',
    'method' => 'GET',
    'action_taken' => 'BLOCKED',
    'reason' => 'endpoint rate limit exceeded',
]);

// Ship telemetry at the end of the request (kernel.terminate in Symfony,
// register_shutdown_function in plain PHP), or call tick() from a worker
// loop in long-running processes.
register_shutdown_function(static function () use ($agent): void {
    $agent->flushBuffer();
    $agent->stop();
});
```

Most applications do not call the agent directly: the guard-core adapters
expose a block hook (for example guard-core-php's `SecurityConfig(onBlock: ...)`)
where the event construction belongs. See
[examples/basic_usage](https://github.com/Guard-Core/guard-agent-php/tree/main/examples/basic_usage)
for the wiring shape.

## What the agent guarantees

- At-least-once delivery: buffered items survive crashes when Redis
  persistence is enabled and are requeued at the front in original order on
  failure
- HMAC request signing: `X-Payload-Signature` covers the uncompressed body,
  matching the ingestion API's post-decompression verification
- Fail-soft: ingestion outages never throw into the host path or block the
  application beyond the chosen overflow policy; the circuit breaker sheds
  load when the API is down
