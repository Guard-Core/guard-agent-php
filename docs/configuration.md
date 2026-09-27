# Configuration

Everything goes through `AgentConfigResolver::resolve(array $input)`, which
fills defaults, validates, and throws `ConfigException` listing every
problem. Both camelCase and snake_case keys are accepted; the agent itself
reads no environment variables (your application maps its environment onto
the array, as the example does).

## Required

| Field | Purpose |
|---|---|
| `apiKey` | Ingestion API key, sent as `X-API-Key` (minimum 10 characters) |

## Endpoints and identity

| Field | Default | Purpose |
|---|---|---|
| `endpoint` | `https://api.guard-core.com` | Ingestion base URL; a trailing `/api/v1` suffix is stripped with a one-time warning |
| `projectId` | `null` | Sent as `X-Project-Id` and as the batch `project_id` |
| `installId` / `installIdPath` | `~/.guard-agent/install-id` | Persisted agent identity, sent as `X-Agent-Install-Id`; all filesystem failures fall back to an in-memory UUID |
| `guardVersion` / `guardCoreVersion` | `null` | Reported in every batch for server-side attribution |

## Buffering

| Field | Default | Purpose |
|---|---|---|
| `bufferSize` | 100 | Per-kind queue capacity |
| `flushInterval` | 30 | Periodic flush cadence and retry backoff base, in seconds |
| `statusInterval` | 300 | Status report cadence, minimum 60s |
| `highWatermarkRatio` | 0.8 | Combined occupancy that triggers an early flush |
| `maxConcurrentFlushes` | 1 | Re-entrancy bound for flushes (single-threaded PHP) |
| `bufferOverflowPolicy` | `drop` | `drop`, `block`, or `raise` |
| `enableEvents` / `enableMetrics` | `true` | Per-kind send switches |

## Network

| Field | Default | Purpose |
|---|---|---|
| `retryAttempts` | 3 | Retries after a failed attempt (0 disables) |
| `timeout` | 30 | Per-request cURL timeout, in seconds |
| `backoffFactor` | 1.0 | Exponential retry delay base, capped at 60s |
| `compressionEnabled` | `true` | Gzip bodies at or above the threshold |
| `compressionThreshold` | 1024 | Gzip cutoff in bytes |
| `payloadSigningSecret` | `null` | HMAC-SHA256 secret over the uncompressed body |
| `projectEncryptionKey` | `null` | Urlsafe-base64 AES-256 key from the core backend. When set, event/metric batches are AES-256-GCM encrypted and POSTed to `/api/v1/events/encrypted`; an invalid key fails startup (no plaintext fallback) |

## Redaction and hooks

| Field | Default | Purpose |
|---|---|---|
| `sensitiveHeaders` | `authorization`, `proxy-authorization`, `cookie`, `x-api-key` | Redacted from metadata/tags at ingest and again at the transport boundary |
| `maxPayloadSize` | 1024 | Advisory truncate helper for adapter metadata |
| `onError` | `null` | `Closure(string $stage, Throwable $error, array $context): void`; a throwing hook is caught and logged |
| `logger` | `DefaultAgentLogger` | Any `AgentLogger` implementation |

## Redis persistence

```php
$agent = new GuardAgent(AgentConfigResolver::resolve([
    'apiKey' => $apiKey,
    'redis' => [
        'url' => 'redis://127.0.0.1:6379', // redis:// or rediss://
        'keyPrefix' => 'guard:agent',      // default
        'password' => null,
        'db' => 0,
        'commandTimeoutMs' => 5000,
    ],
]));
```

Keys are `{keyPrefix}:{namespace}:{short}` with namespaces `agent_events`
and `agent_metrics`. The built-in stream client needs no extension; inject
`ext-redis` or `predis/predis` instances through the same client seam when
you already run them. Persistence is optional; without it, a process crash
loses buffered-but-unsent items.
