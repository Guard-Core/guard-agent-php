# Release Notes

v3.1.0 (2026-09-27)
-------------------

Parity release: the 3.0.2 to 3.1.0 agent feature train (v3.1.0)
---------------------------------------------------------------

### Added

- **AES-256-GCM encrypted ingest** (`src/Encryption/PayloadEncryptor.php`): batches can be encrypted end to end before they leave the host, with encryption test vectors pinned in `tests/fixtures/encryption_vectors.json`, matching the Python agent contract.
- **Dynamic rules** (`src/Model/DynamicRules.php`): the agent pulls rule updates from the ingestion API and applies them locally, with strict validation via `InvalidRulesException`.
- **Helper ports** (`src/Utils/`): `CanonicalJson`, `IpHasher` (hash_ip) and `PayloadTruncator` (truncate_payload), shared by the new subsystems.
- **`on_error` and `max_payload` configuration knobs** on `AgentConfig` / `AgentConfigResolver`: operators choose the failure behavior and cap the serialized payload size.

### Changed

- **The reported agent version is now 3.1.0** (`RenzoFranceschini\GuardAgent\Version::VERSION`), matching this git tag; composer.json carries no version field, Packagist derives it from the tag.

v3.0.2 (2026-09-24)
-------------------

First tagged release, parity with guard-agent 3.0.2 (v3.0.2)
------------------------------------------------------------

### Added

- **First tagged release of guard-agent-php, at parity with the reference guard-agent 3.0.2 (Python).** The PHP telemetry agent buffers security events, metrics and agent status in memory (optionally persisted to Redis for crash recovery) and ships them to the Guard Core App ingestion API with at-least-once semantics, mirroring the Python agent's behavior.
- **Payload-signature contract aligned with the server: HMAC over the uncompressed body.** `X-Payload-Signature` is computed over the uncompressed body while the wire body may be gzipped, matching the server, which verifies the signature after decompression. Regression tests pin the signature to the HMAC over the decompressed wire body, including the compressed path.

### Fixed

- **The flush loop's partial-failure warning must not claim Redis retention without Redis.** When a batch was partially rejected, the warning claimed items were retained in Redis for retry even when Redis persistence was disabled; the warning now names the backend that actually holds the requeued items (the in-memory buffer only, without Redis).

### Changed

- **The reported agent version is now 3.0.2** (`RenzoFranceschini\GuardAgent\Version::VERSION`), matching the reference guard-agent 3.0.2 and this git tag; composer.json carries no version field, Packagist derives it from the tag.

### Verification

- Full suite: 234 T-harness assertions (`bin/test_agent.php`) across PHP 8.2, 8.3 and 8.4 (CI and the Release Gate workflow at the tag), covering config validation, wire models, redaction, HMAC signing over the uncompressed body, buffer overflow/requeue semantics, circuit breaker and rate limiter, the agent handshake over a scriptable transport, fake and real Redis persistence, and an integration smoke against a mock of the ingestion API (gzip, 200 partial requeue, 413 split and singleton drop, 429 Retry-After, 400 permanent, 401 retry, dead-endpoint isolation, breaker open).

___
