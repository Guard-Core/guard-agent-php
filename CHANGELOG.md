# Release Notes

v3.2.2 (2026-10-09)
-------------------

The Guard agent family 3.2.2 lockstep artifact (v3.2.2)
-------------------------------------------------------

### About this release

- **The PHP port rides the 3.2.2 family wave in lockstep (guard-agent 3.2.2 on PyPI is the anchor).** The only content since 3.2.1 is the post-transfer metadata sweep (PR #18): no runtime change, `src/` has a zero diff.

### Changed (3.2.1 -> 3.2.2)

- **Post-transfer metadata sweep (PR #18).** Repo URLs (README, SECURITY, docs, AGENTS/CLAUDE cross-links) point at the Guard-Core org, the Pages host moves to guard-core.github.io, mkdocs repo_url/repo_name follow, FUNDING's github entry and the CODE_OF_CONDUCT enforcement contact move to the org, and a new `.github/CODEOWNERS` covers the tree. The reported agent version is now 3.2.2 (`RenzoFranceschini\GuardAgent\Version::VERSION`), matching this git tag; composer.json carries no version field, Packagist derives it from the tag. No runtime requirements change.

### Compatibility

- **Drop-in.** Consumers on 3.2.1 can move to 3.2.2 with no code or config changes. Still no composer dependency on guard-core-php (unchanged), so no engine floor applies to this package.

___

v3.2.1 (2026-10-07)
-------------------

The family lockstep artifact: the 3.2.1 wave tag (v3.2.1)
----------------------------------------------------------

### About this release

- **An empty lockstep release for the Guard agent family 3.2.1 wave.** No shipped change: `src/` has a zero diff since 3.2.0 apart from the version constant. The tag exists so the family stays version-aligned while the TypeScript port ships the wave's only runtime fix (the js/polynomial-redos endpoint normalization hardening, guard-agent-ts 3.2.1).

### Changed (3.2.0 -> 3.2.1)

- **Version only.** The reported agent version is now 3.2.1 (`RenzoFranceschini\GuardAgent\Version::VERSION`), matching this git tag; composer.json carries no version field, Packagist derives it from the tag. No runtime requirements change.

### Compatibility

- **Drop-in.** Consumers on 3.2.0 can move to 3.2.1 with no code or config changes. Still no composer dependency on guard-core-php (unchanged), so no engine floor applies to this package.

___

v3.2.0 (2026-10-01)
-------------------

The hardening release: full reachable-line coverage, scaffold baseline, and the 4.3.0 train artifact (v3.2.0)
--------------------------------------------------------------------------------------------------------------

### About this release

- **A maintenance release for the Guard 4.3.0 train.** There are no runtime behavior changes in this version: `src/` has a zero diff since 3.1.0. The release exists so consumers on the Guard 4.3.0 train pick up the hardened test suite and the repo governance baseline in a tagged, Packagist-published agent artifact.

### Changed (3.1.0 -> 3.2.0)

- **Repo scaffold baseline.** Adopted the guard-core process baseline: issue templates, pull request template, `FUNDING.yml`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`, and the greetings workflow.
- **CI hardening.** A Semgrep security-audit and secrets gate joins the workflow set, and a hard 100 percent reachable-line coverage gate is enforced through a dedicated coverage runner (`.github/coverage-runner.php`), with the unreachable-line waiver shrunk to the provably impossible set.
- **Dev-only tooling.** `phpunit/php-code-coverage` `^11.0` is added as a dev dependency to measure the coverage gate. Runtime requirements are unchanged: the agent still declares no composer dependency beyond PHP extensions.
- **The reported agent version is now 3.2.0** (`RenzoFranceschini\GuardAgent\Version::VERSION`), matching this git tag; composer.json carries no version field, Packagist derives it from the tag.

### Testing

- **The suite (`bin/test_agent.php`) was extended to full reachable-line coverage and gated at 100 percent.** Previously uncovered defensive arms are driven through namespace shadows (`tests/namespace_shadows.php`), the scripted phpredis double is kept signature-compatible, the ext-redis adapter is exercised over the real extension, and the Redis suites are now environment independent (`tests/fake_redis_server.php` plus the `REDIS_HOST` toggle), so CI no longer depends on host-specific Redis state.

### Compatibility

- **No composer dependency on guard-core-php.** The agent talks to the guard-core-app ingestion API over HTTP and intentionally declares no dependency on the engine (`rennf93/guard-core-php` appears in neither `require` nor `suggest`), so no composer-level guard-core-php floor applies to this package; it stays installable alongside any core version, including 4.3.0. The `guard-core-php` `^4.3.0` floor ships with the adapters that embed the engine (laravel-guard, symfony-guard, slim-guard, psr15-guard), so consumers on the 4.3.0 train resolve against the new engine and embed this agent for telemetry.

___

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
