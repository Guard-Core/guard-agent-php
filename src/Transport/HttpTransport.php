<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardAgent\Transport;

use RenzoFranceschini\GuardAgent\Config\AgentConfig;
use RenzoFranceschini\GuardAgent\Exception\GuardAgentException;
use RenzoFranceschini\GuardAgent\Exception\PayloadTooLargeException;
use RenzoFranceschini\GuardAgent\Exception\PermanentClientException;
use RenzoFranceschini\GuardAgent\Exception\RateLimitedException;
use RenzoFranceschini\GuardAgent\Encryption\PayloadEncryptor;
use RenzoFranceschini\GuardAgent\Exception\EncryptionConfigException;
use RenzoFranceschini\GuardAgent\Exception\EncryptionException;
use RenzoFranceschini\GuardAgent\Exception\SerializationException;
use RenzoFranceschini\GuardAgent\Install\InstallId;
use RenzoFranceschini\GuardAgent\Log\AgentLogger;
use RenzoFranceschini\GuardAgent\Log\DefaultAgentLogger;
use RenzoFranceschini\GuardAgent\Model\AgentStatus;
use RenzoFranceschini\GuardAgent\Model\SecurityEvent;
use RenzoFranceschini\GuardAgent\Model\SecurityMetric;
use RenzoFranceschini\GuardAgent\Utils\Backoff;
use RenzoFranceschini\GuardAgent\Utils\BatchId;
use RenzoFranceschini\GuardAgent\Utils\ErrorHook;
use RenzoFranceschini\GuardAgent\Utils\HeadersRedactor;
use RenzoFranceschini\GuardAgent\Utils\Json;
use RenzoFranceschini\GuardAgent\Utils\ResponseSummary;
use RenzoFranceschini\GuardAgent\Utils\RetryAfter;
use RenzoFranceschini\GuardAgent\Version;
use RenzoFranceschini\GuardAgent\Model\WireFormat;

/**
 * HTTP transport, mirroring guard_agent/transport.py and its mixin split:
 * _transport_lifecycle.py (client lifecycle, headers, stats),
 * _transport_dispatch.py (request building, compression, signing, response
 * classification), _transport_send.py (retry loops, 413 split-or-drop,
 * permanent-rejection drops). Implemented over ext-curl with gzip bodies
 * (zero composer dependencies, like the TypeScript port).
 *
 * Wire contract (guard-core-app/backend/guard-core-api):
 * - POST {endpoint}/api/v1/events   -> BatchTelemetryRequest  (telemetry_router.py:223)
 * - POST {endpoint}/api/v1/metrics  -> BatchTelemetryRequest  (telemetry_router.py:311)
 * - POST {endpoint}/api/v1/status   -> AgentStatusRequest     (telemetry_router.py:290)
 * - Auth: X-API-Key required; X-Project-Id optional
 *   (telemetry_router.py:210-217); X-Agent-Install-Id for install tracking
 *   (telemetry_router.py:194); optional X-Payload-Signature HMAC over the
 *   UNCOMPRESSED body (telemetry_router.py:110-126, verified post-decompression
 *   via the GzipRequestMiddleware, see Signer).
 * - 413 when the (decompressed) body exceeds 262144 bytes
 *   (services/payload_size_guard.py).
 *
 * Status classification, mirrored from _transport_dispatch.py:64-102:
 * - 200: JSON dict is returned for evaluation (success=false or non-empty
 *   errors means partial failure); unparseable body -> false; non-dict JSON
 *   -> true.
 * - 201: accepted.
 * - 429: RateLimitedException carrying Retry-After (default 60s, capped at 300s).
 * - 401/403: generic error -> retried like any transient failure (the
 *   Python agent classifies auth failures this way; mirrored).
 * - 400/404/413/422: 413 -> PayloadTooLargeException (split-or-drop); other
 *   4xx -> PermanentClientException (batch dropped, not retried). Neither
 *   counts toward the circuit breaker.
 * - 5xx: error -> retried with exponential backoff.
 * - any other 4xx: logged, treated as a transient failure (no throw).
 */
final class HttpTransport implements TransportInterface
{
    private const NON_RETRYABLE_STATUS_CODES = [400, 404, 413, 422];

    /** Upper bound on honoring a server Retry-After (Python: 300s). */
    private const MAX_RETRY_AFTER_SECONDS = 300.0;

    /** Backoff ceiling for transport retries (Python calculate_backoff default). */
    private const MAX_RETRY_BACKOFF_SECONDS = 60.0;

    public readonly CircuitBreaker $circuitBreaker;

    public readonly RateLimiter $rateLimiter;

    public int $requestsSent = 0;

    public int $requestsFailed = 0;

    public int $bytesSent = 0;

    private bool $initialized = false;

    /** @var list<string> */
    private array $defaultHeaders = [];

    private readonly string $installId;

    private ?PayloadEncryptor $encryptor = null;

    private bool $encryptionEnabled = false;

    /** Endpoints whose POST bodies are encrypted when a key is configured
     * (mirrors _transport_dispatch._ENCRYPTED_ENDPOINTS). */
    private const ENCRYPTED_ENDPOINTS = ['/api/v1/events', '/api/v1/metrics'];

    private readonly AgentLogger $logger;

    public function __construct(
        private readonly AgentConfig $config,
        ?AgentLogger $logger = null,
    ) {
        $this->logger = $logger ?? $config->logger ?? new DefaultAgentLogger();
        $this->circuitBreaker = new CircuitBreaker(5, 60.0);
        $this->rateLimiter = new RateLimiter(100, 60.0);
        $this->installId = InstallId::resolve($config->installIdPath, $config->installId, $this->logger);
    }

    /** Build default headers (mirrors HTTPTransport.initialize). Idempotent. */
    public function initialize(): void
    {
        if ($this->initialized) {
            return;
        }

        $headers = [
            'User-Agent: ' . Version::USER_AGENT,
            'Content-Type: application/json',
            'X-API-Key: ' . $this->config->apiKey,
            'X-Agent-Install-Id: ' . $this->installId,
        ];
        if ($this->config->projectId !== null) {
            $headers[] = 'X-Project-Id: ' . $this->config->projectId;
        }
        $this->defaultHeaders = $headers;
        $this->initEncryption();
        $this->initialized = true;
        $this->logger->info('HTTP transport initialized successfully');
    }

    /** Release the transport (mirrors close). */
    public function close(): void
    {
        $this->initialized = false;
    }

    /**
     * @return array<string, mixed>
     */
    public function getStats(): array
    {
        return [
            'requestsSent' => $this->requestsSent,
            'requestsFailed' => $this->requestsFailed,
            'bytesSent' => $this->bytesSent,
            'circuitBreakerState' => $this->circuitBreaker->state,
            'failureCount' => $this->circuitBreaker->failureCount,
            'sessionClosed' => !$this->initialized,
        ];
    }

    // ------------------------------------------------------------------
    // Public send API
    // ------------------------------------------------------------------

    /**
     * Send security events to the ingestion API.
     *
     * Returns true when the batch was durably accepted OR intentionally
     * dropped because it is permanently un-sendable (non-retryable 4xx, or a
     * 413 that persists down to a single item); the caller deletes Redis keys
     * and does not requeue in both cases. Returns false only on transient
     * failure, so the caller requeues and retains the Redis keys for retry.
     *
     * @param list<SecurityEvent> $events
     */
    public function sendEvents(array $events): bool
    {
        if ($events === []) {
            return true;
        }

        try {
            return $this->sendWithRetry('/api/v1/events', $this->buildBatchWire(events: $events), 'events');
        } catch (PayloadTooLargeException $error) {
            return $this->splitOrDropOnPayloadTooLarge(
                $events,
                $error,
                'events',
                fn (array $half): bool => $this->sendEvents($half)
            );
        } catch (PermanentClientException $error) {
            $this->dropPermanentRejection($events, $error, 'events');

            return true;
        } catch (\Throwable $error) {
            $this->logger->error('Failed to send events: ' . ErrorHook::message($error));
            $this->requestsFailed++;

            return false;
        }
    }

    /** Send metrics to the ingestion API; see sendEvents for the contract. */
    public function sendMetrics(array $metrics): bool
    {
        if ($metrics === []) {
            return true;
        }

        try {
            return $this->sendWithRetry('/api/v1/metrics', $this->buildBatchWire(metrics: $metrics), 'metrics');
        } catch (PayloadTooLargeException $error) {
            return $this->splitOrDropOnPayloadTooLarge(
                $metrics,
                $error,
                'metrics',
                fn (array $half): bool => $this->sendMetrics($half)
            );
        } catch (PermanentClientException $error) {
            $this->dropPermanentRejection($metrics, $error, 'metrics');

            return true;
        } catch (\Throwable $error) {
            $this->logger->error('Failed to send metrics: ' . ErrorHook::message($error));
            $this->requestsFailed++;

            return false;
        }
    }

    /** Send agent status/health information (mirrors send_status). */
    public function sendStatus(AgentStatus $status): bool
    {
        try {
            return $this->sendWithRetry('/api/v1/status', $status->toWire(), 'status');
        } catch (\Throwable $error) {
            $this->logger->error('Failed to send status: ' . ErrorHook::message($error));

            return false;
        }
    }

    // ------------------------------------------------------------------
    // Batch wire building
    // ------------------------------------------------------------------

    /**
     * @param list<SecurityEvent> $events
     * @param list<SecurityMetric> $metrics
     *
     * @return array<string, mixed>
     */
    private function buildBatchWire(array $events = [], array $metrics = []): array
    {
        return [
            'project_id' => $this->config->projectId ?? 'default',
            'events' => array_map(static fn (SecurityEvent $event): array => $event->toWire(), $events),
            'metrics' => array_map(static fn (SecurityMetric $metric): array => $metric->toWire(), $metrics),
            'batch_id' => BatchId::generate(),
            'created_at' => WireFormat::isoUtc(WireFormat::now()),
            'compressed' => false,
            'agent_version' => Version::VERSION,
            'guard_version' => $this->config->guardVersion,
            'guard_core_version' => $this->config->guardCoreVersion,
        ];
    }

    // ------------------------------------------------------------------
    // Request dispatch
    // ------------------------------------------------------------------

    /**
     * Make an HTTP request against the ingestion API. Failures are raised as
     * typed errors for the retry loop to classify. Mirrors
     * _make_request + _handle_response.
     *
     * @param array<string, mixed> $data
     *
     * @return array<string, mixed>|bool
     */
    private function makeRequest(string $endpoint, array $data): array|bool
    {
        if (!$this->initialized) {
            $this->initialize();
        }

        $data = $this->redactSensitiveHeaders($data);
        $url = rtrim($this->config->endpoint, '/') . $endpoint;

        if ($this->isEncryptedTarget($endpoint, $data)) {
            return $this->postEncrypted($data);
        }

        try {
            $json = Json::encode($data);
        } catch (SerializationException $error) {
            $this->logger->error(
                "Aborting POST to {$url}; payload serialization failed and batch retained: " . $error->getMessage()
            );
            ErrorHook::fire($this->config->onError, $this->logger, 'transport_send', $error, ['endpoint' => $url]);

            return false;
        }

        $headers = $this->defaultHeaders;
        $body = $json;
        if ($this->config->compressionEnabled && strlen($body) >= $this->config->compressionThreshold) {
            $body = (string) gzencode($json);
            $headers[] = 'Content-Encoding: gzip';
        }
        // The signature always covers the UNCOMPRESSED body: the server
        // verifies post-decompression (see Signer).
        $signature = Signer::signPayload($json, $this->config->payloadSigningSecret);
        if ($signature !== null) {
            $headers[] = 'X-Payload-Signature: ' . $signature;
        }
        $this->bytesSent += strlen($body);

        [$status, $responseHeaders, $responseBody] = $this->execute($url, $headers, $body, $endpoint);

        return $this->handleResponse($status, $responseHeaders, $responseBody, $url);
    }

    /**
     * Execute one cURL request.
     *
     * @param list<string> $headers
     * @param array<string, string> $responseHeaders lowercased name => value
     *
     * @return array{0: int, 1: array<string, string>, 2: string}
     */
    private function execute(string $url, array $headers, string $body, string $endpoint): array
    {
        $responseHeaders = [];
        $handle = curl_init($url);
        if ($handle === false) {
            throw new GuardAgentException("HTTP client error for POST {$url}: curl_init failed");
        }
        curl_setopt_array($handle, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_TIMEOUT => $this->config->timeout,
            CURLOPT_CONNECTTIMEOUT => $this->config->timeout,
            CURLOPT_HEADERFUNCTION => static function ($handle, string $line) use (&$responseHeaders): int {
                $length = strlen($line);
                $parts = explode(':', $line, 2);
                if (count($parts) === 2) {
                    $responseHeaders[strtolower(trim($parts[0]))] = trim($parts[1]);
                }

                return $length;
            },
        ]);

        $responseBody = curl_exec($handle);
        if ($responseBody === false) {
            $errorCode = curl_errno($handle);
            $errorMessage = (string) curl_error($handle);
            curl_close($handle);
            $label = $errorCode === CURLE_OPERATION_TIMEDOUT ? 'Timeout error' : 'HTTP client error';
            $this->logger->error("{$label} for POST {$url}: {$errorCode} {$errorMessage}");
            throw new GuardAgentException("{$label} for POST {$url}: {$errorCode} {$errorMessage}");
        }
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        curl_close($handle);
        $this->logger->debug("Response: {$status} for POST {$url} ({$endpoint})");

        return [$status, $responseHeaders, (string) $responseBody];
    }

    /**
     * Initialize the encryptor when projectEncryptionKey is set. Plaintext
     * fallback is forbidden: an invalid key or a failed round trip raises
     * EncryptionConfigException at startup (mirrors
     * _transport_lifecycle._init_encryption).
     */
    private function initEncryption(): void
    {
        if ($this->config->projectEncryptionKey === null || $this->config->projectEncryptionKey === '') {
            return;
        }

        try {
            $this->encryptor = PayloadEncryptor::create($this->config->projectEncryptionKey);
            if ($this->encryptor === null || !$this->encryptor->verifyKey()) {
                throw new EncryptionConfigException('Encryption round-trip failed at startup; refusing plaintext fallback');
            }
            $this->encryptionEnabled = true;
        } catch (EncryptionConfigException $error) {
            $this->encryptor = null;
            $this->encryptionEnabled = false;
            throw $error;
        } catch (\Throwable $error) {
            $this->encryptor = null;
            $this->encryptionEnabled = false;
            throw new EncryptionConfigException('Encryption round-trip failed at startup; refusing plaintext fallback', previous: $error);
        }
    }

    /**
     * Whether this POST batch must be encrypted (mirrors
     * _is_encrypted_target: payload present + encryption enabled + one of
     * the telemetry endpoints).
     *
     * @param array<string, mixed> $data
     */
    private function isEncryptedTarget(string $endpoint, array $data): bool
    {
        return $data !== []
            && $this->encryptionEnabled
            && in_array($endpoint, self::ENCRYPTED_ENDPOINTS, true);
    }

    /**
     * POST an encrypted batch to /api/v1/events/encrypted (mirrors
     * _post_encrypted + _build_encrypted_payload): only the events/metrics
     * arrays are encrypted; the envelope carries batch_id and version
     * fields in clear. Envelope serialization failure fires the
     * "encryption" hook and returns false so the batch is retained.
     *
     * @param array<string, mixed> $data
     *
     * @return array<string, mixed>|bool
     */
    private function postEncrypted(array $data): array|bool
    {
        $encryptor = $this->encryptor;
        if ($encryptor === null) {
            throw new EncryptionException('Encryptor not initialized');
        }
        $encryptedUrl = rtrim($this->config->endpoint, '/') . '/api/v1/events/encrypted';
        $encryptedPayload = $encryptor->encrypt([
            'events' => is_array($data['events'] ?? null) ? $data['events'] : [],
            'metrics' => is_array($data['metrics'] ?? null) ? $data['metrics'] : [],
        ]);
        $envelope = [
            'encrypted_payload' => $encryptedPayload,
            'batch_id' => $data['batch_id'] ?? null,
            'agent_version' => Version::VERSION,
            'guard_version' => $this->config->guardVersion,
            'guard_core_version' => $this->config->guardCoreVersion,
        ];

        try {
            $json = Json::encode($envelope);
        } catch (SerializationException $error) {
            $this->logger->error(
                "Aborting encrypted POST to {$encryptedUrl}; payload serialization failed and batch retained: " . $error->getMessage()
            );
            ErrorHook::fire($this->config->onError, $this->logger, 'encryption', $error, ['endpoint' => $encryptedUrl]);

            return false;
        }

        $headers = $this->defaultHeaders;
        $body = $json;
        if ($this->config->compressionEnabled && strlen($body) >= $this->config->compressionThreshold) {
            $body = (string) gzencode($json);
            $headers[] = 'Content-Encoding: gzip';
        }
        $signature = Signer::signPayload($json, $this->config->payloadSigningSecret);
        if ($signature !== null) {
            $headers[] = 'X-Payload-Signature: ' . $signature;
        }
        $this->bytesSent += strlen($body);

        [$status, $responseHeaders, $responseBody] = $this->execute($encryptedUrl, $headers, $body, '/api/v1/events/encrypted');

        return $this->handleResponse($status, $responseHeaders, $responseBody, $encryptedUrl);
    }

    /**
     * Redact sensitive headers inside event metadata and metric tags one more
     * time at the transport boundary (mirrors _redact_sensitive_headers).
     *
     * @param array<string, mixed> $data
     *
     * @return array<string, mixed>
     */
    private function redactSensitiveHeaders(array $data): array
    {
        if (is_array($data['events'] ?? null)) {
            foreach ($data['events'] as $index => $event) {
                if (is_array($event) && is_array($event['metadata'] ?? null)) {
                    $data['events'][$index]['metadata'] = HeadersRedactor::sanitize(
                        $event['metadata'],
                        $this->config->sensitiveHeaders
                    );
                }
            }
        }
        if (is_array($data['metrics'] ?? null)) {
            foreach ($data['metrics'] as $index => $metric) {
                if (is_array($metric) && is_array($metric['tags'] ?? null)) {
                    $data['metrics'][$index]['tags'] = HeadersRedactor::sanitize(
                        $metric['tags'],
                        $this->config->sensitiveHeaders
                    );
                }
            }
        }

        return $data;
    }

    /**
     * Classify an HTTP response (mirrors _handle_response).
     *
     * @param array<string, string> $responseHeaders
     *
     * @return array<string, mixed>|bool
     */
    private function handleResponse(int $status, array $responseHeaders, string $responseBody, string $url): array|bool
    {
        if ($status === 200) {
            return $this->handle200($responseBody, $url);
        }
        if ($status === 201) {
            return true;
        }
        if ($status === 429) {
            throw new RateLimitedException(
                RetryAfter::parse($responseHeaders['retry-after'] ?? null, 60.0)
            );
        }
        if ($status === 401 || $status === 403) {
            throw new GuardAgentException("Authentication failed: {$status}");
        }
        if (in_array($status, self::NON_RETRYABLE_STATUS_CODES, true)) {
            $errorText = ResponseSummary::summarize($responseBody);
            $this->logger->error("Permanent client error {$status} for {$url}: {$errorText}");
            if ($status === 413) {
                throw new PayloadTooLargeException($errorText);
            }

            throw new PermanentClientException($status, $errorText);
        }
        if ($status >= 500) {
            $errorText = ResponseSummary::summarize($responseBody);
            throw new GuardAgentException("Server error {$status} for {$url}: {$errorText}");
        }

        $errorText = ResponseSummary::summarize($responseBody);
        $this->logger->error("Client error {$status} for {$url}: {$errorText}");

        return false;
    }

    /**
     * 200 with JSON body evaluation (mirrors _handle_200).
     *
     * @return array<string, mixed>|bool
     */
    private function handle200(string $responseBody, string $url): array|bool
    {
        $json = Json::decodeAnyOrNull($responseBody);
        if ($json === null) {
            $this->logger->warning(
                "200 response with unparseable JSON body for {$url}: ResponseNotJSON"
            );

            return false;
        }
        if (is_array($json) && !array_is_list($json)) {
            $success = $json['success'] ?? null;
            $errors = $json['errors'] ?? null;
            if ($success === false || (is_array($errors) && $errors !== [])) {
                $this->logger->warning(
                    "200 response reported partial failure for {$url}: " .
                    'success=' . Json::encode($success) . ' errors=' . Json::encode($errors)
                );
            }

            return $json;
        }

        return true;
    }

    // ------------------------------------------------------------------
    // Retry loops
    // ------------------------------------------------------------------

    /**
     * Evaluate a send result: true (accepted), false (partial failure), or
     * null (retry). Mirrors _evaluate_send_result.
     *
     * @param array<string, mixed>|bool $result
     */
    private function evaluateSendResult(array|bool $result, string $dataType): ?bool
    {
        if (is_array($result)) {
            $success = $result['success'] ?? null;
            $errors = $result['errors'] ?? null;
            if ($success === false || (is_array($errors) && $errors !== [])) {
                $this->logger->warning(
                    "Server acknowledged {$dataType} batch with partial failure: " .
                    'success=' . Json::encode($success) . ' errors=' . Json::encode($errors)
                );
                $this->requestsFailed++;

                return false;
            }
        }
        if ($result) {
            $this->requestsSent++;
            $this->logger->debug("Successfully sent {$dataType} batch");

            return true;
        }
        $this->requestsFailed++;

        return null;
    }

    /**
     * Sleep to retry (true) or record a final failure (false), mirroring
     * _sleep_or_record_giveup.
     */
    private function sleepOrRecordGiveup(int $attempt, float $delay): bool
    {
        if ($attempt < $this->config->retryAttempts) {
            $this->sleep($delay);

            return true;
        }
        $this->requestsFailed++;

        return false;
    }

    /**
     * POST data with retry logic, local rate limiting, and the circuit
     * breaker (mirrors _send_with_retry). Returns true only when the batch
     * was accepted or reported a partial failure that the caller must requeue.
     *
     * @param array<string, mixed> $data
     */
    private function sendWithRetry(string $endpoint, array $data, string $dataType): bool
    {
        for ($attempt = 0; $attempt <= $this->config->retryAttempts; $attempt++) {
            try {
                if (!$this->rateLimiter->acquire()) {
                    $retryAfter = $this->rateLimiter->getRetryAfter();
                    $this->logger->warning(sprintf('Rate limit exceeded, waiting %.1fs', $retryAfter));
                    $this->sleep($retryAfter);
                    continue;
                }

                $result = $this->circuitBreaker->call(fn (): array|bool => $this->makeRequest($endpoint, $data));

                $outcome = $this->evaluateSendResult($result, $dataType);
                if ($outcome !== null) {
                    return $outcome;
                }
            } catch (RateLimitedException $error) {
                $delay = min($error->retryAfterSeconds, self::MAX_RETRY_AFTER_SECONDS);
                $this->logger->warning(
                    sprintf('Server rate-limited %s; sleeping %.1fs per Retry-After', $dataType, $delay)
                );
                $this->sleepOrRecordGiveup($attempt, $delay);
                continue;
            } catch (PermanentClientException $error) {
                throw $error;
            } catch (\Throwable $error) {
                $this->logger->warning(
                    sprintf('Attempt %d failed for %s: %s', $attempt + 1, $dataType, ErrorHook::message($error))
                );
                $delay = Backoff::calculate($attempt, $this->config->backoffFactor, self::MAX_RETRY_BACKOFF_SECONDS);
                if (!$this->sleepOrRecordGiveup($attempt, $delay)) {
                    $this->logger->error("All retry attempts failed for {$dataType}");
                    ErrorHook::fire($this->config->onError, $this->logger, 'transport_send', $error, [
                        'endpoint' => $endpoint,
                        'dataType' => $dataType,
                    ]);
                }
            }
        }

        return false;
    }

    // ------------------------------------------------------------------
    // 413 split-or-drop and permanent rejection
    // ------------------------------------------------------------------

    /**
     * 413 split-or-drop (mirrors _split_or_drop_on_payload_too_large): split
     * the batch in half and retry each half; drop with a warning once a batch
     * of a single item still exceeds the cap.
     *
     * @param list<mixed> $items
     * @param callable(list<mixed>): bool $sendHalf
     */
    private function splitOrDropOnPayloadTooLarge(array $items, PayloadTooLargeException $error, string $dataType, callable $sendHalf): bool
    {
        if (count($items) <= 1) {
            $this->logger->warning(
                "Dropping {$dataType} batch of " . count($items) . ' item; payload exceeds size cap ' .
                "even as a single item: {$error->detail}"
            );
            $this->requestsFailed++;
            ErrorHook::fire($this->config->onError, $this->logger, 'transport_send', $error, [
                'dataType' => $dataType,
                'itemCount' => count($items),
            ]);

            return true;
        }
        $midpoint = intdiv(count($items), 2);
        $left = $sendHalf(array_slice($items, 0, $midpoint));
        $right = $sendHalf(array_slice($items, $midpoint));

        return $left && $right;
    }

    /**
     * Drop a permanently rejected batch (mirrors _drop_permanent_rejection).
     *
     * @param list<mixed> $items
     */
    private function dropPermanentRejection(array $items, PermanentClientException $error, string $dataType): void
    {
        $this->logger->warning(
            "Dropping {$dataType} batch of " . count($items) . " item(s); permanently rejected " .
            "({$error->statusCode}): {$error->detail}"
        );
        $this->requestsFailed++;
        ErrorHook::fire($this->config->onError, $this->logger, 'transport_send', $error, [
            'dataType' => $dataType,
            'itemCount' => count($items),
        ]);
    }

    /** Sleep helper in fractional seconds. */
    private function sleep(float $seconds): void
    {
        if ($seconds <= 0) {
            return;
        }
        usleep((int) ceil($seconds * 1_000_000));
    }
}
