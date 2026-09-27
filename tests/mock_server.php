<?php

/**
 * Mock of the Guard Core App ingestion API for the integration smoke tests,
 * running under `php -S` with this file as the router script. It mirrors the
 * verified wire contract:
 *
 * - POST /api/v1/events | /api/v1/metrics | /api/v1/status
 * - 413 when the (decompressed) body exceeds 262144 bytes
 *   (guard-core-api services/payload_size_guard.py).
 * - X-Payload-Signature verified over the UNCOMPRESSED body: the real server
 *   decompresses gzip request bodies in GzipRequestMiddleware before the
 *   telemetry router runs, so the HMAC must cover the plain JSON bytes.
 * - Scripted responses come from MOCK_CONTROL_FILE (JSON):
 *     {"signatureSecret": "...", "requireSigned": false,
 *      "script": {"events": [entry, ...], "metrics": [...], "status": [...]}}
 *   where an entry is either a status integer or
 *   {"status": N, "body": mixed, "retryAfter": N}.
 * - Every request appends a JSON line to MOCK_STATE_FILE so the tests can
 *   assert on what the mock actually saw.
 */

declare(strict_types=1);

header('Content-Type: application/json');

$controlFile = getenv('MOCK_CONTROL_FILE') ?: '';
$stateFile = getenv('MOCK_STATE_FILE') ?: '';
$control = ['script' => [], 'signatureSecret' => null, 'requireSigned' => false];
if ($controlFile !== '' && is_file($controlFile)) {
    $decoded = json_decode((string) file_get_contents($controlFile), true);
    if (is_array($decoded)) {
        $control = array_merge($control, $decoded);
    }
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$kind = match ($path) {
    '/api/v1/events' => 'events',
    '/api/v1/metrics' => 'metrics',
    '/api/v1/status' => 'status',
    // Encrypted batches share the events script kind.
    '/api/v1/events/encrypted' => 'events',
    default => null,
};

$body = (string) file_get_contents('php://input');
$encoding = strtolower((string) ($_SERVER['HTTP_CONTENT_ENCODING'] ?? ''));
$uncompressed = $body;
if ($encoding === 'gzip') {
    $inflated = @gzdecode($body);
    if ($inflated === false) {
        respond(400, ['detail' => 'Malformed gzip request body']);
        return;
    }
    $uncompressed = $inflated;
}

// Signature verification (server verifies post-decompression).
$signature = (string) ($_SERVER['HTTP_X_PAYLOAD_SIGNATURE'] ?? '');
$signatureValid = null;
if (($control['signatureSecret'] ?? null) !== null) {
    $expected = hash_hmac('sha256', $uncompressed, (string) $control['signatureSecret']);
    $signatureValid = str_starts_with($signature, 'v1=') && hash_equals($expected, substr($signature, 3));
    if (!$signatureValid && ($control['requireSigned'] ?? false) === true) {
        log_request('signature_rejected', $uncompressed);
        respond(401, ['detail' => 'Invalid payload signature']);
        return;
    }
}

// Scripted response, if any.
$entry = $control['script'][$kind]['0'] ?? null;
if (is_array($control['script'][$kind] ?? null)) {
    array_shift($control['script'][$kind]);
    persist_control($controlFile, $control);
}
if ($entry !== null) {
    $status = is_array($entry) ? (int) ($entry['status'] ?? 200) : (int) $entry;
    $responseBody = is_array($entry) && array_key_exists('body', $entry) ? $entry['body'] : ['success' => true];
    if (is_array($entry) && isset($entry['retryAfter'])) {
        header('Retry-After: ' . (string) (int) $entry['retryAfter']);
    }
    log_request($status, $uncompressed);
    respond($status, $responseBody);
    return;
}

// Unscripted: payload size guard, then the happy-path echo envelope.
if (strlen($uncompressed) > 262144) {
    log_request(413, $uncompressed);
    respond(413, ['detail' => 'Payload exceeds 262144 bytes']);
    return;
}

log_request(200, $uncompressed);
respond(200, [
    'success' => true,
    'echo' => [
        'x_api_key' => $_SERVER['HTTP_X_API_KEY'] ?? null,
        'x_project_id' => $_SERVER['HTTP_X_PROJECT_ID'] ?? null,
        'x_agent_install_id' => $_SERVER['HTTP_X_AGENT_INSTALL_ID'] ?? null,
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
        'content_encoding' => $encoding,
        'signature_valid' => $signatureValid,
        'body_sha256' => hash('sha256', $uncompressed),
    ],
]);

function respond(int $status, mixed $body): void
{
    http_response_code($status);
    echo json_encode($body, JSON_UNESCAPED_SLASHES);
}

function log_request(int|string $status, string $requestBody = ''): void
{
    $stateFile = getenv('MOCK_STATE_FILE') ?: '';
    if ($stateFile === '') {
        return;
    }
    $record = [
        'path' => parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/',
        'status' => $status,
        'method' => $_SERVER['REQUEST_METHOD'] ?? '?',
        'content_encoding' => strtolower((string) ($_SERVER['HTTP_CONTENT_ENCODING'] ?? '')),
        'content_length' => (int) ($_SERVER['CONTENT_LENGTH'] ?? 0),
        'x_api_key' => $_SERVER['HTTP_X_API_KEY'] ?? null,
        'x_project_id' => $_SERVER['HTTP_X_PROJECT_ID'] ?? null,
        'x_agent_install_id' => $_SERVER['HTTP_X_AGENT_INSTALL_ID'] ?? null,
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
        'body_json' => json_decode($requestBody, true),
    ];
    @file_put_contents(
        $stateFile,
        json_encode($record) . "\n",
        FILE_APPEND | LOCK_EX
    );
}

function persist_control(string $controlFile, array $control): void
{
    if ($controlFile !== '') {
        @file_put_contents($controlFile, json_encode($control));
    }
}
