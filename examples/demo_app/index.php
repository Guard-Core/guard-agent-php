<?php

declare(strict_types=1);

/**
 * demo_app serves the Guard Agent demo container: the PHP built-in server
 * hosts a small router that starts guard-agent-php, ships one test event on
 * boot, and exposes the agent lifecycle over three routes (/ : service
 * info, /health : agent status, POST /events : emit a test event). It
 * mirrors the Python agent's examples/demo_app.
 *
 * PHP is host-driven: flush timers only run when the host calls the agent,
 * so the router drives flushIfNeeded() per request and stop() at shutdown.
 *
 *   php -S 0.0.0.0:8080 examples/demo_app/index.php
 */

use RenzoFranceschini\GuardAgent\Config\AgentConfigResolver;
use RenzoFranceschini\GuardAgent\GuardAgent;

require __DIR__ . '/../../vendor/autoload.php';

const DEMO_EVENT_TYPE = 'custom_request_check';

/**
 * Boots the agent once per server process; the built-in server keeps the
 * process (and this static) alive across requests.
 */
function agent(): GuardAgent
{
    static $agent = null;
    if ($agent instanceof GuardAgent) {
        return $agent;
    }

    $agent = new GuardAgent(AgentConfigResolver::resolve([
        'apiKey' => getenv('GUARD_AGENT_API_KEY') ?: 'demo-api-key-12345',
        'endpoint' => getenv('GUARD_AGENT_ENDPOINT') ?: 'https://api.guard-core.com',
        'projectId' => getenv('GUARD_AGENT_PROJECT_ID') ?: 'demo-project',
        'payloadSigningSecret' => getenv('GUARD_AGENT_SIGNING_SECRET') ?: null,
        'guardVersion' => 'demo',
        'bufferSize' => 10,
        'flushInterval' => 5,
    ]));

    // start() is the only method that may throw (config validation happens
    // in the resolver; start() can fail on crash-recovery load).
    $agent->start();

    // Boot-time test event, like the Python demo's lifespan startup.
    $agent->sendEvent(buildTestEvent());

    register_shutdown_function(static function () use ($agent): void {
        $agent->stop();
    });

    return $agent;
}

/**
 * @return array<string, mixed>
 */
function buildTestEvent(): array
{
    return [
        'event_type' => DEMO_EVENT_TYPE,
        'ip_address' => '192.168.1.100',
        'action_taken' => 'logged',
        'reason' => 'Guard Agent demo container test event',
        'endpoint' => '/demo/test-event',
        'method' => 'POST',
        'metadata' => ['source' => 'guard-agent-demo-container'],
    ];
}

/**
 * @return never
 */
function respond(array $payload, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($payload, JSON_THROW_ON_ERROR), "\n";
    exit;
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

$agent = agent();

switch ([$method, $path]) {
    case ['GET', '/']:
        respond([
            'service' => 'guard-agent-demo',
            'endpoint' => getenv('GUARD_AGENT_ENDPOINT') ?: 'https://api.guard-core.com',
            'project_id' => getenv('GUARD_AGENT_PROJECT_ID') ?: 'demo-project',
        ]);
        // no break: respond() exits.

    case ['GET', '/health']:
        // Host-driven flush: timers only advance when the host calls in.
        $agent->flushIfNeeded();
        respond(['status' => $agent->getStatus()->status]);

    case ['POST', '/events']:
        $event = buildTestEvent();
        // Never throws, never blocks (default drop policy).
        $agent->sendEvent($event);
        respond(['emitted' => $event['event_type']]);

    default:
        if (($path === '/' || $path === '/health') && $method !== 'GET') {
            respond(['error' => 'GET only'], 405);
        }
        if ($path === '/events' && $method !== 'POST') {
            respond(['error' => 'POST only'], 405);
        }
        respond(['error' => 'not found'], 404);
}
