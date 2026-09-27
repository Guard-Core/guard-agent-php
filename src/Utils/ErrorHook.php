<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardAgent\Utils;

use RenzoFranceschini\GuardAgent\Log\AgentLogger;

/**
 * Error hook plumbing, mirroring fire_error_hook (guard_agent/utils.py) and
 * the logging helpers. A hook that throws is caught and logged, never
 * propagated. Hook stages mirror the Python on_error stages: 'transport_send',
 * 'encryption', 'flush_events', 'flush_metrics'.
 */
final class ErrorHook
{
    private function __construct()
    {
    }

    /**
     * Invoke the user's onError callback without ever raising.
     *
     * @param \Closure(string, \Throwable, array<string, mixed>): void|null $onError
     * @param array<string, mixed> $context
     */
    public static function fire(?\Closure $onError, AgentLogger $logger, string $stage, \Throwable $error, array $context): void
    {
        if ($onError === null) {
            return;
        }
        try {
            ($onError)($stage, $error, $context);
        } catch (\Throwable $hookError) {
            $logger->error("onError hook raised while handling '{$stage}': " . self::message($hookError));
        }
    }

    /** Format an unknown thrown value for a single log line. */
    public static function message(mixed $error): string
    {
        if ($error instanceof \Throwable) {
            return $error::class . ': ' . $error->getMessage();
        }

        return (string) $error;
    }
}
