<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardAgent\Utils;

/**
 * Truncate a payload with an indicator, mirroring truncate_payload
 * (guard_agent/utils.py:200-204). Length is measured in bytes (no mbstring
 * dependency); this is a host-adapter helper and is not used inside the
 * transport itself.
 */
final class PayloadTruncator
{
    private function __construct()
    {
    }

    public static function truncate(string $payload, int $maxSize): string
    {
        if (strlen($payload) <= $maxSize) {
            return $payload;
        }

        return substr($payload, 0, $maxSize) . '...[TRUNCATED]';
    }
}
