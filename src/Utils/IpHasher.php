<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardAgent\Utils;

/**
 * Hash an IP address for privacy-conscious telemetry, mirroring hash_ip
 * (guard_agent/utils.py:221-225): SHA-256 over the concatenation of the IP
 * and an optional salt, rendered as the first 16 hex characters. This is a
 * host-adapter helper and is not used inside the transport itself.
 */
final class IpHasher
{
    private function __construct()
    {
    }

    public static function hash(string $ip, string $salt = ''): string
    {
        return substr(hash('sha256', $ip . $salt), 0, 16);
    }
}
