<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardAgent\Model;

use RenzoFranceschini\GuardAgent\Exception\InvalidRulesException;

/**
 * Dynamic rules received from the SaaS platform via GET /api/v1/rules,
 * mirroring DynamicRules (guard_agent/models.py:250-324) field for field.
 *
 * The server serializes the pydantic model, so the wire payload is
 * snake_case with ISO-8601 timestamps, endpoint_rate_limits as
 * {endpoint: [requests, window]} arrays and blocked_cloud_providers as an
 * array (the Python model holds a set). This class keeps camelCase
 * properties (idiomatic PHP, matching SecurityEvent/SecurityMetric) and
 * normalize() accepts BOTH camelCase and snake_case input keys, mirroring
 * the pydantic parse of `DynamicRules(**response_data)`
 * (guard_agent/_transport_send.py:146). Unknown fields are ignored
 * (pydantic default); wrong-typed known fields raise InvalidRulesException,
 * which the transport converts to a null result.
 *
 * @phpstan-type EndpointLimitPair list{int, int}
 */
final class DynamicRules
{
    /**
     * @param array<string, list<int>> $endpointRateLimits endpoint => [requests, window]
     * @param list<string> $ipBlacklist
     * @param list<string> $ipWhitelist
     * @param list<string> $blockedCountries
     * @param list<string> $whitelistCountries
     * @param list<string> $blockedCloudProviders
     * @param list<string> $blockedUserAgents
     * @param list<string> $suspiciousPatterns
     * @param list<string> $emergencyWhitelist
     */
    public function __construct(
        public readonly string $ruleId = 'default-rule',
        public readonly int $version = 1,
        /** Rule creation/update timestamp; normalize() fills "now" when absent. */
        public readonly ?\DateTimeImmutable $timestamp = null,
        public readonly ?\DateTimeImmutable $expiresAt = null,
        /** Cache TTL in seconds (drives the client-side rules cache). */
        public readonly int $ttl = 300,
        public readonly array $ipBlacklist = [],
        public readonly array $ipWhitelist = [],
        /** Ban duration in seconds. */
        public readonly int $ipBanDuration = 3600,
        public readonly array $blockedCountries = [],
        public readonly array $whitelistCountries = [],
        public readonly ?int $globalRateLimit = null,
        public readonly ?int $globalRateWindow = null,
        public readonly array $endpointRateLimits = [],
        public readonly array $blockedCloudProviders = [],
        public readonly array $blockedUserAgents = [],
        public readonly array $suspiciousPatterns = [],
        public readonly ?bool $enablePenetrationDetection = null,
        public readonly ?bool $enableIpBanning = null,
        public readonly ?bool $enableRateLimiting = null,
        public readonly ?int $autoBanThreshold = null,
        public readonly ?int $autoBanDuration = null,
        public readonly ?bool $enableRateLimitAutoBan = null,
        public readonly bool $emergencyMode = false,
        public readonly array $emergencyWhitelist = [],
        public readonly bool $emergencyWhitelistOnly = false,
        public readonly ?string $message = null,
    ) {
    }

    /**
     * Normalize arbitrary input into a DynamicRules instance. Missing fields
     * keep the Python defaults; null is a valid explicit value for the
     * nullable fields, mirroring the pydantic Optional fields.
     *
     * @throws InvalidRulesException
     */
    public static function normalize(mixed $input): self
    {
        if ($input instanceof self) {
            return $input;
        }
        if (!is_array($input)) {
            throw new InvalidRulesException('Dynamic rules must be an array');
        }

        $rawRuleId = self::pick($input, 'ruleId', 'rule_id');
        $rawVersion = self::pick($input, 'version', 'version');
        $rawTimestamp = self::pick($input, 'timestamp', 'timestamp');
        $rawExpiresAt = self::pick($input, 'expiresAt', 'expires_at');
        $rawTtl = self::pick($input, 'ttl', 'ttl');
        $rawIpBanDuration = self::pick($input, 'ipBanDuration', 'ip_ban_duration');
        $rawGlobalRateLimit = self::pick($input, 'globalRateLimit', 'global_rate_limit');
        $rawGlobalRateWindow = self::pick($input, 'globalRateWindow', 'global_rate_window');
        $rawAutoBanThreshold = self::pick($input, 'autoBanThreshold', 'auto_ban_threshold');
        $rawAutoBanDuration = self::pick($input, 'autoBanDuration', 'auto_ban_duration');
        $rawMessage = self::pick($input, 'message', 'message');

        $timestamp = null;
        if ($rawTimestamp !== null) {
            $timestamp = self::timestamp($rawTimestamp, 'rule timestamp');
        }
        $expiresAt = null;
        if ($rawExpiresAt !== null) {
            $expiresAt = self::timestamp($rawExpiresAt, 'rule expires_at');
        }

        return new self(
            ruleId: $rawRuleId === null ? 'default-rule' : self::requiredString($rawRuleId, 'rule_id'),
            version: $rawVersion === null ? 1 : self::int($rawVersion, 'version'),
            timestamp: $timestamp ?? WireFormat::now(),
            expiresAt: $expiresAt,
            ttl: $rawTtl === null ? 300 : self::int($rawTtl, 'ttl'),
            ipBlacklist: self::stringList(self::pick($input, 'ipBlacklist', 'ip_blacklist'), 'ip_blacklist'),
            ipWhitelist: self::stringList(self::pick($input, 'ipWhitelist', 'ip_whitelist'), 'ip_whitelist'),
            ipBanDuration: $rawIpBanDuration === null ? 3600 : self::int($rawIpBanDuration, 'ip_ban_duration'),
            blockedCountries: self::stringList(self::pick($input, 'blockedCountries', 'blocked_countries'), 'blocked_countries'),
            whitelistCountries: self::stringList(self::pick($input, 'whitelistCountries', 'whitelist_countries'), 'whitelist_countries'),
            globalRateLimit: self::optionalInt($rawGlobalRateLimit, 'global_rate_limit'),
            globalRateWindow: self::optionalInt($rawGlobalRateWindow, 'global_rate_window'),
            endpointRateLimits: self::endpointRateLimits(self::pick($input, 'endpointRateLimits', 'endpoint_rate_limits')),
            blockedCloudProviders: self::stringSet(self::pick($input, 'blockedCloudProviders', 'blocked_cloud_providers'), 'blocked_cloud_providers'),
            blockedUserAgents: self::stringList(self::pick($input, 'blockedUserAgents', 'blocked_user_agents'), 'blocked_user_agents'),
            suspiciousPatterns: self::stringList(self::pick($input, 'suspiciousPatterns', 'suspicious_patterns'), 'suspicious_patterns'),
            enablePenetrationDetection: self::optionalBool(self::pick($input, 'enablePenetrationDetection', 'enable_penetration_detection'), 'enable_penetration_detection'),
            enableIpBanning: self::optionalBool(self::pick($input, 'enableIpBanning', 'enable_ip_banning'), 'enable_ip_banning'),
            enableRateLimiting: self::optionalBool(self::pick($input, 'enableRateLimiting', 'enable_rate_limiting'), 'enable_rate_limiting'),
            autoBanThreshold: self::optionalPositiveInt($rawAutoBanThreshold, 'auto_ban_threshold'),
            autoBanDuration: self::optionalPositiveInt($rawAutoBanDuration, 'auto_ban_duration'),
            enableRateLimitAutoBan: self::optionalBool(self::pick($input, 'enableRateLimitAutoBan', 'enable_rate_limit_auto_ban'), 'enable_rate_limit_auto_ban'),
            emergencyMode: self::strictBool(self::pick($input, 'emergencyMode', 'emergency_mode'), 'emergency_mode', false),
            emergencyWhitelist: self::stringList(self::pick($input, 'emergencyWhitelist', 'emergency_whitelist'), 'emergency_whitelist'),
            emergencyWhitelistOnly: self::strictBool(self::pick($input, 'emergencyWhitelistOnly', 'emergency_whitelist_only'), 'emergency_whitelist_only', false),
            message: self::optionalString($rawMessage, 'message'),
        );
    }

    /**
     * Read a field accepting both camelCase and snake_case keys.
     *
     * @param array<string, mixed> $source
     */
    private static function pick(array $source, string $camel, string $snake): mixed
    {
        if (array_key_exists($camel, $source)) {
            return $source[$camel];
        }

        return $source[$snake] ?? null;
    }

    private static function timestamp(mixed $value, string $field): \DateTimeImmutable
    {
        try {
            return WireFormat::parseTimestamp($value, $field);
        } catch (\RenzoFranceschini\GuardAgent\Exception\InvalidEventException $error) {
            throw new InvalidRulesException($error->getMessage(), previous: $error);
        }
    }

    /**
     * @throws InvalidRulesException
     */
    private static function requiredString(mixed $value, string $field): string
    {
        if (!is_string($value)) {
            throw new InvalidRulesException("{$field} must be a string");
        }

        return $value;
    }

    /**
     * @throws InvalidRulesException
     */
    private static function optionalString(mixed $value, string $field): ?string
    {
        if ($value === null) {
            return null;
        }

        return self::requiredString($value, $field);
    }

    /**
     * Plain integer field (no constraint in the pydantic model).
     *
     * @throws InvalidRulesException
     */
    private static function int(mixed $value, string $field): int
    {
        if (!is_int($value) && !(is_float($value) && floor($value) === $value) && !is_numeric($value)) {
            throw new InvalidRulesException("{$field} must be an integer");
        }

        return (int) $value;
    }

    /**
     * @throws InvalidRulesException
     */
    private static function optionalInt(mixed $value, string $field): ?int
    {
        if ($value === null) {
            return null;
        }

        return self::int($value, $field);
    }

    /**
     * Field with the pydantic ge=1 constraint.
     *
     * @throws InvalidRulesException
     */
    private static function positiveInt(mixed $value, string $field): int
    {
        if (!is_int($value) && !(is_float($value) && floor($value) === $value) && !is_numeric($value)) {
            throw new InvalidRulesException("{$field} must be an integer");
        }
        $parsed = (int) $value;
        if ($parsed < 1) {
            throw new InvalidRulesException("{$field} must be at least 1");
        }

        return $parsed;
    }

    /**
     * @throws InvalidRulesException
     */
    private static function optionalPositiveInt(mixed $value, string $field): ?int
    {
        if ($value === null) {
            return null;
        }

        return self::positiveInt($value, $field);
    }

    /**
     * @throws InvalidRulesException
     */
    private static function optionalBool(mixed $value, string $field): ?bool
    {
        if ($value === null) {
            return null;
        }
        if (!is_bool($value)) {
            throw new InvalidRulesException("{$field} must be a boolean or null");
        }

        return $value;
    }

    /**
     * @throws InvalidRulesException
     */
    private static function strictBool(mixed $value, string $field, bool $fallback): bool
    {
        $parsed = self::optionalBool($value, $field);

        return $parsed ?? $fallback;
    }

    /**
     * @return list<string>
     *
     * @throws InvalidRulesException
     */
    private static function stringList(mixed $value, string $field): array
    {
        if ($value === null) {
            return [];
        }
        if (!is_array($value) || !array_is_list($value)) {
            throw new InvalidRulesException("{$field} must be an array of strings");
        }
        $result = [];
        foreach ($value as $item) {
            if (!is_string($item)) {
                throw new InvalidRulesException("{$field} must contain only strings");
            }
            $result[] = $item;
        }

        return $result;
    }

    /**
     * The Python model holds a set: dedupe on input, like pydantic does
     * when handed a list for a set field.
     *
     * @return list<string>
     *
     * @throws InvalidRulesException
     */
    private static function stringSet(mixed $value, string $field): array
    {
        return array_values(array_unique(self::stringList($value, $field)));
    }

    /**
     * @return array<string, list<int>>
     *
     * @throws InvalidRulesException
     */
    private static function endpointRateLimits(mixed $value): array
    {
        if ($value === null) {
            return [];
        }
        if (!is_array($value)) {
            throw new InvalidRulesException('endpoint_rate_limits must be an object');
        }
        $result = [];
        foreach ($value as $endpoint => $pair) {
            $key = (string) $endpoint;
            if (!is_array($pair) || !array_is_list($pair) || count($pair) !== 2) {
                throw new InvalidRulesException(
                    "endpoint_rate_limits[\"{$key}\"] must be a [requests, window] pair"
                );
            }
            $result[$key] = [
                self::int($pair[0], "endpoint_rate_limits[\"{$key}\"] requests"),
                self::int($pair[1], "endpoint_rate_limits[\"{$key}\"] window"),
            ];
        }

        return $result;
    }
}
