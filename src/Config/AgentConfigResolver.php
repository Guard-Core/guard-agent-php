<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardAgent\Config;

use RenzoFranceschini\GuardAgent\Exception\ConfigException;
use RenzoFranceschini\GuardAgent\Log\AgentLogger;
use RenzoFranceschini\GuardAgent\Log\DefaultAgentLogger;

/**
 * Resolve user input into a full AgentConfig with defaults, then validate,
 * mirroring guard_agent/utils.py validate_config (lines 281-306), the
 * pydantic field constraints, and AgentConfig.validate_endpoint
 * (guard_agent/models.py:176-205). Throws ConfigException listing every
 * problem, mirroring `ValueError(f"Invalid agent configuration: ...")`.
 */
final class AgentConfigResolver
{
    private static bool $endpointSuffixWarned = false;

    private function __construct()
    {
    }

    /**
     * @param array<string, mixed> $input
     *
     * @throws ConfigException
     */
    public static function resolve(array $input): AgentConfig
    {
        $logger = $input['logger'] ?? null;
        if (!$logger instanceof AgentLogger) {
            $logger = new DefaultAgentLogger();
        }

        $errors = [];

        $endpoint = $input['endpoint'] ?? 'https://api.guard-core.com';
        if (!is_string($endpoint)) {
            $endpoint = '';
        }
        $endpoint = self::normalizeEndpoint($endpoint, $logger);

        $policy = BufferOverflowPolicy::Drop;
        $policyInput = $input['bufferOverflowPolicy']
            ?? $input['buffer_overflow_policy']
            ?? null;
        if ($policyInput !== null) {
            $parsed = BufferOverflowPolicy::tryFromValue($policyInput);
            if ($parsed === null) {
                $errors[] = "bufferOverflowPolicy must be one of 'drop', 'block', 'raise'";
            } else {
                $policy = $parsed;
            }
        }

        $redis = null;
        if (is_array($input['redis'] ?? null)) {
            $redis = RedisConfig::fromArray($input['redis']);
        } elseif (($input['redis'] ?? null) instanceof RedisConfig) {
            $redis = $input['redis'];
        }

        $config = new AgentConfig(
            apiKey: self::stringInput($input, 'apiKey'),
            endpoint: $endpoint,
            projectId: self::optionalStringInput($input, 'projectId', 'project_id'),
            bufferSize: self::intInput($input, 'bufferSize', 'buffer_size', 100),
            flushInterval: self::intInput($input, 'flushInterval', 'flush_interval', 30),
            dynamicRuleInterval: self::intInput($input, 'dynamicRuleInterval', 'dynamic_rule_interval', 300),
            statusInterval: self::intInput($input, 'statusInterval', 'status_interval', 300),
            highWatermarkRatio: self::floatInput($input, 'highWatermarkRatio', 'high_watermark_ratio', 0.8),
            maxConcurrentFlushes: self::intInput($input, 'maxConcurrentFlushes', 'max_concurrent_flushes', 1),
            bufferOverflowPolicy: $policy,
            enableMetrics: self::boolInput($input, 'enableMetrics', 'enable_metrics', true),
            enableEvents: self::boolInput($input, 'enableEvents', 'enable_events', true),
            retryAttempts: self::intInput($input, 'retryAttempts', 'retry_attempts', 3),
            timeout: self::intInput($input, 'timeout', 'timeout', 30),
            backoffFactor: self::floatInput($input, 'backoffFactor', 'backoff_factor', 1.0),
            sensitiveHeaders: self::stringListInput($input, 'sensitiveHeaders', 'sensitive_headers')
                ?? AgentConfig::DEFAULT_SENSITIVE_HEADERS,
            maxPayloadSize: self::intInput($input, 'maxPayloadSize', 'max_payload_size', 1024),
            guardVersion: self::optionalStringInput($input, 'guardVersion', 'guard_version'),
            guardCoreVersion: self::optionalStringInput($input, 'guardCoreVersion', 'guard_core_version'),
            compressionEnabled: self::boolInput($input, 'compressionEnabled', 'compression_enabled', true),
            compressionThreshold: self::intInput($input, 'compressionThreshold', 'compression_threshold', 1024),
            installId: self::optionalStringInput($input, 'installId', 'install_id'),
            installIdPath: self::optionalStringInput($input, 'installIdPath', 'install_id_path'),
            payloadSigningSecret: self::optionalStringInput($input, 'payloadSigningSecret', 'payload_signing_secret'),
            projectEncryptionKey: self::optionalStringInput($input, 'projectEncryptionKey', 'project_encryption_key'),
            onError: ($input['onError'] ?? null) instanceof \Closure ? $input['onError'] : null,
            logger: $logger,
            redis: $redis,
        );

        $errors = array_merge($errors, self::validate($config));
        if ($errors !== []) {
            throw new ConfigException('Invalid agent configuration: ' . implode('; ', $errors));
        }

        return $config;
    }

    /**
     * Validate a resolved config and return a list of human-readable errors,
     * mirroring validate_config (guard_agent/utils.py:281-306) plus the checks
     * the Python config gets from pydantic field constraints.
     *
     * @return list<string>
     */
    public static function validate(AgentConfig $config): array
    {
        $errors = [];

        if ($config->apiKey === '' || strlen($config->apiKey) < 10) {
            $errors[] = 'apiKey must be at least 10 characters long';
        }

        if (preg_match('#^https?://#i', $config->endpoint) !== 1) {
            $errors[] = 'endpoint must be a valid HTTP/HTTPS URL';
        }

        if ($config->bufferSize <= 0) {
            $errors[] = 'bufferSize must be greater than 0';
        }

        if ($config->flushInterval <= 0) {
            $errors[] = 'flushInterval must be greater than 0';
        }

        if ($config->timeout <= 0) {
            $errors[] = 'timeout must be greater than 0';
        }

        if ($config->retryAttempts < 0) {
            $errors[] = 'retryAttempts cannot be negative';
        }

        if ($config->backoffFactor <= 0) {
            $errors[] = 'backoffFactor must be greater than 0';
        }

        if ($config->statusInterval < 60) {
            $errors[] = 'statusInterval must be at least 60 seconds';
        }

        if ($config->dynamicRuleInterval < 60) {
            $errors[] = 'dynamicRuleInterval must be at least 60 seconds';
        }

        if ($config->highWatermarkRatio <= 0 || $config->highWatermarkRatio > 1) {
            $errors[] = 'highWatermarkRatio must be in the range (0, 1]';
        }

        if ($config->maxConcurrentFlushes < 1) {
            $errors[] = 'maxConcurrentFlushes must be at least 1';
        }

        if ($config->compressionThreshold < 0) {
            $errors[] = 'compressionThreshold cannot be negative';
        }

        if ($config->redis !== null) {
            if (preg_match('#^rediss?://#i', $config->redis->url) !== 1) {
                $errors[] = 'redis.url must be a redis:// or rediss:// URL';
            }
            if ($config->redis->commandTimeoutMs <= 0) {
                $errors[] = 'redis.commandTimeoutMs must be greater than 0';
            }
        }

        return $errors;
    }

    /**
     * Normalize the endpoint: require http/https, strip trailing slashes, and
     * strip a legacy "/api/v1" suffix with a one-time warning, mirroring
     * AgentConfig.validate_endpoint (guard_agent/models.py:176-205). The
     * transport already appends versioned paths.
     *
     * @throws ConfigException
     */
    public static function normalizeEndpoint(string $endpoint, AgentLogger $logger): string
    {
        if ($endpoint === '') {
            throw new ConfigException('Endpoint URL cannot be empty');
        }

        $parts = parse_url($endpoint);
        if ($parts === false || !isset($parts['scheme'], $parts['host']) || $parts['scheme'] === '' || $parts['host'] === '') {
            throw new ConfigException('Endpoint must be a valid URL with scheme and domain');
        }

        $scheme = strtolower($parts['scheme']);
        if ($scheme !== 'http' && $scheme !== 'https') {
            throw new ConfigException('Endpoint URL must use http or https scheme');
        }

        $normalized = rtrim($endpoint, '/');
        if (str_ends_with($normalized, '/api/v1')) {
            $stripped = rtrim(substr($normalized, 0, -strlen('/api/v1')), '/');
            if (!self::$endpointSuffixWarned) {
                $logger->warning(
                    "Endpoint '{$endpoint}' ends with '/api/v1'; transport already appends " .
                    "versioned paths. Stripping suffix to '{$stripped}'. Update your config to " .
                    "set the bare host (e.g. 'https://api.guard-core.com')."
                );
                self::$endpointSuffixWarned = true;
            }

            return $stripped;
        }

        return $normalized;
    }

    /** @param array<string, mixed> $input */
    private static function stringInput(array $input, string $key): string
    {
        $value = $input[$key] ?? null;

        return is_string($value) ? $value : '';
    }

    /** @param array<string, mixed> $input */
    private static function optionalStringInput(array $input, string $key, ?string $altKey = null): ?string
    {
        foreach ([$key, $altKey] as $candidate) {
            if ($candidate === null) {
                continue;
            }
            $value = $input[$candidate] ?? null;
            if (is_string($value) && $value !== '') {
                return $value;
            }
        }

        return null;
    }

    /** @param array<string, mixed> $input */
    private static function intInput(array $input, string $key, string $altKey, int $default): int
    {
        foreach ([$key, $altKey] as $candidate) {
            $value = $input[$candidate] ?? null;
            if (is_int($value) || is_float($value)) {
                return (int) $value;
            }
            if (is_string($value) && is_numeric($value)) {
                return (int) $value;
            }
        }

        return $default;
    }

    /** @param array<string, mixed> $input */
    private static function floatInput(array $input, string $key, string $altKey, float $default): float
    {
        foreach ([$key, $altKey] as $candidate) {
            $value = $input[$candidate] ?? null;
            if (is_int($value) || is_float($value)) {
                return (float) $value;
            }
            if (is_string($value) && is_numeric($value)) {
                return (float) $value;
            }
        }

        return $default;
    }

    /** @param array<string, mixed> $input */
    private static function boolInput(array $input, string $key, string $altKey, bool $default): bool
    {
        foreach ([$key, $altKey] as $candidate) {
            $value = $input[$candidate] ?? null;
            if (is_bool($value)) {
                return $value;
            }
            if (is_int($value) && ($value === 0 || $value === 1)) {
                return $value === 1;
            }
        }

        return $default;
    }

    /**
     * @param array<string, mixed> $input
     *
     * @return list<string>|null null keeps the configured defaults
     */
    private static function stringListInput(array $input, string $key, ?string $altKey): ?array
    {
        foreach ([$key, $altKey] as $candidate) {
            if ($candidate === null) {
                continue;
            }
            $value = $input[$candidate] ?? null;
            if (is_array($value)) {
                $list = [];
                foreach ($value as $item) {
                    $list[] = (string) $item;
                }

                return $list;
            }
        }

        return null;
    }
}
