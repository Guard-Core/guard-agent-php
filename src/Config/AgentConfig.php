<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardAgent\Config;

use RenzoFranceschini\GuardAgent\Log\AgentLogger;

/**
 * Resolved, validated agent configuration, mirroring AgentConfig
 * (guard_agent/models.py:56-205) with camelCase field names (TypeScript-port
 * convention). Validation runs at resolve() time and raises ConfigException
 * listing every problem, mirroring GuardAgentHandler.__init__ raising
 * ValueError (guard_agent/client.py:72-74).
 */
final class AgentConfig
{
    /** Header names excluded from telemetry metadata/tags by default. */
    public const DEFAULT_SENSITIVE_HEADERS = ['authorization', 'proxy-authorization', 'cookie', 'x-api-key'];

    /**
     * @param list<string> $sensitiveHeaders
     * @param \Closure(string, \Throwable, array<string, mixed>): void|null $onError
     */
    public function __construct(
        public readonly string $apiKey,
        public readonly string $endpoint,
        public readonly ?string $projectId = null,
        public readonly int $bufferSize = 100,
        public readonly int $flushInterval = 30,
        /** Dynamic rule poll interval in seconds (minimum 60). */
        public readonly int $dynamicRuleInterval = 300,
        public readonly int $statusInterval = 300,
        public readonly float $highWatermarkRatio = 0.8,
        public readonly int $maxConcurrentFlushes = 1,
        public readonly BufferOverflowPolicy $bufferOverflowPolicy = BufferOverflowPolicy::Drop,
        public readonly bool $enableMetrics = true,
        public readonly bool $enableEvents = true,
        public readonly int $retryAttempts = 3,
        public readonly int $timeout = 30,
        public readonly float $backoffFactor = 1.0,
        public readonly array $sensitiveHeaders = self::DEFAULT_SENSITIVE_HEADERS,
        public readonly int $maxPayloadSize = 1024,
        public readonly ?string $guardVersion = null,
        public readonly ?string $guardCoreVersion = null,
        public readonly bool $compressionEnabled = true,
        public readonly int $compressionThreshold = 1024,
        public readonly ?string $installId = null,
        public readonly ?string $installIdPath = null,
        public readonly ?string $payloadSigningSecret = null,
        public readonly ?string $projectEncryptionKey = null,
        public readonly ?\Closure $onError = null,
        public readonly ?AgentLogger $logger = null,
        public readonly ?RedisConfig $redis = null,
    ) {
    }
}
