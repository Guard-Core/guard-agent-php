<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardAgent\Exception;

/**
 * Raised when encryption initialization fails; plaintext fallback is
 * forbidden, mirroring the Python EncryptionConfigError
 * (guard_agent/encryption.py:22-24, raised by
 * _transport_lifecycle._init_encryption).
 */
final class EncryptionConfigException extends \RuntimeException
{
}
