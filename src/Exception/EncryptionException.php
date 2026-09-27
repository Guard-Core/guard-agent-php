<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardAgent\Exception;

/**
 * Base exception for encryption-related errors, mirroring the Python
 * EncryptionError (guard_agent/encryption.py:17-19).
 */
class EncryptionException extends GuardAgentException
{
}
