<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardAgent\Encryption;

use RenzoFranceschini\GuardAgent\Exception\EncryptionException;
use RenzoFranceschini\GuardAgent\Utils\CanonicalJson;

/**
 * AES-256-GCM payload encryption, mirroring guard_agent/encryption.py
 * byte-for-byte on the wire:
 *
 * - 256-bit keys, urlsafe-base64-encoded (padded, like Python
 *   base64.urlsafe_b64encode), supplied by the core backend
 * - canonical JSON plaintext (CanonicalJson: sorted keys, compact
 *   separators, ensure_ascii escaping)
 * - a fresh 12-byte random nonce prefixes every ciphertext, the 16-byte
 *   GCM auth tag follows the ciphertext (OpenSSL's aes-256-gcm framing
 *   matches Python cryptography's AESGCM)
 * - the combined blob is padded urlsafe base64 for transmission
 * - an optional associated-data string authenticates without encryption
 *
 * Requires ext-openssl (PHP >= 7.1 for AES-GCM support).
 */
final class PayloadEncryptor
{
    public const NONCE_SIZE = 12;

    public const KEY_SIZE = 32;

    private const TAG_SIZE = 16;

    private string $keyBytes;

    public function __construct(string $projectKey)
    {
        if ($projectKey === '') {
            throw new EncryptionException('Project key cannot be empty');
        }

        $keyBytes = self::decodeUrlsafeBase64($projectKey);
        if ($keyBytes === false) {
            throw new EncryptionException('Invalid project key format: invalid base64');
        }
        if (strlen($keyBytes) !== self::KEY_SIZE) {
            throw new EncryptionException(
                sprintf('Invalid key size: %d bytes, expected %d', strlen($keyBytes), self::KEY_SIZE)
            );
        }
        $this->keyBytes = $keyBytes;
    }

    /**
     * Encrypt a telemetry payload. Returns the padded urlsafe-base64
     * nonce || ciphertext || tag string, byte-compatible with the Python
     * agent's PayloadEncryptor.encrypt.
     *
     * @param array<string, mixed> $data
     *
     * @throws EncryptionException
     */
    public function encrypt(array $data, ?string $associatedData = null): string
    {
        try {
            $json = CanonicalJson::encode($data);
            $nonce = random_bytes(self::NONCE_SIZE);
            $tag = '';
            $ciphertext = openssl_encrypt(
                $json,
                'aes-256-gcm',
                $this->keyBytes,
                OPENSSL_RAW_DATA,
                $nonce,
                $tag,
                $associatedData ?? '',
                self::TAG_SIZE
            );
            if ($ciphertext === false || $tag === '') {
                throw new EncryptionException('Failed to encrypt payload: openssl_encrypt failed');
            }

            return self::encodeUrlsafeBase64($nonce . $ciphertext . $tag);
        } catch (EncryptionException $exception) {
            throw $exception;
        } catch (\Throwable $error) {
            throw new EncryptionException('Failed to encrypt payload: ' . $error->getMessage(), previous: $error);
        }
    }

    /**
     * Decrypt an encrypted payload (primarily for testing; in normal
     * operation only the core backend decrypts).
     *
     * @return array<string, mixed>
     *
     * @throws EncryptionException when decryption fails or data is tampered
     */
    public function decrypt(string $encryptedData, ?string $associatedData = null): array
    {
        $combined = self::decodeUrlsafeBase64($encryptedData);
        if ($combined === false || strlen($combined) < self::NONCE_SIZE + self::TAG_SIZE) {
            throw new EncryptionException('Invalid or tampered payload');
        }
        $nonce = substr($combined, 0, self::NONCE_SIZE);
        $tag = substr($combined, -self::TAG_SIZE);
        $ciphertext = substr($combined, self::NONCE_SIZE, -self::TAG_SIZE);
        $plaintext = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $this->keyBytes,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $associatedData ?? ''
        );
        if ($plaintext === false) {
            throw new EncryptionException('Invalid or tampered payload');
        }
        $parsed = json_decode($plaintext, true);
        if (!is_array($parsed) || array_is_list($parsed)) {
            throw new EncryptionException('Invalid or tampered payload');
        }

        return $parsed;
    }

    /**
     * Verify that the encryption key is valid with an encrypt/decrypt
     * round trip (mirrors verify_key).
     */
    public function verifyKey(): bool
    {
        try {
            $testData = ['test' => 'verification'];

            return $this->decrypt($this->encrypt($testData)) === $testData;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Factory: returns null when no key is configured; throws
     * EncryptionException when a key is provided but invalid (mirrors
     * create_encryptor).
     */
    public static function create(?string $projectKey): ?self
    {
        if ($projectKey === null || $projectKey === '') {
            return null;
        }

        return new self($projectKey);
    }

    /**
     * Decode padded or unpadded urlsafe base64 (Python urlsafe_b64decode
     * requires padding; Node and PHP callers may omit it, so accept both).
     */
    private static function decodeUrlsafeBase64(string $text): string|false
    {
        $standard = strtr($text, ['-' => '+', '_' => '/']);
        $pad = strlen($standard) % 4;
        if ($pad > 0) {
            $standard .= str_repeat('=', 4 - $pad);
        }

        return base64_decode($standard, true);
    }

    /**
     * Encode padded urlsafe base64, matching Python
     * base64.urlsafe_b64encode (PHP base64_encode is already padded).
     */
    private static function encodeUrlsafeBase64(string $bytes): string
    {
        return strtr(base64_encode($bytes), ['+' => '-', '/' => '_']);
    }
}
