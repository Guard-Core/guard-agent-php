<?php

/**
 * Test-only namespace shadows for the guard-agent-php suite.
 *
 * PHP resolves an unqualified function call inside a namespace against that
 * namespace first and only falls back to the global table, so declaring these
 * functions intercepts every openssl_encrypt / curl_init call made by the
 * matching src/ namespace. By default the shims forward to the global
 * functions untouched; a test flips the matching $GLOBALS flag to force the
 * failure arms (openssl_encrypt returning false, curl_init returning false)
 * that real infrastructure cannot produce on demand.
 *
 * Required by bin/test_agent.php; loaded once per suite process. The mock
 * and fake servers run as separate processes and are unaffected.
 */

namespace RenzoFranceschini\GuardAgent\Encryption {
    /**
     * Mirrors the global openssl_encrypt signature; forwards unless the
     * failure flag is set, in which case the "returns false" arm of
     * PayloadEncryptor::encrypt (and, transitively, verifyKey) is exercised.
     *
     * @param-out string $tag_output
     */
    function openssl_encrypt(string $data, string $cipher_algo, string $passphrase, int $options = 0, string $iv = '', &$tag_output = null, string $aad = '', int $tag_length = 16): string|false
    {
        if ($GLOBALS['__guard_test_openssl_encrypt_fails'] ?? false) {
            return false;
        }

        return \openssl_encrypt($data, $cipher_algo, $passphrase, $options, $iv, $tag_output, $aad, $tag_length);
    }
}

namespace RenzoFranceschini\GuardAgent\Transport {
    /**
     * Mirrors the global curl_init signature; forwards unless the failure
     * flag is set, in which case the handle check in
     * HttpTransport::execute is exercised.
     *
     * @return \CurlHandle|false
     */
    function curl_init(?string $url = null)
    {
        if ($GLOBALS['__guard_test_curl_init_fails'] ?? false) {
            return false;
        }

        return \curl_init($url);
    }
}
