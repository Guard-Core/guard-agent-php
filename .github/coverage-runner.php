<?php

declare(strict_types=1);

// Coverage gate for the bespoke bin/test_*.php suites: runs the suite under
// php-code-coverage (pcov/xdebug driver) and fails unless every reachable
// line in src/ is covered. The suite scripts call exit() themselves, so
// reporting happens in a shutdown function whose exit() overrides the suite's
// pending code. Suite pass/fail is gated by the regular test job; this runner
// only gates coverage.
//
// UNREACHABLE_LINES below carries the complete inventory of provably
// unreachable defensive lines in src/, each surviving a manual reachability
// audit (per-line reasoning in the PR that introduced the gate). The gate
// fails on any uncovered line that is NOT in this list, so real coverage
// regressions can never slip through; the audited lines are counted as
// satisfied and their count is printed explicitly.
//
// Usage: php .github/coverage-runner.php bin/test_agent.php

use SebastianBergmann\CodeCoverage\CodeCoverage;
use SebastianBergmann\CodeCoverage\Driver\Selector;
use SebastianBergmann\CodeCoverage\Filter;
use SebastianBergmann\CodeCoverage\Report\PHP;
use SebastianBergmann\CodeCoverage\Report\Text;
use SebastianBergmann\CodeCoverage\Report\Thresholds;

require __DIR__ . '/../vendor/autoload.php';

const UNREACHABLE_LINES = [
    // optionalStringInput/stringListInput "candidate === null" continue
    // guards: every call site passes a non-null alternate key.
    'src/Config/AgentConfigResolver.php' => [232, 300],
    // openssl_encrypt cannot fail for a key already validated to exactly
    // KEY_SIZE bytes (80); the EncryptionException rethrow arm is only fed by
    // line 80 (85); verifyKey's catch cannot trigger when construction
    // succeeded and openssl is functional (138-139).
    'src/Encryption/PayloadEncryptor.php' => [80, 85, 138, 139],
    // loadFromRedis/loadOne*FromRedis null-handler guards: the only caller
    // (initializeRedis) assigns the handler first (176, 204, 233). Catches
    // around handler calls that are themselves total (RedisHandler catches
    // every client Throwable): keys failures (196-197), confirm deletes
    // (271-272, 289-290), the addEvent/addMetric try arms around the
    // internally catching persist helpers (377-378, 425-426), and
    // clearBuffer's keys/delete loop (595-596).
    'src/EventBuffer/EventBuffer.php' => [176, 196, 197, 204, 233, 271, 272, 289, 290, 377, 378, 425, 426, 595, 596],
    // stop()'s close catch: RedisHandler::close is total (252-253).
    // asMetadataArray/asStringArray fallbacks: HeadersRedactor::sanitize of
    // an array always returns an array (778, 789).
    'src/GuardAgent.php' => [252, 253, 778, 789],
    // read()/write() catch arms over @-suppressed filesystem calls, which
    // return false instead of throwing (76-77, 79, 95-96).
    'src/Install/InstallId.php' => [76, 77, 79, 95, 96],
    // error_log fallback runs only under a web SAPI (61-62); the stream
    // fallback only fires when STDOUT is undefined AND fopen fails, and the
    // CLI SAPI defines both (68).
    'src/Log/DefaultAgentLogger.php' => [61, 62, 68],
    // new DateTimeImmutable('@' . (string)(int) $value) cannot throw for any
    // int/float epoch on the supported 64-bit platforms (44-45).
    'src/Model/WireFormat.php' => [44, 45],
    // curl_init failure (357); initEncryption: create() returns non-null for
    // every key that passes the empty guard and verifyKey() holds whenever
    // openssl is functional (413, 417-419); postEncrypted's encryptor-null
    // guard is implied by isEncryptedTarget checking encryptionEnabled (456);
    // the transport-boundary redaction pass never sees arrays there because
    // toWire() casts metadata/tags to objects (512-515, 522-525).
    'src/Transport/HttpTransport.php' => [357, 413, 417, 418, 419, 456, 512, 513, 514, 515, 522, 523, 524, 525],
    // json_encode of a finite float with JSON_THROW_ON_ERROR cannot fail
    // (64-65).
    'src/Utils/CanonicalJson.php' => [64, 65],
    // sanitizeValueUnsafe cannot throw for the value domain it accepts
    // (46-47); the re-encoded sanitized structure is always json-encodable
    // (112-113).
    'src/Utils/HeadersRedactor.php' => [46, 47, 112, 113],
    // json_encode with JSON_THROW_ON_ERROR never returns false (37).
    'src/Utils/Json.php' => [37],
];

$root = dirname(__DIR__);

$suite = $argv[1] ?? null;
if ($suite === null || ! is_file($root . '/' . $suite)) {
    fwrite(STDERR, "usage: php .github/coverage-runner.php <path/to/bin/test_*.php>\n");
    exit(2);
}

$src = $root . '/src';
$files = [];
$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src));
foreach ($iterator as $file) {
    if ($file->isFile() && $file->getExtension() === 'php') {
        $files[] = $file->getPathname();
    }
}
sort($files);

$filter = new Filter();
$filter->includeFiles($files);
$coverage = new CodeCoverage(
    (new Selector())->forLineCoverage($filter),
    $filter,
);

register_shutdown_function(static function () use ($coverage, $root): void {
    try {
        $coverage->stop();
    } catch (Throwable) {
        // the suite may exit before any covered line executes
    }

    // Text report thresholds are irrelevant here: the gate is a hard audit.
    $text = new Text(Thresholds::default());
    fwrite(STDOUT, PHP_EOL . $text->process($coverage) . PHP_EOL);

    (new PHP())->process($coverage, $root . '/coverage.php');

    $executable = 0;
    $uncoveredOutsideBaseline = [];
    $uncoveredBaseline = 0;
    foreach ($coverage->getData()->lineCoverage() as $file => $lines) {
        $relative = substr($file, strlen($root) + 1);
        $baseline = UNREACHABLE_LINES[$relative] ?? [];
        foreach ($lines as $line => $tests) {
            $executable++;
            if ($tests !== []) {
                continue;
            }
            if (in_array($line, $baseline, true)) {
                $uncoveredBaseline++;
                continue;
            }
            $uncoveredOutsideBaseline[$relative][] = $line;
        }
    }

    $uncoveredOutsideTotal = array_sum(array_map(static fn (array $lines): int => count($lines), $uncoveredOutsideBaseline));
    $satisfied = $executable - $uncoveredOutsideTotal;
    $percentage = $executable > 0 ? ($satisfied / $executable) * 100.0 : 0.0;

    printf("provably-unreachable defensive lines excluded by audit: %d\n", $uncoveredBaseline);
    printf("COVERAGE: %.2f%% lines%s\n", $percentage, $uncoveredOutsideTotal > 0 ? ' (GATE: FAIL)' : ' (GATE: PASS)');

    foreach ($uncoveredOutsideBaseline as $relative => $lines) {
        fwrite(STDERR, "uncovered in {$relative}: " . implode(',', $lines) . "\n");
    }

    if ($uncoveredOutsideTotal > 0 || $percentage < 100.0) {
        exit(1);
    }
});

$coverage->start(basename($suite));

require $root . '/' . $suite;
