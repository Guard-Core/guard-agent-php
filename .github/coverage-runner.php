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
    // Catches around RedisHandler calls that are themselves total: keys()
    // (196-197, 595-596), delete() (271-272, 289-290), and setKey()
    // (377-378, 425-426, via the persist helpers whose try additionally
    // spans uniqueKey, Json::encode, and SplObjectStorage assignment, none
    // of which throw) each catch every client Throwable inside RedisHandler
    // and degrade to a return value, so no Throwable can reach the buffer's
    // own catch arms.
    'src/EventBuffer/EventBuffer.php' => [196, 197, 271, 272, 289, 290, 377, 378, 425, 426, 595, 596],
    // stop()'s close catch: GuardAgent::$redisHandler is the final
    // RedisHandler (initializeRedis hard-types it) whose close() catches
    // every Throwable (252-253). asMetadataArray/asStringArray fallbacks:
    // the inputs are SecurityEvent::$metadata / SecurityMetric::$tags array
    // properties passed through HeadersRedactor::sanitize, which returns an
    // array for an array input at the top depth (778, 789).
    'src/GuardAgent.php' => [252, 253, 778, 789],
    // read()/write() catch arms over @-suppressed filesystem calls, which
    // return false instead of throwing (76-77, 79, 95-96): is_file($path)
    // true implies a non-empty path, and the PHP 8 ValueErrors in this
    // function family require an empty path, which cannot reach read()'s
    // file_get_contents (is_file('') is false) or write()'s
    // file_put_contents (the mkdir guard returns early for the empty dir).
    'src/Install/InstallId.php' => [76, 77, 79, 95, 96],
    // error_log fallback runs only under a web SAPI (61-62); the stream
    // fallback only fires when STDOUT is undefined AND fopen fails, and the
    // CLI SAPI defines both (68).
    'src/Log/DefaultAgentLogger.php' => [61, 62, 68],
    // new DateTimeImmutable('@' . (string)(int) $value) cannot throw for any
    // int/float epoch: the (int) cast yields an int for every float
    // (NAN/overflow casts emit a diagnostic, not a throw) and '@<int>' is
    // always constructible on the supported 64-bit platforms (44-45).
    'src/Model/WireFormat.php' => [44, 45],
    // The transport-boundary redaction pass never sees arrays there because
    // toWire() casts metadata/tags to objects (SecurityEvent.php:155,
    // SecurityMetric.php:101) and makeRequest's payload always comes from
    // buildBatchWire mapping those toWire() outputs (512-515, 522-525).
    'src/Transport/HttpTransport.php' => [512, 513, 514, 515, 522, 523, 524, 525],
    // json_encode of a finite float with JSON_THROW_ON_ERROR cannot fail:
    // the is_finite guard above rejects Inf/NaN before this call is reached
    // (asserted by the canonical json tests) and a finite float scalar has
    // no depth, UTF-8, or type failure mode (64-65).
    'src/Utils/CanonicalJson.php' => [64, 65],
    // sanitizeValueUnsafe cannot throw for the value domain it accepts
    // (46-47): every operation is a non-throwing type check, arithmetic-free
    // recursion, or pass-through, and its two fallible callees (json_decode
    // at 105, Json::encode at 111) carry their own local catches.
    'src/Utils/HeadersRedactor.php' => [46, 47],
    // json_encode with JSON_THROW_ON_ERROR never returns false (37).
    'src/Utils/Json.php' => [37],
    // phpredis 6 close() returns silently on an already-closed socket; the
    // catch arm exists for older versions that raised RedisException (72).
    'src/Persistence/ExtRedisClient.php' => [72],
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
