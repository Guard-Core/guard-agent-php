<?php

/**
 * Scripted RESP fake server for StreamRedisClient coverage, run as a separate
 * `php` process by bin/test_agent.php (same harness style as mock_server.php).
 *
 * Env:
 * - FAKE_REDIS_CONTROL_FILE: JSON {"mode": "...", "script": [...]} re-read on
 *   every accepted connection:
 *   - mode "script" (default): each script item is one RESP reply line (CRLF
 *     appended), consumed in order, one per received command; an item that is
 *     itself a list writes one line per element (multi-line replies such as
 *     KEYS arrays). When the queue runs dry the connection is dropped.
 *   - mode "close": accept and immediately close (client sees EOF on read).
 *   - mode "rst": accept and close with SO_LINGER 0 (abortive RST, so the
 *     client's next write fails). Requires ext-sockets; without it behaves
 *     like "close".
 *   - mode "hang": accept and sleep, never replying (client read timeout).
 * - FAKE_REDIS_PORT: TCP port to bind on 127.0.0.1.
 */

declare(strict_types=1);

$controlFile = getenv('FAKE_REDIS_CONTROL_FILE');
$port = (int) (getenv('FAKE_REDIS_PORT') ?: 0);
if ($controlFile === false || $controlFile === '') {
    fwrite(STDERR, "fake redis: FAKE_REDIS_CONTROL_FILE not set\n");
    exit(1);
}

$server = @stream_socket_server("tcp://127.0.0.1:{$port}", $errno, $errstr);
if ($server === false) {
    fwrite(STDERR, "fake redis: cannot bind: {$errstr}\n");
    exit(1);
}

while (($conn = @stream_socket_accept($server, 60)) !== false) {
    // Readiness probes connect and close without sending a command; get out
    // of the way fast so the single-threaded loop never stalls on one.
    stream_set_timeout($conn, 0, 500_000);
    $first = @fgets($conn);
    if ($first === false || trim($first) === '') {
        fclose($conn);
        continue;
    }
    $control = readControl($controlFile);
    $mode = (string) ($control['mode'] ?? 'script');
    if ($mode === 'hang') {
        sleep(30);
        fclose($conn);
        continue;
    }
    if ($mode === 'partial') {
        // A reply line that never terminates: the client's fgets blocks until
        // its stream timeout fires with data already buffered.
        fwrite($conn, '+PON');
        sleep(30);
        fclose($conn);
        continue;
    }
    if ($mode === 'close') {
        fclose($conn);
        continue;
    }
    if ($mode === 'halfclose') {
        // Shut down the write side only: the client's write keeps succeeding
        // (no RST) while its next read hits a deterministic EOF.
        @stream_socket_shutdown($conn, STREAM_SHUT_WR);
        fgets($conn, 2);
        fclose($conn);
        continue;
    }
    $script = is_array($control['script'] ?? null) ? $control['script'] : [];
    $index = 0;
    while (($line = fgets($conn)) !== false) {
        if ($index >= count($script)) {
            break;
        }
        $reply = $script[$index++];
        foreach ((array) $reply as $replyLine) {
            fwrite($conn, $replyLine . "\r\n");
        }
    }
    if (($control['mode'] ?? 'script') === 'rst-after-reply') {
        // Abortive close (RST) on the established connection so the client's
        // next write fails with EPIPE.
        if (function_exists('socket_import_stream')) {
            $socket = socket_import_stream($conn);
            if ($socket !== false) {
                socket_set_option($socket, SOL_SOCKET, SO_LINGER, ['l_onoff' => 1, 'l_linger' => 0]);
            }
        }
    }
    fclose($conn);
}

function readControl(string $controlFile): array
{
    $decoded = json_decode((string) file_get_contents($controlFile), true);

    return is_array($decoded) ? $decoded : [];
}
