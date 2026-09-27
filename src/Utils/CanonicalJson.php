<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardAgent\Utils;

use RenzoFranceschini\GuardAgent\Exception\SerializationException;

/**
 * Canonical JSON serialization for encrypted payloads, byte-identical to
 * Python json.dumps(data, separators=(",", ":"), sort_keys=True) with the
 * ensure_ascii default:
 *
 * - object keys sorted recursively (by byte value, like Python sort_keys)
 * - compact separators, no whitespace
 * - forward slashes left unescaped
 * - non-ASCII and control characters \uXXXX-escaped, with the short \b \f
 *   \n \r \t \\" \\\\ forms Python uses
 *
 * PHP json_encode alone cannot produce this (it preserves array order,
 * escapes slashes by default, and differs on control characters), so the
 * encoder walks the structure itself.
 */
final class CanonicalJson
{
    private function __construct()
    {
    }

    /**
     * @throws SerializationException when a value cannot be represented
     */
    public static function encode(mixed $value): string
    {
        return self::encodeValue($value, 0);
    }

    private static function encodeValue(mixed $value, int $depth): string
    {
        if ($depth > 512) {
            throw new SerializationException('Maximum nesting depth exceeded');
        }
        if ($value === null) {
            return 'null';
        }
        if ($value === true) {
            return 'true';
        }
        if ($value === false) {
            return 'false';
        }
        if (is_int($value)) {
            return (string) $value;
        }
        if (is_float($value)) {
            if (!is_finite($value)) {
                throw new SerializationException('Inf and NaN cannot be JSON-serialized');
            }
            // serialize_precision=-1 (the PHP default) emits the shortest
            // round-trip representation, matching Python repr, including
            // the trailing ".0" Python prints for whole floats.
            try {
                return (string) json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            } catch (\JsonException $exception) {
                throw new SerializationException($exception->getMessage(), previous: $exception);
            }
        }
        if (is_string($value)) {
            return '"' . self::escapeString($value) . '"';
        }
        if (is_array($value)) {
            $isList = array_is_list($value);
            if ($isList) {
                $parts = [];
                foreach ($value as $item) {
                    $parts[] = self::encodeValue($item, $depth + 1);
                }

                return '[' . implode(',', $parts) . ']';
            }
            $pairs = [];
            foreach ($value as $key => $item) {
                $pairs[(string) $key] = self::encodeValue($item, $depth + 1);
            }
            ksort($pairs, SORT_STRING);
            $parts = [];
            foreach ($pairs as $key => $encoded) {
                $parts[] = '"' . self::escapeString($key) . '":' . $encoded;
            }

            return '{' . implode(',', $parts) . '}';
        }
        if ($value instanceof \DateTimeInterface) {
            return '"' . self::escapeString($value->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\\TH:i:s.v\\Z')) . '"';
        }
        if (is_object($value)) {
            // stdClass and other objects encode as maps, matching json_encode.
            return self::encodeValue((array) $value, $depth + 1);
        }

        throw new SerializationException('Value of type ' . get_debug_type($value) . ' is not JSON-serializable');
    }

    /**
     * Escape a string exactly like Python json.dumps with ensure_ascii.
     */
    public static function escapeString(string $text): string
    {
        $out = '';
        $length = strlen($text);
        $offset = 0;
        $replacements = [
            '"' => '\\"',
            '\\' => '\\\\',
            "\x08" => '\\b',
            "\x0C" => '\\f',
            "\n" => '\\n',
            "\r" => '\\r',
            "\t" => '\\t',
        ];
        while ($offset < $length) {
            $byte = $text[$offset];
            $ordinal = ord($byte);
            if ($ordinal < 0x80) {
                $out .= $replacements[$byte] ?? ($ordinal < 0x20 ? sprintf('\\u%04x', $ordinal) : $byte);
                $offset++;
                continue;
            }
            // Multi-byte UTF-8 sequence; decode the code point.
            $char = mb_substr($text, mb_strlen(substr($text, 0, $offset)), 1, 'UTF-8');
            $code = (int) mb_ord($char, 'UTF-8');
            if ($code >= 0x10000) {
                $high = intdiv($code - 0x10000, 0x400) + 0xD800;
                $low = (($code - 0x10000) % 0x400) + 0xDC00;
                $out .= sprintf('\\u%04x\\u%04x', $high, $low);
            } else {
                $out .= sprintf('\\u%04x', $code);
            }
            $offset += strlen($char);
        }

        return $out;
    }
}
