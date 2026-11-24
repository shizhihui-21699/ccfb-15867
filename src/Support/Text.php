<?php

declare(strict_types=1);

namespace WScan\Support;

/**
 * Text helpers shared by every detector.
 *
 * Everything here must be safe to run against binary-ish input (cached pages,
 * serialized DB fields, gzinflate output), so functions avoid assuming UTF-8
 * unless they explicitly say otherwise.
 */
final class Text
{
    /** Hard cap for any single string we analyse (bytes). */
    public const MAX_ANALYZE_BYTES = 2_097_152;

    public static function truncateForAnalysis(string $text): string
    {
        if (strlen($text) <= self::MAX_ANALYZE_BYTES) {
            return $text;
        }

        return substr($text, 0, self::MAX_ANALYZE_BYTES);
    }

    public static function lineAt(string $text, int $offset): int
    {
        if ($offset <= 0) {
            return 1;
        }
        $offset = min($offset, strlen($text));

        return substr_count(substr($text, 0, $offset), "\n") + 1;
    }

    /**
     * A compact, single-line evidence excerpt around an offset.
     *
     * Offsets are byte offsets. The window is widened to valid UTF-8 boundaries
     * so we never produce a half-character (mojibake) in the report.
     */
    public static function snippet(string $text, int $offset, int $before = 70, int $after = 110): string
    {
        $len = strlen($text);
        $offset = max(0, min($offset, $len));
        $start = max(0, $offset - $before);
        $end = min($len, $offset + $after);

        // Expand to character boundaries.
        while ($start > 0 && (ord($text[$start]) & 0xC0) === 0x80) {
            $start--;
        }
        while ($end < $len && (ord($text[$end]) & 0xC0) === 0x80) {
            $end++;
        }

        $excerpt = substr($text, $start, $end - $start);
        $excerpt = self::toUtf8($excerpt);
        $excerpt = preg_replace('/\s+/u', ' ', $excerpt) ?? $excerpt;

        return trim($excerpt);
    }

    public static function toUtf8(string $text): string
    {
        if ($text === '' || mb_check_encoding($text, 'UTF-8')) {
            return $text;
        }

        $converted = @mb_convert_encoding($text, 'UTF-8', 'GB18030,GBK,BIG5,ISO-8859-1');
        if (is_string($converted) && mb_check_encoding($converted, 'UTF-8')) {
            return $converted;
        }

        // Last resort: drop invalid sequences instead of poisoning the report.
        return mb_convert_encoding($text, 'UTF-8', 'UTF-8');
    }

    public static function printableRatio(string $text): float
    {
        $len = strlen($text);
        if ($len === 0) {
            return 1.0;
        }

        $printable = preg_match_all('/[\x09\x0A\x0D\x20-\x7E]/', $text);
        // Multi-byte UTF-8 counts as printable text too.
        $high = preg_match_all('/[\xC2-\xF4][\x80-\xBF]+/', $text);

        return min(1.0, (($printable ?: 0) + ($high ?: 0) * 3) / $len);
    }

    public static function looksBinary(string $text): bool
    {
        if ($text === '') {
            return false;
        }
        if (str_contains($text, "\0")) {
            return true;
        }

        return self::printableRatio($text) < 0.75;
    }

    public static function entropy(string $text): float
    {
        $len = strlen($text);
        if ($len === 0) {
            return 0.0;
        }

        $counts = count_chars($text, 1);
        $entropy = 0.0;
        foreach ($counts as $count) {
            $p = $count / $len;
            $entropy -= $p * log($p, 2);
        }

        return $entropy;
    }

    public static function normalizeSpace(string $text): string
    {
        $text = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]+/', ' ', $text) ?? $text;

        return trim(preg_replace('/\s+/u', ' ', $text) ?? $text);
    }

    /**
     * Canonical form for differential comparisons: strips volatile tokens
     * (timestamps, nonces, counters) that legitimately change per request.
     */
    public static function normalizeForDiff(string $text): string
    {
        $text = strtolower($text);
        $text = preg_replace('/<!--.*?-->/s', '', $text) ?? $text;
        $text = preg_replace('#<script\b[^>]*>.*?</script>#is', '<script></script>', $text) ?? $text;
        $text = preg_replace('#<style\b[^>]*>.*?</style>#is', '<style></style>', $text) ?? $text;
        $text = preg_replace('/\b\d{9,}\b/', '#n#', $text) ?? $text;
        $text = preg_replace('/\b[0-9a-f]{16,}\b/', '#h#', $text) ?? $text;
        $text = preg_replace('/\bv?\d+(?:\.\d+)+\b/', '#v#', $text) ?? $text;
        $text = preg_replace('/\b\d{4}-\d{2}-\d{2}[ t]\d{2}:\d{2}(?::\d{2})?\b/', '#t#', $text) ?? $text;

        return self::normalizeSpace($text);
    }

    /**
     * Token-set Jaccard similarity, robust to reordered markup. Used by the
     * dynamic scanner to decide whether two visitor profiles saw the same page.
     */
    public static function similarity(string $a, string $b): float
    {
        $ta = self::tokenSet($a);
        $tb = self::tokenSet($b);
        if ($ta === [] && $tb === []) {
            return 1.0;
        }
        $intersect = count(array_intersect_key($ta, $tb));
        $union = count($ta + $tb);

        return $union === 0 ? 1.0 : $intersect / $union;
    }

    /** @return array<string,true> */
    private static function tokenSet(string $text): array
    {
        $text = self::normalizeForDiff($text);
        $parts = preg_split('/[\s<>"\']+/u', $text, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        $set = [];
        foreach ($parts as $part) {
            if (strlen($part) < 2) {
                continue;
            }
            $set[substr($part, 0, 64)] = true;
            if (count($set) >= 4000) {
                break;
            }
        }

        return $set;
    }

    public static function isCjk(string $text): bool
    {
        return preg_match('/[\x{4e00}-\x{9fff}]/u', $text) === 1;
    }

    /**
     * Decodes a backslash/JS/PHP escaped sequence such as \x68\x74 or h.
     */
    public static function decodeEscapes(string $text): string
    {
        $text = preg_replace_callback('/\\\\x([0-9a-fA-F]{2})/', static fn (array $m): string => chr((int) hexdec($m[1])), $text) ?? $text;

        return preg_replace_callback('/\\\\u([0-9a-fA-F]{4})/', static function (array $m): string {
            $code = (int) hexdec($m[1]);
            if ($code < 0x80) {
                return chr($code);
            }

            return mb_chr($code, 'UTF-8') ?: '';
        }, $text) ?? $text;
    }
}
