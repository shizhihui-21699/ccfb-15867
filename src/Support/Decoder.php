<?php

declare(strict_types=1);

namespace WScan\Support;

/**
 * Recursive de-obfuscator.
 *
 * Malware in old PHP CMS deployments is typically wrapped several layers deep:
 *
 *   eval(gzinflate(base64_decode('...')));
 *   document.write(unescape('%3Cscript%3E...'));
 *   \x65\x76\x61\x6c(...)
 *   fromCharCode(104,116,116,112,...)
 *
 * This class peels those layers so the detectors see the plaintext payload.
 * Every step is bounded: depth, output size and expansion ratio are capped so a
 * zip bomb or a self-recursive decoder cannot hang the scan.
 */
final class Decoder
{
    private const MAX_DEPTH = 8;
    private const MAX_OUTPUT_BYTES = 4_194_304;
    private const MAX_RATIO = 200;
    /** Minimum length before an encoded blob is worth decoding. */
    private const MIN_BLOB = 16;

    /**
     * Returns the decoded variants of a string (original included), each with
     * the chain of transforms that produced it.
     *
     * @return list<array{text:string, chain:list<string>}>
     */
    public static function layers(string $input): array
    {
        $results = [];
        $seen = [];
        $queue = [['text' => Text::truncateForAnalysis($input), 'chain' => []]];
        $budget = self::MAX_OUTPUT_BYTES;

        while ($queue !== []) {
            /** @var array{text:string,chain:list<string>} $current */
            $current = array_shift($queue);
            $text = $current['text'];
            $chain = $current['chain'];

            $key = md5(substr($text, 0, 4096) . '|' . strlen($text));
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
            $results[] = $current;

            if (count($chain) >= self::MAX_DEPTH || $budget <= 0) {
                continue;
            }

            foreach (self::nextLayer($text) as $label => $decoded) {
                $decoded = trim($decoded);
                if (strlen($decoded) < 8) {
                    continue;
                }
                if (strlen($text) > 0) {
                    $ratio = strlen($decoded) / max(1, strlen($text));
                    if ($ratio > self::MAX_RATIO && strlen($decoded) > 65536) {
                        continue; // likely a decompression bomb
                    }
                }
                $budget -= strlen($decoded);
                if ($budget <= 0) {
                    break;
                }
                $queue[] = ['text' => $decoded, 'chain' => [...$chain, $label]];
            }
        }

        return $results;
    }

    /**
     * Produces every plausible one-step decoding of the input.
     *
     * @return array<string,string> label => decoded text
     */
    public static function nextLayer(string $text): array
    {
        $out = [];

        // 1. Hex/unicode escape sequences (\x68, h).
        if (preg_match('/\\\\x[0-9a-fA-F]{2}|\\\\u[0-9a-fA-F]{4}/', $text)) {
            $out['escapes'] = Text::decodeEscapes($text);
        }

        // 2. URL encoding (%3Cscript...). Only when it actually reduces encoding.
        if (preg_match('/%[0-9a-fA-F]{2}/', $text)) {
            $decoded = rawurldecode(str_replace('+', '%20', $text));
            if ($decoded !== $text) {
                $out['urldecode'] = $decoded;
            }
        }

        // 3. JS String.fromCharCode(...) and PHP chr chains.
        if (preg_match('/fromCharCode\s*\(([^)]*)\)/i', $text, $m)) {
            $codes = array_filter(array_map('intval', preg_split('/[,\s]+/', $m[1]) ?: []));
            if ($codes !== []) {
                $out['fromCharCode'] = self::codesToText($codes);
            }
        }

        // 4. base64 blobs (nested inside base64_decode/gzinflate/atob calls or as literals).
        foreach (self::findBase64Blobs($text) as $i => $blob) {
            $decoded = base64_decode($blob, true);
            if ($decoded === false || strlen($decoded) < 8) {
                continue;
            }
            $out['base64#' . $i] = $decoded;

            // 5. gzinflate / gzuncompress / zlib payloads on top of base64.
            $inflated = self::tryInflate($decoded);
            if ($inflated !== null) {
                $out['base64+gzinflate#' . $i] = $inflated;
            }
        }

        // 6. Bare gzinflate/gzuncompress on the raw text.
        if (preg_match('/\bgz(?:inflate|uncompress|decode)\s*\(\s*[\'"]([^\'"]{16,})[\'"]/i', $text, $m)) {
            $inflated = self::tryInflate($m[1]);
            if ($inflated !== null) {
                $out['gzinflate-arg'] = $inflated;
            }
        }

        // 7. str_rot13, strrev, str_replace chains common in PHP webshells.
        if (preg_match('/\bstr_rot13\s*\(\s*[\'"]([^\'"]{16,})[\'"]/i', $text, $m)) {
            $out['rot13'] = str_rot13($m[1]);
        }
        if (preg_match('/\bstrrev\s*\(\s*[\'"]([^\'"]{16,})[\'"]/i', $text, $m)) {
            $out['strrev'] = strrev($m[1]);
        }

        // 8. Hex string of the form "68747470..." (long even-length hex).
        if (preg_match('/[\'"]((?:[0-9a-fA-F]{2}){12,})[\'"]/', $text, $m)) {
            $decoded = @hex2bin($m[1]);
            if (is_string($decoded) && $decoded !== '') {
                $out['hex2bin'] = $decoded;
            }
        }

        // 9. Unicode \\uXXXX already covered; handle HTML entity storms.
        if (preg_match_all('/&#(?:x[0-9a-fA-F]+|\d+);/', $text, $mm) > 20) {
            $out['html-entities'] = html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }

        return $out;
    }

    /** @param list<int> $codes */
    private static function codesToText(array $codes): string
    {
        $text = '';
        foreach ($codes as $code) {
            if ($code < 0 || $code > 0x10FFFF) {
                continue;
            }
            $text .= ($code < 0x80) ? chr($code) : (mb_chr($code, 'UTF-8') ?: '');
        }

        return $text;
    }

    /** @return list<string> */
    private static function findBase64Blobs(string $text): array
    {
        $blobs = [];

        // Prefer explicit arguments: base64_decode('...'), atob('...').
        if (preg_match_all('/\b(?:base64_decode|atob|decodeURIComponent)\s*\(\s*[\'"]([A-Za-z0-9+\/=\r\n]{20,})[\'"]/i', $text, $m)) {
            foreach ($m[1] as $blob) {
                $blobs[] = preg_replace('/\s+/', '', $blob) ?? $blob;
            }
        }

        // Long standalone base64-looking literals.
        if (preg_match_all('/[\'"]([A-Za-z0-9+\/]{40,}={0,2})[\'"]/', $text, $m)) {
            foreach ($m[1] as $blob) {
                if (strlen($blob) % 4 === 0 && preg_match('/[A-Z]/', $blob) && preg_match('/[a-z]/', $blob)) {
                    $blobs[] = $blob;
                }
            }
        }

        $unique = [];
        foreach ($blobs as $blob) {
            if (strlen($blob) < self::MIN_BLOB) {
                continue;
            }
            if (!array_key_exists($blob, $unique)) {
                $unique[$blob] = true;
            }
        }

        return array_keys($unique);
    }

    private static function tryInflate(string $data): ?string
    {
        $candidates = [$data];
        // Some payloads are raw-deflate; some keep the gzip/zlib header.
        foreach ([@gzuncompress($data), @gzinflate($data), @gzdecode($data)] as $attempt) {
            if (is_string($attempt) && $attempt !== '') {
                $candidates[] = $attempt;
            }
        }

        // Try stripping a leading b64-decoded zlib header byte mismatch.
        foreach (['gzuncompress', 'gzinflate', 'gzdecode'] as $fn) {
            $attempt = @$fn(substr($data, 2));
            if (is_string($attempt) && $attempt !== '') {
                $candidates[] = $attempt;
            }
        }

        foreach ($candidates as $candidate) {
            if ($candidate !== $data && strlen($candidate) > 8 && !Text::looksBinary($candidate)) {
                return $candidate;
            }
        }

        return null;
    }

    /**
     * Convenience: returns all decoded texts (deduplicated) for detectors that
     * just want to regex over every plausible plaintext.
     *
     * @return list<array{text:string, chain:list<string>}>
     */
    public static function decodeAll(string $input): array
    {
        $out = [];
        $seen = [];
        foreach (self::layers($input) as $layer) {
            $key = md5($layer['text']);
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
            $out[] = $layer;
        }

        return $out;
    }
}
