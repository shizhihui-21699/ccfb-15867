<?php

declare(strict_types=1);

namespace WScan\Support;

/**
 * Domain classification used for allow-listing (analytics/ads) and for
 * spotting injected gambling destinations.
 */
final class Domains
{
    /** Public suffixes that need three labels to reach the registrable name. */
    private const MULTI_LABEL_SUFFIXES = [
        'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
        'com.hk', 'org.hk', 'com.tw', 'com.sg', 'com.my', 'com.au',
        'co.uk', 'org.uk', 'co.jp', 'co.kr', 'co.in',
    ];

    /** TLDs heavily abused by gambling / redirect campaigns in CN sites. */
    private const SUSPICIOUS_TLDS = [
        'vip', 'xyz', 'top', 'cc', 'club', 'win', 'bet', 'icu', 'cyou',
        'shop', 'buzz', 'cam', 'rest', 'bar', 'life', 'pw', 'tk', 'ml', 'ga', 'cf', 'gq',
    ];

    public static function hostFromUrl(string $url): ?string
    {
        $url = trim($url);
        $url = str_replace(['\\/', '&amp;', '&#38;'], ['/', '&', '&'], $url);
        if (str_starts_with($url, '//')) {
            $url = 'http:' . $url;
        }

        $host = parse_url($url, PHP_URL_HOST);
        if (!is_string($host) || $host === '') {
            // Bare domain: example.com/path
            if (preg_match('~^([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})(?::\d+)?(?:[/?#]|$)~i', $url, $m)) {
                $host = $m[1];
            }
        }
        if (!is_string($host) || $host === '') {
            return null;
        }

        return strtolower(rtrim($host, '.'));
    }

    public static function registrable(string $host): string
    {
        $host = strtolower(trim($host, '.'));
        if (self::isIp($host) || !str_contains($host, '.')) {
            return $host;
        }

        $labels = explode('.', $host);
        $count = count($labels);
        foreach (self::MULTI_LABEL_SUFFIXES as $suffix) {
            if (str_ends_with($host, '.' . $suffix) || $host === $suffix) {
                return implode('.', array_slice($labels, -3));
            }
        }

        return implode('.', array_slice($labels, -2));
    }

    public static function isIp(string $host): bool
    {
        return filter_var($host, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * @param list<string> $siteDomains Registrable domains that belong to the site group.
     */
    public static function isInternal(string $host, array $siteDomains): bool
    {
        $reg = self::registrable($host);
        foreach ($siteDomains as $allowed) {
            $allowed = strtolower(trim($allowed));
            if ($allowed === '') {
                continue;
            }
            if ($reg === self::registrable($allowed) || $host === $allowed) {
                return true;
            }
        }

        return false;
    }

    /**
     * Wildcard-aware allow-list matching: "*.baidu.com", "baidu.com" (matches
     * subdomains), "hm.baidu.com" (exact host).
     */
    public static function matchesPattern(string $host, string $pattern): bool
    {
        $host = strtolower($host);
        $pattern = strtolower(trim($pattern));
        if ($pattern === '' || $host === '') {
            return false;
        }
        if ($pattern === '*') {
            return true;
        }
        if (str_starts_with($pattern, '*.')) {
            $suffix = substr($pattern, 2);

            return $host === $suffix || str_ends_with($host, '.' . $suffix);
        }

        return $host === $pattern || str_ends_with($host, '.' . $pattern);
    }

    /**
     * @param list<string> $patterns
     */
    public static function isAllowlisted(string $host, array $patterns): bool
    {
        foreach ($patterns as $pattern) {
            if (self::matchesPattern($host, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Extracts absolute URLs plus protocol-relative URLs from mixed HTML/JS/PHP.
     *
     * @return list<array{url:string,offset:int,host:string,domain:string}>
     */
    public static function extractUrls(string $text): array
    {
        // Normalize escaped slashes commonly found inside JS strings.
        $normalized = str_replace(['\\/', '\\u002f', '\\u002F', '&#x2f;', '&#x2F;', '&#47;'], '/', $text);

        $found = [];
        $pattern = '~(?:https?:)?//[a-z0-9][a-z0-9._\-]*(?::\d+)?(?:[/?#][^\s"\'<>()\[\]{}\\\\]*)?~i';
        if (preg_match_all($pattern, $normalized, $matches, PREG_OFFSET_CAPTURE) !== false) {
            foreach ($matches[0] as [$url, $offset]) {
                $url = rtrim($url, ".,;:!?'\"");
                $host = self::hostFromUrl($url);
                if ($host === null) {
                    continue;
                }
                $found[] = [
                    'url' => $url,
                    'offset' => (int) $offset,
                    'host' => $host,
                    'domain' => self::registrable($host),
                ];
            }
        }

        return $found;
    }

    /**
     * @return array<string, list<string>> domain => sample urls
     */
    public static function domainsIn(string $text, array $allowlist = []): array
    {
        $map = [];
        foreach (self::extractUrls($text) as $hit) {
            $domain = $hit['domain'];
            if ($allowlist !== [] && self::isAllowlisted($hit['host'], $allowlist)) {
                continue;
            }
            $map[$domain] ??= [];
            if (count($map[$domain]) < 3 && !in_array($hit['url'], $map[$domain], true)) {
                $map[$domain][] = $hit['url'];
            }
        }

        return $map;
    }

    public static function hasSuspiciousTld(string $host): bool
    {
        $tld = substr($host, (int) (strrpos($host, '.') ?: 0) + 1);

        return in_array($tld, self::SUSPICIOUS_TLDS, true);
    }

    /**
     * A label that looks machine-generated: 6+ digits, long random alnum, or
     * many hyphens. Gambling redirect domains are usually like this.
     */
    public static function hasGeneratedLabel(string $host): bool
    {
        foreach (explode('.', $host) as $label) {
            if ($label === '') {
                continue;
            }
            if (preg_match('/^\d{5,}$/', $label)) {
                return true;
            }
            // Look past hyphens: "8888bet-vip-77" is generated even though the
            // full label is not pure alphanumeric.
            $compact = str_replace('-', '', $label);
            if (strlen($compact) >= 8
                && preg_match('/^[a-z0-9]+$/i', $compact)
                && preg_match('/\d/', $compact)
                && preg_match('/[a-z]/i', $compact)) {
                return true;
            }
            if (substr_count($label, '-') >= 2) {
                return true;
            }
        }

        return false;
    }
}
