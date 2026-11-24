<?php

declare(strict_types=1);

namespace WScan\Scan;

use WScan\Support\Config;
use WScan\Support\Domains;

/**
 * Builds the URL list handed to the dynamic scanner.
 *
 * Sources, in order of preference:
 *   - explicit URLs passed on the command line
 *   - sitemap.xml found at the site root
 *   - same-site links harvested from the home page
 * Crawler-only landing pages are what we want, and those are usually linked
 * from somewhere, so the home page is a good seed.
 */
final class UrlDiscovery
{
    public function __construct(
        private readonly Config $config,
        private readonly HttpClient $http,
    ) {
    }

    /**
     * @param list<string> $seeds
     * @return list<string>
     */
    public function discover(array $seeds, int $limit): array
    {
        $urls = [];
        foreach ($seeds as $seed) {
            $seed = trim($seed);
            if ($seed === '') {
                continue;
            }
            if (!str_starts_with($seed, 'http://') && !str_starts_with($seed, 'https://')) {
                $seed = 'http://' . $seed;
            }
            $urls[$this->canonical($seed)] = true;
        }

        $siteDomains = $this->config->getList('site_domains');
        foreach (array_keys($urls) as $base) {
            if (count($urls) >= $limit) {
                break;
            }
            $this->addSitemap($base, $urls, $limit);
            $this->addHomeLinks($base, $urls, $limit, $siteDomains);
        }

        return array_slice(array_keys($urls), 0, $limit);
    }

    /**
     * Canonicalizes a URL so that `http://h` and `http://h/` (and fragments)
     * are treated as one target and do not double every finding.
     */
    private function canonical(string $url): string
    {
        $url = trim($url);
        // Drop the fragment: it never reaches the server.
        if (($hash = strpos($url, '#')) !== false) {
            $url = substr($url, 0, $hash);
        }
        $parts = parse_url($url);
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
            return $url;
        }
        $out = $parts['scheme'] . '://' . strtolower($parts['host']);
        if (isset($parts['port'])) {
            $out .= ':' . $parts['port'];
        }
        $path = $parts['path'] ?? '/';
        if ($path === '') {
            $path = '/';
        }
        $out .= $path;
        if (isset($parts['query'])) {
            $out .= '?' . $parts['query'];
        }

        return $out;
    }

    /** @param array<string,true> $urls */
    private function addSitemap(string $base, array &$urls, int $limit): void
    {
        $parsed = parse_url($base);
        if (!is_array($parsed) || !isset($parsed['scheme'], $parsed['host'])) {
            return;
        }
        $root = $parsed['scheme'] . '://' . $parsed['host'] . (isset($parsed['port']) ? ':' . $parsed['port'] : '');
        $sitemapUrl = $root . '/sitemap.xml';
        $resp = $this->http->get($sitemapUrl);
        if ($resp['status'] !== 200 || $resp['body'] === '') {
            return;
        }
        if (preg_match_all('/<loc>\s*([^<\s]+)\s*<\/loc>/i', $resp['body'], $m)) {
            foreach ($m[1] as $loc) {
                $loc = html_entity_decode(trim($loc), ENT_QUOTES);
                if (str_starts_with($loc, 'http')) {
                    $urls[$loc] = true;
                }
                if (count($urls) >= $limit) {
                    return;
                }
            }
        }
    }

    /**
     * @param array<string,true> $urls
     * @param list<string> $siteDomains
     */
    private function addHomeLinks(string $base, array &$urls, int $limit, array $siteDomains): void
    {
        $resp = $this->http->get($base);
        if ($resp['status'] !== 200 || $resp['body'] === '') {
            return;
        }

        $parsed = parse_url($base);
        $host = is_array($parsed) ? strtolower((string) ($parsed['host'] ?? '')) : '';
        if ($host === '') {
            return;
        }
        // If no explicit site_domains, treat the seed's registrable domain as ours.
        $domains = $siteDomains !== [] ? $siteDomains : [Domains::registrable($host)];
        $scheme = is_array($parsed) ? ($parsed['scheme'] ?? 'http') : 'http';
        $baseHost = $scheme . '://' . $host;

        if (!preg_match_all('/href\s*=\s*["\']([^"\']+)["\']/i', $resp['body'], $m)) {
            return;
        }

        foreach ($m[1] as $href) {
            $href = html_entity_decode(trim($href), ENT_QUOTES);
            if ($href === '' || str_starts_with($href, '#') || str_starts_with($href, 'javascript:') || str_starts_with($href, 'mailto:')) {
                continue;
            }
            if (str_starts_with($href, '//')) {
                $href = $scheme . ':' . $href;
            } elseif (str_starts_with($href, '/')) {
                $href = $baseHost . $href;
            } elseif (!str_starts_with($href, 'http')) {
                $href = rtrim($baseHost, '/') . '/' . ltrim($href, '/');
            }

            $h = Domains::hostFromUrl($href);
            if ($h === null || !Domains::isInternal($h, $domains)) {
                continue;
            }
            // Only page-like URLs.
            if (preg_match('/\.(?:jpg|jpeg|png|gif|css|js|ico|svg|woff2?|pdf|zip|mp4|mp3)$/i', $href)) {
                continue;
            }
            $urls[$this->canonical($href)] = true;
            if (count($urls) >= $limit) {
                return;
            }
        }
    }
}
