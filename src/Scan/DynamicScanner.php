<?php

declare(strict_types=1);

namespace WScan\Scan;

use WScan\Detect\Subject;
use WScan\Detect\DetectorInterface;
use WScan\Finding;
use WScan\Support\Config;
use WScan\Support\Domains;
use WScan\Support\Text;

/**
 * Dynamic cloaking detector.
 *
 * The defining feature of an SEO-hijack injection is that it activates for some
 * visitors and not others. No static scan can prove that; you have to observe
 * it. This scanner fetches each URL several times, once per visitor profile
 * (desktop / mobile / Baiduspider / Googlebot / WeChat), and compares:
 *
 *   - HTTP status and Location header (redirect only for bots == smoking gun)
 *   - overall structural similarity of the body
 *   - the *differential* set of external domains: domains that appear for a bot
 *     or mobile profile but not for the desktop baseline
 *
 * Differencing before scoring is what suppresses analytics/ad noise: a tracking
 * pixel loads for every profile, so it cancels out. Only content that is
 * conditional survives the subtraction, and that conditional slice is then run
 * through the same detectors used for files.
 */
final class DynamicScanner
{
    private HttpClient $http;

    /** @param list<DetectorInterface> $detectors */
    public function __construct(
        private readonly Config $config,
        private readonly array $detectors,
    ) {
        $this->http = new HttpClient(
            (int) $config->get('http.timeout', 8),
            (bool) $config->get('http.verify_tls', false),
            (bool) $config->get('http.follow_redirects', false),
        );
    }

    /**
     * @param list<string> $urls
     * @return list<Finding>
     */
    public function scanUrls(array $urls): array
    {
        if (!$this->config->get('http.enabled', true)) {
            return [];
        }

        $profiles = $this->config->get('http.profiles', []);
        if (!is_array($profiles) || $profiles === []) {
            return [];
        }

        $findings = [];
        foreach ($urls as $url) {
            foreach ($this->scanUrl($url, $profiles) as $finding) {
                $findings[] = $finding;
            }
        }

        return $findings;
    }

    /**
     * @param array<string,array{user_agent:string,headers?:array<string,string>}> $profiles
     * @return list<Finding>
     */
    public function scanUrl(string $url, array $profiles): array
    {
        $responses = [];
        foreach ($profiles as $name => $profile) {
            $headers = ['User-Agent' => (string) ($profile['user_agent'] ?? 'WScan')];
            foreach (($profile['headers'] ?? []) as $h => $v) {
                $headers[$h] = $v;
            }
            $responses[$name] = $this->http->get($url, $headers);
        }

        $baselineName = isset($responses['desktop']) ? 'desktop' : array_key_first($responses);
        if ($baselineName === null) {
            return [];
        }
        $baseline = $responses[$baselineName];

        $findings = [];
        $threshold = (float) $this->config->get('http.cloak_similarity_threshold', 0.82);

        // Redirect and body divergences are each reported once per URL with the
        // full profile list, otherwise identical findings collapse at dedup and
        // only the first (arbitrary) profile is ever named.
        $redirectProfiles = [];
        $redirectLocation = '';
        $redirectStatus = 0;

        $dynamicProfiles = [];
        $dynamicBest = null; // the highest-scoring divergence defines the finding
        $dynamicDomains = [];

        foreach ($responses as $name => $resp) {
            if ($name === $baselineName) {
                continue;
            }

            // 1. Redirect only for this profile.
            $redirectFinding = $this->redirectDivergence($url, $name, $resp, $baseline);
            if ($redirectFinding !== null) {
                $redirectProfiles[] = $name;
                $redirectLocation = (string) ($redirectFinding->meta['location'] ?? '');
                $redirectStatus = (int) ($redirectFinding->meta['status'] ?? 0);
            }

            // When this profile got a redirect while the baseline did not, the
            // "different body" comparison is just the redirect stub; skip it so
            // we do not emit a redundant low-value finding.
            $baselineRedirect = $baseline['status'] >= 300 && $baseline['status'] < 400;
            if ($redirectFinding !== null && !$baselineRedirect) {
                continue;
            }

            // 2. Content divergence.
            if ($resp['body'] === '' || $baseline['body'] === '') {
                continue;
            }
            if ($resp['body'] === $baseline['body']) {
                continue; // byte identical, nothing conditional
            }

            $similarity = Text::similarity($baseline['body'], $resp['body']);
            $diff = $this->differential($baseline['body'], $resp['body']);
            $diffDomains = $this->newDomains($baseline['body'], $resp['body']);

            // What did the conditional slice actually contain?
            $diffFindings = $this->inspectDiff($url, $name, $diff);

            $score = 0;
            $signals = [];
            if ($similarity < $threshold) {
                $score += 40;
                $signals[] = sprintf('页面结构差异显著 (相似度 %.2f < %.2f)', $similarity, $threshold);
            }
            if ($diffDomains !== []) {
                $score += 35;
                $signals[] = '仅对该访客出现的外部域名: ' . implode(', ', array_slice($diffDomains, 0, 5));
            }
            if (preg_match('/(?:window|document|top|self)\s*\.\s*location|location\s*\.\s*(?:href|replace)|<meta[^>]+refresh/i', $diff)) {
                $score += 25;
                $signals[] = '差异片段含跳转动作';
            }

            if ($score < 30) {
                // Differences exist but are minor/benign (e.g. a viewport tag).
                continue;
            }

            $dynamicProfiles[] = $name;
            $dynamicDomains = array_values(array_unique([...$dynamicDomains, ...$diffDomains]));

            $candidate = [
                'score' => $score,
                'signals' => $signals,
                'similarity' => $similarity,
                'diff' => $diff,
                'diffFindings' => $diffFindings,
                'profile' => $name,
            ];
            if ($dynamicBest === null || $score > $dynamicBest['score']) {
                $dynamicBest = $candidate;
            }
        }

        if ($dynamicBest !== null) {
            $evidence = [Text::snippet($dynamicBest['diff'], 0, 0, 400)];
            foreach ($dynamicBest['diffFindings'] as $df) {
                $evidence[] = '[' . $df->rule . '] ' . ($df->evidence[0] ?? $df->detail);
            }
            $score = min(100, $dynamicBest['score'] + 20);

            $findings[] = new Finding(
                rule: 'cloaking-dynamic',
                level: Finding::levelFromScore($score),
                score: $score,
                title: '伪装跳转：不同访客内容不一致',
                target: $url,
                detail: sprintf(
                    '访客档案 (%s) 与桌面基线 "%s" 看到的内容不同。%s',
                    implode('/', $dynamicProfiles),
                    $baselineName,
                    implode('；', $dynamicBest['signals']),
                ),
                evidence: array_values(array_filter($evidence)),
                meta: [
                    'profiles' => $dynamicProfiles,
                    'baseline' => $baselineName,
                    'similarity' => round($dynamicBest['similarity'], 3),
                    'diff_domains' => $dynamicDomains,
                    'sub_findings' => array_map(static fn (Finding $f): array => $f->toArray(), $dynamicBest['diffFindings']),
                ],
            );
        }

        // Emit one consolidated redirect finding for the URL.
        if ($redirectProfiles !== []) {
            $host = Domains::hostFromUrl($redirectLocation);
            $siteDomains = $this->config->getList('site_domains');
            $allow = $this->config->getList('allowlist_domains');
            $external = $host !== null && !Domains::isInternal($host, $siteDomains) && !Domains::isAllowlisted($host, $allow);

            $score = 60;
            $signals = [sprintf('%d 个访客档案 (%s) 收到 %d 跳转，桌面基线为 %d',
                count($redirectProfiles), implode('/', $redirectProfiles), $redirectStatus, $baseline['status'])];
            if ($external) {
                $score += 25;
                $signals[] = '跳转目标是站外域名 ' . ($host ?? $redirectLocation);
            }
            if ($host !== null && (Domains::hasSuspiciousTld($host) || Domains::hasGeneratedLabel($host))) {
                $score += 10;
                $signals[] = '跳转目标域名形态可疑';
            }

            $findings[] = new Finding(
                rule: 'cloaking-redirect',
                level: Finding::levelFromScore(min(100, $score)),
                score: min(100, $score),
                title: '伪装跳转：仅对特定访客返回重定向',
                target: $url,
                detail: implode('；', $signals) . '。',
                evidence: array_values(array_filter([
                    $redirectLocation !== '' ? 'Location: ' . $redirectLocation : null,
                    'HTTP ' . $redirectStatus,
                ])),
                meta: ['profiles' => $redirectProfiles, 'location' => $redirectLocation, 'status' => $redirectStatus],
            );
        }

        return $findings;
    }

    /**
     * @param array{status:int,headers:array<string,string>,body:string,error:?string,effective_url:string} $resp
     * @param array{status:int,headers:array<string,string>,body:string,error:?string,effective_url:string} $baseline
     */
    private function redirectDivergence(string $url, string $profile, array $resp, array $baseline): ?Finding
    {
        $isRedirect = $resp['status'] >= 300 && $resp['status'] < 400;
        $baselineRedirect = $baseline['status'] >= 300 && $baseline['status'] < 400;
        if (!$isRedirect) {
            return null;
        }

        $location = $resp['headers']['location'] ?? '';
        $host = Domains::hostFromUrl($location);
        $siteDomains = $this->config->getList('site_domains');
        $allow = $this->config->getList('allowlist_domains');
        $external = $host !== null && !Domains::isInternal($host, $siteDomains) && !Domains::isAllowlisted($host, $allow);

        // If desktop also redirects to the same place, it is a normal redirect.
        if ($baselineRedirect && strcasecmp($baseline['headers']['location'] ?? '', $location) === 0) {
            return null;
        }

        $score = 60;
        $signals = [sprintf('访客档案 "%s" 收到 %d 跳转，桌面基线为 %d', $profile, $resp['status'], $baseline['status'])];
        if ($external) {
            $score += 25;
            $signals[] = '跳转目标是站外域名 ' . ($host ?? $location);
        }
        if ($host !== null && (Domains::hasSuspiciousTld($host) || Domains::hasGeneratedLabel($host))) {
            $score += 10;
            $signals[] = '跳转目标域名形态可疑';
        }

        return new Finding(
            rule: 'cloaking-redirect',
            level: Finding::levelFromScore(min(100, $score)),
            score: min(100, $score),
            title: '伪装跳转：仅对特定访客返回重定向',
            target: $url,
            detail: implode('；', $signals) . '。',
            evidence: array_values(array_filter([
                $location !== '' ? 'Location: ' . $location : null,
                'HTTP ' . $resp['status'],
            ])),
            meta: ['profile' => $profile, 'location' => $location, 'status' => $resp['status']],
        );
    }

    /**
     * Returns the lines present in $suspect but not in $baseline, after
     * normalizing volatile tokens. This is the "conditional content" slice.
     */
    private function differential(string $baseline, string $suspect): string
    {
        $baseLines = $this->lineSet($baseline);
        $diffLines = [];
        foreach ($this->splitLines($suspect) as $line) {
            $norm = Text::normalizeForDiff($line);
            if ($norm === '' || strlen($norm) < 8) {
                continue;
            }
            if (!isset($baseLines[$norm])) {
                $diffLines[] = $line;
            }
            if (count($diffLines) >= 300) {
                break;
            }
        }

        return implode("\n", $diffLines);
    }

    /** @return array<string,true> */
    private function lineSet(string $text): array
    {
        $set = [];
        foreach ($this->splitLines($text) as $line) {
            $norm = Text::normalizeForDiff($line);
            if ($norm !== '' && strlen($norm) >= 8) {
                $set[$norm] = true;
            }
        }

        return $set;
    }

    /** @return list<string> */
    private function splitLines(string $text): array
    {
        // Split on newlines and on tag boundaries so minified HTML still diffs.
        $parts = preg_split('/\r?\n|(?<=>)\s*(?=<)|(?<=;)\s*(?=<)/', $text) ?: [];

        return array_values(array_filter($parts, static fn (string $p): bool => trim($p) !== ''));
    }

    /**
     * External domains present in the suspect response but absent from the
     * baseline. Allow-listed hosts (analytics/ads) are removed first so that a
     * tracker that only loads for mobile does not become a false positive.
     *
     * @return list<string>
     */
    private function newDomains(string $baseline, string $suspect): array
    {
        $siteDomains = $this->config->getList('site_domains');
        $allow = $this->config->getList('allowlist_domains');

        // Domains visible to the baseline visitor. Computed once.
        $baselineDomains = [];
        foreach (Domains::extractUrls($baseline) as $hit) {
            $baselineDomains[$hit['domain']] = true;
        }

        $new = [];
        foreach (Domains::extractUrls($suspect) as $hit) {
            $domain = $hit['domain'];
            if (isset($new[$domain]) || isset($baselineDomains[$domain])) {
                continue;
            }
            if (Domains::isInternal($hit['host'], $siteDomains) || Domains::isAllowlisted($hit['host'], $allow)) {
                continue;
            }
            $new[$domain] = true;
        }

        return array_keys($new);
    }

    /** @return list<Finding> */
    private function inspectDiff(string $url, string $profile, string $diff): array
    {
        if (trim($diff) === '') {
            return [];
        }
        $subject = new Subject($diff, "http:{$url}#{$profile}", 'http', $this->config);
        $out = [];
        foreach ($this->detectors as $detector) {
            // The dynamic diff has already proven conditionality; skip the
            // static cloaking detector to avoid double-counting.
            if ($detector->name() === 'cloaking') {
                continue;
            }
            foreach ($detector->inspect($subject) as $finding) {
                $out[] = $finding;
            }
        }

        return $out;
    }
}
