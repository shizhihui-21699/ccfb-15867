<?php

declare(strict_types=1);

namespace WScan\Detect;

use WScan\Support\Domains;
use WScan\Support\Text;

/**
 * Detects gambling / adult-content injection markers in raw and decoded text.
 *
 * Two independent signals, because each alone is noisy:
 *   1. Gambling keywords (中文博彩词 / known brand names). A single keyword in a
 *      news article about gambling is normal; we require several distinct terms,
 *      or one term in an anchor/script/hidden context.
 *   2. Links to suspicious domains (bad TLD, generated labels, gambling-brand
 *      look-alikes, IP-literal hosts).
 *
 * Analytics/ads are filtered by the allow-list, so they never reach scoring.
 */
final class GamblingDetector extends BaseDetector
{
    public function name(): string
    {
        return 'gambling';
    }

    public function inspect(Subject $subject): array
    {
        if (!$this->enabled() || $subject->isBinary()) {
            return [];
        }

        $findings = [];
        $keywords = $this->config->getList('gambling_keywords');

        // Keyword scoring over all decoded layers.
        $keywordHits = $this->searchAllLayers(
            $subject,
            '/(' . implode('|', array_map(static fn (string $k): string => preg_quote($k, '/'), $keywords)) . ')/iu',
            30,
        );
        if ($keywordHits !== []) {
            $distinct = array_values(array_unique(array_map(static fn (array $h): string => mb_strtolower($h['match']), $keywordHits)));
            $count = count($distinct);
            $score = match (true) {
                $count >= 5 => 78,
                $count >= 3 => 62,
                $count >= 2 => 45,
                default => 25,
            };

            // Context boost: keyword sitting inside a link, script or hidden element.
            $boosted = $this->inSensitiveContext($subject, $keywordHits);
            if ($boosted) {
                $score += 15;
            }

            $evidence = [];
            foreach (array_slice($keywordHits, 0, 5) as $hit) {
                $layerText = $this->findLayerText($subject, $hit['match']);
                if ($layerText === null) {
                    continue;
                }
                $pos = mb_stripos($layerText, $hit['match']);
                $offset = $pos === false ? 0 : $pos;
                $evidence[] = '[' . $this->chainLabel($hit['chain']) . '] ' . Text::snippet($layerText, $offset, 20, 120);
            }
            $evidence = array_values(array_unique($evidence));

            $findings[] = $this->finding(
                $subject,
                'gambling-keywords',
                min(100, $score),
                '疑似博彩内容注入',
                '在内容中发现 ' . $count . ' 个不同的博彩关键词：' . implode('、', array_slice($distinct, 0, 8)) . '。',
                $evidence,
                null,
                ['keywords' => $distinct, 'in_sensitive_context' => $boosted],
            );
        }

        // Suspicious external domains.
        $domainFindings = $this->suspiciousDomains($subject);
        if ($domainFindings !== null) {
            $findings[] = $domainFindings;
        }

        return $findings;
    }

    private function suspiciousDomains(Subject $subject): ?\WScan\Finding
    {
        $allow = $subject->allowlist();
        $siteDomains = $subject->siteDomains();
        $suspects = [];
        $evidence = [];

        foreach ($subject->layers() as $layer) {
            foreach (Domains::extractUrls($layer['text']) as $hit) {
                $host = $hit['host'];
                if (Domains::isInternal($host, $siteDomains) || Domains::isAllowlisted($host, $allow)) {
                    continue;
                }

                $reasons = [];
                if (Domains::hasSuspiciousTld($host)) {
                    $reasons[] = '高风险后缀';
                }
                if (Domains::hasGeneratedLabel($host)) {
                    $reasons[] = '机器生成域名';
                }
                if (Domains::isIp($host)) {
                    $reasons[] = 'IP 直连';
                }
                if ($reasons === []) {
                    continue;
                }

                $suspects[$hit['domain']] ??= $reasons;
                if (count($evidence) < 5) {
                    $evidence[] = $hit['url'] . '  (' . implode('、', $reasons) . ')';
                }
            }
        }

        if ($suspects === []) {
            return null;
        }

        $score = count($suspects) >= 2 ? 70 : 55;
        // IP-literal or explicit gambling-brand host is very strong.
        foreach ($suspects as $reasons) {
            if (in_array('IP 直连', $reasons, true)) {
                $score = max($score, 78);
            }
        }

        return $this->finding(
            $subject,
            'gambling-domains',
            $score,
            '疑似博彩/黑帽跳转域名',
            '发现 ' . count($suspects) . ' 个可疑站外域名：' . implode(', ', array_slice(array_keys($suspects), 0, 8)) . '。',
            $evidence,
            null,
            ['domains' => $suspects],
        );
    }

    private function inSensitiveContext(Subject $subject, array $hits): bool
    {
        $text = $subject->content;

        // Pre-extract script bodies once instead of running an expensive
        // tempered-dot regex per keyword (which can overflow PCRE).
        $scriptBodies = [];
        if (preg_match_all('#<script\b[^>]*>(.*?)</script>#isu', $text, $sm)) {
            $scriptBodies = $sm[1];
        }
        // Body of the hidden-style pattern only (no delimiters), so it can be
        // composed into larger patterns without mangling the trailing /i.
        $hiddenBody = 'display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|text-indent\s*:\s*-\d{3,}';

        foreach ($hits as $hit) {
            $needle = $hit['match'];
            foreach ($scriptBodies as $body) {
                if (mb_stripos($body, $needle) !== false) {
                    return true;
                }
            }
            $quoted = preg_quote($needle, '/');
            // Keyword used as anchor text.
            if (@preg_match('/<a\b[^>]{0,300}>[^<]{0,80}' . $quoted . '/iu', $text)) {
                return true;
            }
            // Keyword near a hidden-style declaration.
            if (@preg_match('/(?:' . $hiddenBody . ')[^>]{0,200}' . $quoted . '/iu', $text)) {
                return true;
            }
        }

        return false;
    }

    private function findLayerText(Subject $subject, string $needle): ?string
    {
        foreach ($subject->layers() as $layer) {
            if (str_contains($layer['text'], $needle)) {
                return $layer['text'];
            }
        }

        return null;
    }
}
