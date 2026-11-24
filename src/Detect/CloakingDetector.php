<?php

declare(strict_types=1);

namespace WScan\Detect;

use WScan\Finding;
use WScan\Support\Text;

/**
 * Detects "cloaking": code that behaves differently depending on who is asking.
 *
 * This is the static half of the SEO-hijack problem. A normal page never needs
 * to inspect the User-Agent and then redirect; an injected snippet almost always
 * does. We score co-occurrence of:
 *   - reading visitor signals (UA / Referer / mobile flags)
 *   - a crawler or mobile test
 *   - a navigation sink (location / header Location / meta refresh)
 * plus a strong bonus when the sink target is an external, non-allow-listed host.
 *
 * Analytics scripts read the UA too, so a UA read alone is INFO at most; it only
 * escalates when paired with a conditional redirect to a foreign domain.
 */
final class CloakingDetector extends BaseDetector
{
    public function name(): string
    {
        return 'cloaking';
    }

    public function inspect(Subject $subject): array
    {
        if (!$this->enabled() || $subject->isBinary()) {
            return [];
        }

        $findings = [];

        // Examine the raw content and every decoded layer. Decoded layers catch
        // the case where the whole snippet is base64/rot13 wrapped.
        $best = null;
        foreach ($subject->layers() as $layer) {
            $text = $layer['text'];
            if (strlen($text) < 40) {
                continue;
            }
            $analysis = $this->analyzeText($text);
            if ($analysis === null) {
                continue;
            }
            if ($best === null || $analysis['score'] > $best['score']) {
                $best = $analysis + ['chain' => $layer['chain']];
            }
        }

        if ($best !== null && $best['score'] >= 20) {
            $detail = $this->describe($best);
            $findings[] = $this->finding(
                $subject,
                'cloaking',
                $best['score'],
                '疑似针对搜索引擎/手机的伪装跳转 (cloaking)',
                $detail,
                $best['evidence'],
                $best['line'],
                [
                    'chain' => $best['chain'],
                    'signals' => $best['signals'],
                    'external_targets' => $best['external_targets'],
                ],
            );
        }

        return $findings;
    }

    /**
     * @return array{score:int,signals:list<string>,evidence:list<string>,line:?int,external_targets:list<string>}|null
     */
    private function analyzeText(string $text): ?array
    {
        $signals = [];
        $score = 0;

        $visitorSignal = $this->hasVisitorSignal($text);
        $crawlerSignal = $this->hasCrawlerSignal($text);
        $mobileSignal = $this->hasMobileSignal($text);
        $sink = $this->findNavigationSink($text);
        $externalTargets = $this->externalTargets($text);

        if ($visitorSignal) {
            $signals[] = '读取访客特征 (UA/Referer/Cookie)';
            $score += 15;
        }
        if ($crawlerSignal) {
            $signals[] = '检测搜索引擎爬虫';
            $score += 25;
        }
        if ($mobileSignal) {
            $signals[] = '检测移动端/微信';
            $score += 15;
        }
        if ($sink !== null) {
            $signals[] = '包含跳转动作 (' . $sink . ')';
            $score += 20;
        }

        // The killer combination: conditional + redirect.
        if (($crawlerSignal || $mobileSignal) && $sink !== null) {
            $score += 25;
        }
        if ($visitorSignal && ($crawlerSignal || $mobileSignal) && $sink !== null) {
            $score += 10;
        }

        // External destination raises confidence sharply.
        if ($sink !== null && $externalTargets !== []) {
            $score += 20;
            $signals[] = '跳转目标指向站外域名';
        }

        // A crawl test that never redirects is common in legit "SEO" tools, but
        // on a government template it is still worth flagging at a low score.
        if ($score < 15 && !$visitorSignal && !$crawlerSignal && !$mobileSignal) {
            return null;
        }

        $evidence = [];
        foreach ($this->evidenceSnippets($text, $externalTargets) as $snippet) {
            $evidence[] = $snippet;
        }

        $line = null;
        if ($sink !== null && preg_match('/location|header\s*\(/i', $text, $m, PREG_OFFSET_CAPTURE)) {
            $line = Text::lineAt($text, (int) $m[0][1]);
        }

        return [
            'score' => $score,
            'signals' => $signals,
            'evidence' => $evidence,
            'line' => $line,
            'external_targets' => $externalTargets,
        ];
    }

    private function hasVisitorSignal(string $text): bool
    {
        $signals = $this->config->getList('cloak_signals.user-agent');
        $referer = $this->config->getList('cloak_signals.referer');
        foreach ([...$signals, ...$referer] as $needle) {
            if ($needle !== '' && stripos($text, $needle) !== false) {
                return true;
            }
        }
        // Generic PHP access to the headers.
        return preg_match('/\$_SERVER\s*\[\s*[\'"](?:HTTP_USER_AGENT|HTTP_REFERER)[\'"]\s*\]/i', $text) === 1;
    }

    private function hasCrawlerSignal(string $text): bool
    {
        $bots = $this->config->getList('cloak_signals.bot');

        foreach ($bots as $needle) {
            if (stripos($text, $needle) === false) {
                continue;
            }
            // Require it to look like a comparison, not a comment or a log.
            $quoted = preg_quote($needle, '/');
            if (preg_match('/(?:stri?pos|preg_match|strstr|stristr|in_array|==|===|!==|!=)\s*[^\n;]{0,60}' . $quoted . '/i', $text)) {
                return true;
            }
            if (preg_match('/' . $quoted . '[^\n;]{0,80}(?:stri?pos|preg_match|==|===)/i', $text)) {
                return true;
            }
        }

        // Search-engine entry cloaking: testing the Referer against a search
        // domain is the same trick as testing for a bot — it targets visitors
        // arriving from search results. Require a comparison, not a mere mention.
        foreach ($this->config->getList('cloak_signals.crawler_domains') as $domain) {
            $quoted = preg_quote($domain, '/');
            if (preg_match('/(?:stri?pos|preg_match|strstr|stristr|indexOf|includes|test|==|===|!==|!=)\s*[^\n;]{0,60}[\'"]?' . $quoted . '/i', $text)) {
                return true;
            }
            if (preg_match('/[\'"]?' . $quoted . '[\'"]?[^\n;]{0,80}(?:stri?pos|preg_match|indexOf|includes|==|===)/i', $text)) {
                return true;
            }
        }

        return false;
    }

    private function hasMobileSignal(string $text): bool
    {
        $mobiles = $this->config->getList('cloak_signals.mobile');
        foreach ($mobiles as $needle) {
            $quoted = preg_quote($needle, '/');
            if (preg_match('/(?:stri?pos|preg_match|stristr|in_array|==|===|!==)\s*[^\n;]{0,60}' . $quoted . '/i', $text)) {
                return true;
            }
        }

        return false;
    }

    private function findNavigationSink(string $text): ?string
    {
        // JS navigation: must be an assignment (=, +=) or a method call.
        // A plain read like `document.location.href || ""` is NOT navigation.
        if (preg_match('/(?:window|document|top|self|parent)\s*\.\s*location\s*(?:\.\s*(?:href|pathname)\s*[+\-]?=(?!=)|\.\s*(?:replace|assign|reload)\s*\()/i', $text)) {
            return 'JS location 跳转';
        }
        if (preg_match('/(?<![.\w])location\s*(?:\.\s*(?:href|pathname)\s*[+\-]?=(?!=)|\.\s*(?:replace|assign)\s*\()/i', $text)) {
            return 'JS location 跳转';
        }
        if (preg_match('/\bwindow\.open\s*\(\s*[\'"]https?:\/\//i', $text)) {
            return 'window.open';
        }
        // Server-side redirect.
        if (preg_match('/\bheader\s*\(\s*[\'"]\s*Location\s*:/i', $text)) {
            return 'HTTP Location header';
        }
        // Meta refresh.
        if (preg_match('/<meta[^>]+http-equiv\s*=\s*[\'"]?refresh/i', $text)) {
            return 'meta refresh';
        }

        return null;
    }

    /** @return list<string> */
    private function externalTargets(string $text): array
    {
        $allow = $this->config->getList('allowlist_domains');
        $siteDomains = $this->config->getList('site_domains');
        $out = [];
        foreach (\WScan\Support\Domains::extractUrls($text) as $hit) {
            if (\WScan\Support\Domains::isInternal($hit['host'], $siteDomains)) {
                continue;
            }
            if (\WScan\Support\Domains::isAllowlisted($hit['host'], $allow)) {
                continue;
            }
            $out[$hit['domain']] = true;
        }

        return array_keys($out);
    }

    /** @return list<string> */
    private function evidenceSnippets(string $text, array $externalTargets): array
    {
        $snippets = [];
        foreach ($externalTargets as $domain) {
            $pos = stripos($text, (string) $domain);
            if ($pos !== false) {
                $snippets[] = Text::snippet($text, $pos, 60, 100);
            }
        }
        if ($snippets === []) {
            foreach (['Baiduspider', 'Googlebot', 'HTTP_USER_AGENT', 'HTTP_REFERER', 'location.href', 'location.replace', 'Location:'] as $marker) {
                $pos = stripos($text, $marker);
                if ($pos !== false) {
                    $snippets[] = Text::snippet($text, $pos);
                    break;
                }
            }
        }

        return array_values(array_unique($snippets));
    }

    /** @param array{signals:list<string>,external_targets:list<string>,chain:list<string>} $best */
    private function describe(array $best): string
    {
        $parts = ['命中特征: ' . implode('；', $best['signals'])];
        if ($best['external_targets'] !== []) {
            $parts[] = '站外跳转目标: ' . implode(', ', array_slice($best['external_targets'], 0, 5));
        }
        if ($best['chain'] !== []) {
            $parts[] = '经解码层: ' . implode(' → ', $best['chain']);
        }

        return implode('。', $parts) . '。正常页面不会在读取访客特征后再跳转，高度疑似被植入只对特定访客生效的跳转代码。';
    }
}
