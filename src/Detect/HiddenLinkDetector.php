<?php

declare(strict_types=1);

namespace WScan\Detect;

use WScan\Support\Domains;
use WScan\Support\Text;

/**
 * Detects "dark links": anchors that are invisible to humans (CSS hiding, zero
 * size, off-screen, colour-matched) and point to an external domain. These are
 * used for SEO-link farming and are a strong tamper signal, because a CMS never
 * generates them.
 *
 * We score:
 *   - the hiding technique (display:none / visibility:hidden / 0 font / off-screen
 *     / colour == background / 1px height)
 *   - whether the link is external and not allow-listed
 *   - anchor text relevance to gambling keywords
 */
final class HiddenLinkDetector extends BaseDetector
{
    private const HIDING_CSS = [
        // The two most common dark-link techniques carry the most weight: a
        // display:none external anchor is the signature of an SEO dark link and
        // should reach MEDIUM on that combination alone.
        'display\s*:\s*none' => 20,
        'visibility\s*:\s*hidden' => 20,
        'font-size\s*:\s*0(?:px|pt|em|rem)?' => 12,
        'font-size\s*:\s*1px' => 10,
        'text-indent\s*:\s*-\d{3,}(?:px|em)?' => 10,
        'position\s*:\s*absolute[^;}]{0,80}(?:left|top)\s*:\s*-\d{3,}' => 10,
        'height\s*:\s*(?:0|1)px' => 8,
        'width\s*:\s*(?:0|1)px' => 8,
        'overflow\s*:\s*hidden[^;}]{0,40}height\s*:\s*(?:0|1)px' => 6,
        'line-height\s*:\s*0' => 6,
        'opacity\s*:\s*0(?:\.0+)?\b' => 8,
        'color\s*:\s*#fff(?:fff)?\b' => 3,
        'clip\s*:\s*rect\s*\(\s*[01]px' => 10,
    ];

    public function name(): string
    {
        return 'hidden_link';
    }

    public function inspect(Subject $subject): array
    {
        if (!$this->enabled() || $subject->isBinary()) {
            return [];
        }

        $text = $subject->content;
        if (!preg_match_all('/<a\b([^>]*)>(.*?)<\/a>/isu', $text, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
            return [];
        }

        $allow = $subject->allowlist();
        $siteDomains = $subject->siteDomains();
        $gambling = $this->config->getList('gambling_keywords');

        $findings = [];
        foreach ($matches as $m) {
            $attrs = $m[1][0];
            $inner = $m[2][0];
            $offset = (int) $m[0][1];

            if (!preg_match('/href\s*=\s*["\']([^"\']+)["\']/i', $attrs, $hm)) {
                continue;
            }
            $href = trim($hm[1]);
            $host = Domains::hostFromUrl($href);
            if ($host === null || Domains::isInternal($host, $siteDomains) || Domains::isAllowlisted($host, $allow)) {
                continue;
            }

            $score = 0;
            $reasons = [];

            // Inline style hiding.
            if (preg_match('/style\s*=\s*["\']([^"\']*)["\']/i', $attrs, $sm)) {
                $style = $sm[1];
                foreach (self::HIDING_CSS as $pattern => $weight) {
                    if (preg_match('/' . $pattern . '/i', $style)) {
                        $score += $weight;
                        $reasons[] = 'CSS: ' . $pattern;
                    }
                }
                // Colour equals likely background (white on white / transparent).
                if (preg_match('/color\s*:\s*(?:#fff(?:fff)?|white|rgba?\([^)]*,\s*0\s*\))/i', $style)
                    && preg_match('/background(?:-color)?\s*:\s*(?:#fff(?:fff)?|white)/i', $style)) {
                    $score += 10;
                    $reasons[] = '前景色与背景色相同';
                }
            }

            // Presentational hiding attributes. Match the standalone attribute,
            // not the substring inside a style value like visibility:hidden.
            if (preg_match('/(?:^|\s)hidden(?:\s|=|$)/i', $attrs)) {
                $score += 12;
                $reasons[] = 'HTML hidden 属性';
            }
            if (preg_match('/\baria-hidden\s*=\s*["\']?true/i', $attrs)) {
                $score += 6;
                $reasons[] = 'aria-hidden';
            }
            if (preg_match('/\btabindex\s*=\s*["\']?-1/i', $attrs)) {
                $score += 3;
            }

            // Empty or single-char anchor text is typical for dark links; a real
            // navigation link has readable text.
            $visibleText = trim(strip_tags($inner));
            if ($visibleText === '') {
                $score += 6;
                $reasons[] = '链接无可见文字';
            }

            if ($score < 8) {
                continue; // not hidden enough to be a dark link
            }

            // External link is the other half of the signal.
            $score += 20;
            $reasons[] = '指向站外域名 ' . $host;

            if (Domains::hasSuspiciousTld($host) || Domains::hasGeneratedLabel($host)) {
                $score += 12;
                $reasons[] = '可疑域名形态';
            }

            foreach ($gambling as $kw) {
                if ($kw !== '' && (mb_stripos($visibleText, $kw) !== false || mb_stripos($inner, $kw) !== false)) {
                    $score += 15;
                    $reasons[] = '含博彩词';
                    break;
                }
            }

            $findings[] = $this->finding(
                $subject,
                'hidden_link',
                min(100, $score),
                '疑似隐藏暗链',
                '发现视觉隐藏的外链，指向 ' . $host . '。隐藏手法：' . implode('；', $reasons) . '。',
                [$subject->evidence($offset, 40, 220)],
                $subject->lineOf($offset),
                ['href' => $href, 'host' => $host, 'reasons' => $reasons],
            );

            if (count($findings) >= 10) {
                break;
            }
        }

        return $findings;
    }
}
