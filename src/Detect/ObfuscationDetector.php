<?php

declare(strict_types=1);

namespace WScan\Detect;

use WScan\Support\Text;

/**
 * Flags heavy obfuscation and dangerous dynamic-execution primitives.
 *
 * On its own, obfuscation is not proof of compromise — minified vendor JS is
 * obfuscated too — so the score is deliberately moderate and gets a large boost
 * when the decoded payload turns out to contain a redirect or gambling string,
 * or when the obfuscation sits inside PHP (where it has no legitimate reason on
 * a CMS template).
 */
final class ObfuscationDetector extends BaseDetector
{
    public function name(): string
    {
        return 'obfuscation';
    }

    public function inspect(Subject $subject): array
    {
        if (!$this->enabled() || $subject->isBinary()) {
            return [];
        }

        $text = $subject->content;
        $score = 0;
        $reasons = [];
        $evidence = [];

        // PHP eval-family with an encoded argument: the classic webshell /
        // injector shape (eval(gzinflate(base64_decode(...)))).
        if (preg_match('/\b(?:eval|assert|create_function|preg_replace)\s*\(\s*(?:@)?(?:base64_decode|gzinflate|gzuncompress|str_rot13|strrev|hex2bin)\s*\(/i', $text, $m, PREG_OFFSET_CAPTURE)) {
            $score += 55;
            $reasons[] = 'eval/assert 组合编码解码函数';
            $evidence[] = Text::snippet($text, (int) $m[0][1], 60, 160);
        }

        // Dynamic function dispatch: $f='sys'.'tem'; $f(...).
        if (preg_match('/\$[a-z_]\w*\s*=\s*[\'"][a-z_\x41-\x7a]{2,}[\'"]\s*\.\s*[\'"][a-z_]{2,}[\'"]/i', $text)) {
            $score += 25;
            $reasons[] = '分段拼接函数名';
        }
        if (preg_match('/\$\{?\$[a-z_]\w*\}?\s*\(/i', $text) || preg_match('/\$[a-z_]\w*\s*\(\s*\$_/', $text)) {
            $score += 20;
            $reasons[] = '可变函数调用';
        }

        // Very long encoded blob.
        $layers = $subject->layers();
        $deep = array_filter($layers, static fn (array $l): bool => count($l['chain']) >= 2);
        if ($deep !== []) {
            $score += 30;
            $reasons[] = '存在多层嵌套编码';
            foreach (array_slice(array_values($deep), 0, 3) as $layer) {
                $evidence[] = '解码链 ' . implode(' → ', $layer['chain']) . '：' . Text::snippet($layer['text'], 0, 0, 160);
            }
        }

        // Long base64 literal even without a surrounding call.
        if (preg_match('/[\'"]([A-Za-z0-9+\/]{200,}={0,2})[\'"]/', $text, $m, PREG_OFFSET_CAPTURE)) {
            $blob = $m[1][0];
            if (Text::entropy($blob) > 5.2) {
                $score += 20;
                $reasons[] = '超长高熵 base64 字符串';
                $evidence[] = Text::snippet($text, (int) $m[1][1], 20, 80) . ' ... (长度 ' . strlen($blob) . ')';
            }
        }

        // Heavy eval density.
        $evalCount = preg_match_all('/\beval\s*\(/i', $text);
        if ($evalCount >= 3) {
            $score += 15;
            $reasons[] = "eval 密度异常 ({$evalCount} 处)";
        }

        if ($score === 0) {
            return [];
        }

        // Escalate when the decoded payload actually does something malicious.
        $decodedText = implode("\n", array_map(static fn (array $l): string => $l['text'], $deep ?: $layers));
        $payloadBoost = 0;
        if (preg_match('/location\s*\.\s*(?:href|replace)|window\.open|Location\s*:/i', $decodedText)) {
            $payloadBoost += 25;
            $reasons[] = '解码后含跳转动作';
        }
        $gambling = $this->config->getList('gambling_keywords');
        foreach ($gambling as $kw) {
            if ($kw !== '' && mb_stripos($decodedText, $kw) !== false) {
                $payloadBoost += 20;
                $reasons[] = '解码后含博彩词';
                break;
            }
        }

        // PHP context is far more suspicious than JS.
        if (preg_match('/\.ph(?:p|tml|ar)|\.inc$/i', $subject->origin) || preg_match('/<\?php/i', $text)) {
            $payloadBoost += 10;
        }

        $score = min(100, $score + $payloadBoost);

        return [
            $this->finding(
                $subject,
                'obfuscation',
                $score,
                '可疑代码混淆/动态执行',
                '检测到混淆特征：' . implode('；', $reasons) . '。',
                $evidence,
                null,
                ['reasons' => $reasons, 'layers' => count($layers)],
            ),
        ];
    }
}
