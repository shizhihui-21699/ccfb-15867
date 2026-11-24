<?php

declare(strict_types=1);

namespace WScan\Detect;

use WScan\Support\Text;

/**
 * Heuristic web-shell / backdoor detector for PHP files.
 *
 * Rather than a signature list (which expires fast), it scores combinations that
 * a legitimate CMS page almost never produces:
 *   - request superglobal feeding an execution primitive
 *   - a very short file that is mostly a single dynamic call
 *   - a file whose name is random-looking inside an upload/cache directory
 *   - preg_replace /e, assert($_POST), call_user_func($_REQUEST[...])
 *
 * Findings in known-vendor directories are downgraded by BaseDetector.
 */
final class WebshellDetector extends BaseDetector
{
    public function name(): string
    {
        return 'webshell';
    }

    public function inspect(Subject $subject): array
    {
        if (!$this->enabled() || $subject->isBinary()) {
            return [];
        }
        // Only meaningful for executable content.
        if (!preg_match('/\.(?:php\d?|phtml|phar|inc)$/i', $subject->origin) && !preg_match('/<\?php/i', $subject->content)) {
            return [];
        }

        $text = $subject->content;
        $score = 0;
        $reasons = [];
        $evidence = [];

        $hasRequest = preg_match('/\$_(?:POST|GET|REQUEST|COOKIE|SERVER|FILES)\b/i', $text) === 1;
        $exec = $this->executionPrimitive($text);

        if ($hasRequest && $exec !== null) {
            $score += 45;
            $reasons[] = "请求参数直接进入执行函数 ({$exec})";
        } elseif ($exec !== null) {
            $score += 20;
            $reasons[] = "使用执行函数 ({$exec})";
        }

        // Encoded request payload: eval(base64_decode($_POST[...])).
        if (preg_match('/\b(?:eval|assert|system|passthru|shell_exec|popen|proc_open)\s*\(\s*(?:@)?(?:base64_decode|gzinflate|str_rot13)\s*\(\s*\$_/i', $text, $m, PREG_OFFSET_CAPTURE)) {
            $score += 45;
            $reasons[] = '编码后的请求参数被直接执行';
            $evidence[] = Text::snippet($text, (int) $m[0][1], 40, 140);
        }

        // Ultra-short one-liner payload.
        $nonComment = preg_replace('/\/\*.*?\*\/|\/\/[^\n]*|#[^\n]*/s', '', $text) ?? $text;
        $trimmed = trim(strip_tags($nonComment));
        if (strlen($trimmed) < 200 && $exec !== null) {
            $score += 20;
            $reasons[] = '极短文件仅包含执行调用 (长度 ' . strlen($trimmed) . ')';
        }

        // Suspicious primitives with no legitimate need on a CMS page.
        foreach ([
            '/\b(?:proc_open|pcntl_exec|popen)\s*\(/' => '进程执行',
            '/\bassert\s*\(\s*\$_/' => 'assert 注入点',
            '/\bpreg_replace\s*\(\s*[\'"][^\'"]*\/e[\'"]/' => 'preg_replace /e 后门',
            '/\bfile_put_contents\s*\([^)]*\$_(?:POST|GET|REQUEST)/i' => '任意文件写入',
            '/\bmove_uploaded_file\s*\(/' => '文件上传落盘',
        ] as $pattern => $label) {
            if (preg_match($pattern, $text, $m, PREG_OFFSET_CAPTURE)) {
                $score += 18;
                $reasons[] = $label;
                $evidence[] = Text::snippet($text, (int) $m[0][1], 40, 140);
                if (count($evidence) >= 3) {
                    break;
                }
            }
        }

        // Random filename in a writable directory.
        $base = basename($subject->origin);
        if (preg_match('/^[a-f0-9]{8,32}\.php$/i', $base) && preg_match('#(?:upload|uploads|cache|tmp|data|runtime)/#i', $subject->origin)) {
            $score += 15;
            $reasons[] = '上传/缓存目录中的随机命名 PHP';
        }

        if ($score < 20) {
            return [];
        }

        return [
            $this->finding(
                $subject,
                'webshell',
                min(100, $score),
                '疑似 WebShell / 后门',
                '检测到后门特征：' . implode('；', $reasons) . '。',
                $evidence,
                null,
                ['reasons' => $reasons],
            ),
        ];
    }

    private function executionPrimitive(string $text): ?string
    {
        $primitives = [
            'eval', 'assert', 'system', 'exec', 'shell_exec', 'passthru',
            'popen', 'proc_open', 'create_function', 'call_user_func',
            'call_user_func_array', 'array_map', 'preg_replace',
        ];
        foreach ($primitives as $fn) {
            if (preg_match('/\b' . preg_quote($fn, '/') . '\s*\(/i', $text)) {
                // Must be called with a request-derived argument to count as direct.
                if (preg_match('/\b' . preg_quote($fn, '/') . '\s*\([^)]{0,120}\$_/is', $text)) {
                    return $fn;
                }
            }
        }

        return null;
    }
}
