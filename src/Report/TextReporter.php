<?php

declare(strict_types=1);

namespace WScan\Report;

use WScan\Finding;
use WScan\Support\Text;

/**
 * Human-readable terminal report with colour, grouped by severity.
 */
final class TextReporter
{
    private const COLORS = [
        Finding::CRITICAL => "\033[1;97;41m", // white on red
        Finding::HIGH => "\033[1;31m",
        Finding::MEDIUM => "\033[1;33m",
        Finding::LOW => "\033[1;36m",
        Finding::INFO => "\033[0;37m",
    ];
    private const RESET = "\033[0m";

    public function __construct(private readonly bool $color = true)
    {
    }

    /**
     * @param list<Finding> $findings
     * @param array{total:int,by_level:array<string,int>,by_rule:array<string,int>,max_score:int} $summary
     */
    public function render(array $findings, array $summary, array $meta = []): string
    {
        $lines = [];
        $lines[] = $this->paint('══════════════════════════════════════════════════════════════', Finding::HIGH, true);
        $lines[] = $this->paint('  WScan 网站群隐蔽跳转 / 暗链检测报告', Finding::HIGH, true);
        $lines[] = $this->paint('══════════════════════════════════════════════════════════════', Finding::HIGH, true);
        foreach ($meta as $k => $v) {
            $lines[] = sprintf('  %-12s %s', $k, is_scalar($v) ? (string) $v : json_encode($v, JSON_UNESCAPED_UNICODE));
        }
        $lines[] = '';

        $lines[] = $this->paint('—— 总览 ——', Finding::HIGH, true);
        $lines[] = sprintf(
            '  发现项: %d   严重: %d   高危: %d   中危: %d   低危: %d   提示: %d',
            $summary['total'],
            $summary['by_level'][Finding::CRITICAL] ?? 0,
            $summary['by_level'][Finding::HIGH] ?? 0,
            $summary['by_level'][Finding::MEDIUM] ?? 0,
            $summary['by_level'][Finding::LOW] ?? 0,
            $summary['by_level'][Finding::INFO] ?? 0,
        );
        if ($summary['by_rule'] !== []) {
            $ruleParts = [];
            foreach ($summary['by_rule'] as $rule => $count) {
                $ruleParts[] = "{$rule}×{$count}";
            }
            $lines[] = '  按规则: ' . implode('  ', $ruleParts);
        }
        $lines[] = '';

        if ($findings === []) {
            $lines[] = $this->paint('  未发现达到阈值的问题。', Finding::LOW, true);

            return implode("\n", $lines);
        }

        $lines[] = $this->paint('—— 明细（按风险排序）——', Finding::HIGH, true);
        $index = 0;
        foreach ($findings as $f) {
            $index++;
            $tag = strtoupper($f->level);
            $lines[] = '';
            $lines[] = $this->paint(sprintf(' [%d] [%s %d] %s', $index, $tag, $f->score, $f->title), $f->level, true);
            $lines[] = '     目标: ' . $f->target . ($f->line !== null ? '  行 ' . $f->line : '');
            $lines[] = '     规则: ' . $f->rule;
            $lines[] = '     说明: ' . Text::toUtf8($f->detail);
            foreach ($f->evidence as $ev) {
                $ev = Text::toUtf8($ev);
                if (function_exists('mb_strimwidth')) {
                    $ev = mb_strimwidth($ev, 0, 240, '…');
                }
                $lines[] = '     · ' . $ev;
            }
        }
        $lines[] = '';

        return implode("\n", $lines);
    }

    private function paint(string $text, string $level, bool $bold = false): string
    {
        if (!$this->color) {
            return $text;
        }
        $color = self::COLORS[$level] ?? self::COLORS[Finding::INFO];

        return $color . $text . self::RESET;
    }
}
