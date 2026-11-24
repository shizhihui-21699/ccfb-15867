<?php

declare(strict_types=1);

namespace WScan\Report;

use WScan\Finding;
use WScan\Support\Config;

/**
 * Aggregates findings, de-duplicates obvious repeats and computes a summary.
 */
final class FindingSet
{
    /** @var list<Finding> */
    private array $findings = [];

    public function __construct(private readonly Config $config)
    {
    }

    /** @param iterable<Finding> $findings */
    public function add(iterable $findings): void
    {
        foreach ($findings as $finding) {
            $this->findings[] = $finding;
        }
    }

    /** @return list<Finding> */
    public function all(): array
    {
        return $this->findings;
    }

    /**
     * Sorted, filtered by minimum level, de-duplicated by (rule,target,line).
     *
     * @return list<Finding>
     */
    public function ranked(): array
    {
        $minLevel = (string) $this->config->get('report.min_level', 'low');
        $minScore = self::scoreForLevel($minLevel);

        $seen = [];
        $out = [];
        foreach ($this->findings as $f) {
            if ($f->score < $minScore) {
                continue;
            }
            $key = $f->rule . '|' . $f->target . '|' . ($f->line ?? 0);
            if (isset($seen[$key])) {
                // Keep the higher-scoring duplicate.
                if ($seen[$key] < $f->score) {
                    foreach ($out as $i => $existing) {
                        if ($existing->rule . '|' . $existing->target . '|' . ($existing->line ?? 0) === $key) {
                            $out[$i] = $f;
                        }
                    }
                    $seen[$key] = $f->score;
                }
                continue;
            }
            $seen[$key] = $f->score;
            $out[] = $f;
        }

        usort($out, static fn (Finding $a, Finding $b): int => $b->score <=> $a->score ?: strcmp($a->target, $b->target));

        return $out;
    }

    /**
     * @return array{total:int,by_level:array<string,int>,by_rule:array<string,int>,max_score:int}
     */
    public function summary(): array
    {
        $byLevel = [Finding::CRITICAL => 0, Finding::HIGH => 0, Finding::MEDIUM => 0, Finding::LOW => 0, Finding::INFO => 0];
        $byRule = [];
        $max = 0;
        foreach ($this->ranked() as $f) {
            $byLevel[$f->level] = ($byLevel[$f->level] ?? 0) + 1;
            $byRule[$f->rule] = ($byRule[$f->rule] ?? 0) + 1;
            $max = max($max, $f->score);
        }
        arsort($byRule);

        return [
            'total' => array_sum($byLevel),
            'by_level' => $byLevel,
            'by_rule' => $byRule,
            'max_score' => $max,
        ];
    }

    public static function scoreForLevel(string $level): int
    {
        return match (strtolower($level)) {
            'critical' => 85,
            'high' => 65,
            'medium' => 40,
            'low' => 20,
            default => 0,
        };
    }
}
