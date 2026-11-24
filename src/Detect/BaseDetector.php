<?php

declare(strict_types=1);

namespace WScan\Detect;

use WScan\Finding;

/**
 * Shared helpers for the content detectors.
 */
abstract class BaseDetector implements DetectorInterface
{
    public function __construct(protected readonly \WScan\Support\Config $config)
    {
    }

    protected function weight(): float
    {
        $w = $this->config->get('rules.' . $this->name() . '.weight', 1.0);

        return is_numeric($w) ? (float) $w : 1.0;
    }

    protected function enabled(): bool
    {
        return (bool) $this->config->get('rules.' . $this->name() . '.enabled', true);
    }

    /**
     * Applies the configured weight and the vendor-path downgrade, then builds
     * a Finding with the correct level.
     *
     * @param list<string> $evidence
     * @param array<string,mixed> $meta
     */
    protected function finding(
        Subject $subject,
        string $rule,
        int $baseScore,
        string $title,
        string $detail,
        array $evidence,
        ?int $line = null,
        array $meta = [],
    ): Finding {
        $score = (int) round($baseScore * $this->weight());
        if ($subject->isDowngraded()) {
            $score = (int) round($score * 0.5);
        }
        $score = max(1, min(100, $score));

        $maxEvidence = (int) $this->config->get('report.max_evidence_per_finding', 5);
        if (count($evidence) > $maxEvidence) {
            $evidence = array_slice($evidence, 0, $maxEvidence);
        }

        return new Finding(
            rule: $rule,
            level: Finding::levelFromScore($score),
            score: $score,
            title: $title,
            target: $subject->origin,
            detail: $detail,
            evidence: $evidence,
            line: $line,
            meta: $meta,
        );
    }

    /**
     * Runs a regex over every decoded layer and returns unique matches with the
     * layer chain that revealed them. This is the core trick that lets a single
     * keyword rule work even when the payload is base64 + gzinflate wrapped.
     *
     * @return list<array{match:string,chain:list<string>,offset:int}>
     */
    protected function searchAllLayers(Subject $subject, string $pattern, int $limit = 20): array
    {
        $hits = [];
        $seen = [];
        foreach ($subject->layers() as $layer) {
            if ($layer['text'] === '' || strlen($layer['text']) < 4) {
                continue;
            }
            $count = preg_match_all($pattern, $layer['text'], $matches, PREG_OFFSET_CAPTURE);
            if (!$count) {
                continue;
            }
            foreach ($matches[0] as [$match, $offset]) {
                $key = md5($match);
                if (isset($seen[$key])) {
                    continue;
                }
                $seen[$key] = true;
                $hits[] = [
                    'match' => (string) $match,
                    'chain' => $layer['chain'],
                    'offset' => (int) $offset,
                ];
                if (count($hits) >= $limit) {
                    return $hits;
                }
            }
        }

        return $hits;
    }

    protected function chainLabel(array $chain): string
    {
        return $chain === [] ? '明文' : implode(' → ', $chain);
    }
}
