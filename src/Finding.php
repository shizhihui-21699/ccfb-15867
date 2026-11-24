<?php

declare(strict_types=1);

namespace WScan;

/**
 * One detection result. Severity is a 0-100 score so the report can rank
 * findings and apply thresholds; `level` is the human-facing bucket.
 */
final class Finding
{
    public const CRITICAL = 'critical';
    public const HIGH = 'high';
    public const MEDIUM = 'medium';
    public const LOW = 'low';
    public const INFO = 'info';

    /**
     * @param list<string> $evidence
     * @param array<string,mixed> $meta
     */
    public function __construct(
        public readonly string $rule,
        public readonly string $level,
        public readonly int $score,
        public readonly string $title,
        public readonly string $target,
        public readonly string $detail,
        public readonly array $evidence = [],
        public readonly ?int $line = null,
        public readonly array $meta = [],
    ) {
    }

    public static function levelFromScore(int $score): string
    {
        return match (true) {
            $score >= 85 => self::CRITICAL,
            $score >= 65 => self::HIGH,
            $score >= 40 => self::MEDIUM,
            $score >= 20 => self::LOW,
            default => self::INFO,
        };
    }

    /** @param array<string,mixed> $meta */
    public function toArray(): array
    {
        return [
            'rule' => $this->rule,
            'level' => $this->level,
            'score' => $this->score,
            'title' => $this->title,
            'target' => $this->target,
            'line' => $this->line,
            'detail' => $this->detail,
            'evidence' => $this->evidence,
            'meta' => $this->meta,
        ];
    }
}
