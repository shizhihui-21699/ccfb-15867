<?php

declare(strict_types=1);

namespace WScan\Detect;

use WScan\Support\Config;
use WScan\Support\Decoder;
use WScan\Support\Text;

/**
 * One piece of inspectable content plus everything a detector needs to reason
 * about it. Lazily computes expensive derived data (decoded layers, normalized
 * text) so detectors can share it.
 */
final class Subject
{
    /** @var list<array{text:string,chain:list<string>}>|null */
    private ?array $layers = null;

    private ?string $normalized = null;

    /**
     * @param string $content Raw bytes.
     * @param string $origin Human path / URL / "db:table.column#row".
     * @param string $kind   file | cache | db | http
     */
    public function __construct(
        public readonly string $content,
        public readonly string $origin,
        public readonly string $kind,
        public readonly Config $config,
        public readonly array $meta = [],
    ) {
    }

    public function size(): int
    {
        return strlen($this->content);
    }

    public function isBinary(): bool
    {
        return Text::looksBinary($this->content);
    }

    /** True when findings should be softened (vendor JS, bundled libs). */
    public function isDowngraded(): bool
    {
        $paths = $this->config->getList('downgrade_paths');
        foreach ($paths as $path) {
            if ($path !== '' && str_contains($this->origin, $path)) {
                return true;
            }
        }

        return false;
    }

    /**
     * All plausible decoded variants (including the original).
     *
     * @return list<array{text:string,chain:list<string>}>
     */
    public function layers(): array
    {
        if ($this->layers === null) {
            $this->layers = Decoder::decodeAll($this->content);
        }

        return $this->layers;
    }

    public function normalized(): string
    {
        if ($this->normalized === null) {
            $this->normalized = Text::normalizeSpace($this->content);
        }

        return $this->normalized;
    }

    public function lineOf(int $offset): int
    {
        return Text::lineAt($this->content, $offset);
    }

    public function evidence(int $offset, int $before = 70, int $after = 110): string
    {
        return Text::snippet($this->content, $offset, $before, $after);
    }

    /** @return list<string> */
    public function siteDomains(): array
    {
        return $this->config->getList('site_domains');
    }

    /** @return list<string> */
    public function allowlist(): array
    {
        return $this->config->getList('allowlist_domains');
    }
}
