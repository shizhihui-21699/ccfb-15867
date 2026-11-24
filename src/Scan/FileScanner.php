<?php

declare(strict_types=1);

namespace WScan\Scan;

use WScan\Detect\Subject;
use WScan\Detect\DetectorInterface;
use WScan\Finding;
use WScan\Support\Config;

/**
 * Walks a directory tree, builds a Subject per file and runs the detectors.
 *
 * It deliberately looks in the places trojan PHP hides: template caches,
 * compiled views, upload folders and data directories are scanned even though
 * they are not "source" — a tampered file there is still a tampered file.
 */
final class FileScanner
{
    /** @param list<DetectorInterface> $detectors */
    public function __construct(
        private readonly Config $config,
        private readonly array $detectors,
        private readonly ?\Closure $progress = null,
    ) {
    }

    /**
     * @return array{findings:list<Finding>, scanned:int, skipped:int, bytes:int, errors:list<string>}
     */
    public function scanTree(string $root): array
    {
        $findings = [];
        $scanned = 0;
        $skipped = 0;
        $bytes = 0;
        $errors = [];

        if (!is_dir($root)) {
            return ['findings' => [], 'scanned' => 0, 'skipped' => 0, 'bytes' => 0, 'errors' => ["目录不存在: {$root}"]];
        }

        $extensions = $this->config->getList('scan.extensions');
        $skipExt = $this->config->getList('skip_extensions');
        $skipDirs = $this->config->getList('skip_dirs');
        $maxBytes = (int) $this->config->get('scan.max_file_bytes', 8388608);

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveCallbackFilterIterator(
                new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
                static function (\SplFileInfo $file) use ($skipDirs): bool {
                    if ($file->isDir()) {
                        $name = $file->getFilename();
                        foreach ($skipDirs as $skip) {
                            if ($name === $skip || str_contains($file->getPathname(), '/' . $skip . '/')) {
                                return false;
                            }
                        }
                    }

                    return true;
                },
            ),
            \RecursiveIteratorIterator::SELF_FIRST,
        );

        foreach ($iterator as $file) {
            /** @var \SplFileInfo $file */
            if (!$file->isFile()) {
                continue;
            }
            $path = $file->getPathname();
            $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));

            // Compound extensions: .tpl.php, .blade.php are handled by checking
            // the full suffix list as well.
            $matchesExt = in_array($ext, $extensions, true) || $this->matchesCompound($path, $extensions);
            if (!$matchesExt || in_array($ext, $skipExt, true)) {
                $skipped++;
                continue;
            }

            $size = $file->getSize();
            if ($size === false || $size > $maxBytes) {
                $skipped++;
                continue;
            }

            $content = @file_get_contents($path);
            if ($content === false) {
                $errors[] = "无法读取: {$path}";
                continue;
            }

            $scanned++;
            $bytes += strlen($content);
            if ($this->progress !== null) {
                ($this->progress)($path, $scanned);
            }

            $subject = new Subject(
                content: $content,
                origin: $this->relative($path, $root),
                kind: $this->classifyKind($path),
                config: $this->config,
                meta: ['abs' => $path, 'size' => $size],
            );

            foreach ($this->detectors as $detector) {
                foreach ($detector->inspect($subject) as $finding) {
                    $findings[] = $finding;
                }
            }
        }

        return [
            'findings' => $findings,
            'scanned' => $scanned,
            'skipped' => $skipped,
            'bytes' => $bytes,
            'errors' => $errors,
        ];
    }

    /** @param list<Finding> $findings */
    public function scanFile(string $path): array
    {
        $content = @file_get_contents($path);
        if ($content === false) {
            return [];
        }
        $subject = new Subject($content, $path, $this->classifyKind($path), $this->config, ['abs' => $path]);
        $findings = [];
        foreach ($this->detectors as $detector) {
            foreach ($detector->inspect($subject) as $finding) {
                $findings[] = $finding;
            }
        }

        return $findings;
    }

    /** @param list<string> $extensions */
    private function matchesCompound(string $path, array $extensions): bool
    {
        $lower = strtolower($path);
        foreach ($extensions as $ext) {
            if (str_ends_with($lower, '.' . $ext)) {
                return true;
            }
        }

        return false;
    }

    private function classifyKind(string $path): string
    {
        if (preg_match('#(?:cache|caches|runtime/cache|data/cache|compiled|tpl_c|templates_c)/#i', $path) || str_ends_with(strtolower($path), '.cache')) {
            return 'cache';
        }

        return 'file';
    }

    private function relative(string $path, string $root): string
    {
        $root = rtrim($root, '/') . '/';
        if (str_starts_with($path, $root)) {
            return substr($path, strlen($root));
        }

        return $path;
    }
}
