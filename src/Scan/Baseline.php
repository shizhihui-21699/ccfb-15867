<?php

declare(strict_types=1);

namespace WScan\Scan;

use WScan\Finding;
use WScan\Support\Config;

/**
 * File-integrity baseline.
 *
 * Content analysis catches known-bad patterns, but the surest way to find a
 * tampered file is to know what it looked like before. `baseline` records a
 * SHA-256 of every scanned file; a later `verify` reports new, changed and
 * deleted files, and flags changed files that also score on a content detector.
 *
 * The baseline is plain JSON so it can be diffed in version control or attached
 * to an incident ticket.
 */
final class Baseline
{
    public function __construct(private readonly Config $config)
    {
    }

    /**
     * @return array{count:int,path:string}
     */
    public function build(string $root, string $outPath): array
    {
        $files = $this->hashTree($root);
        $payload = [
            'generated_at' => gmdate('c'),
            'root' => realpath($root) ?: $root,
            'files' => $files,
        ];
        $dir = dirname($outPath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0775, true);
        }
        file_put_contents($outPath, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

        return ['count' => count($files), 'path' => $outPath];
    }

    /**
     * @return array{findings:list<Finding>,added:int,modified:int,deleted:int,unchanged:int}
     */
    public function verify(string $root, string $baselinePath): array
    {
        if (!is_file($baselinePath)) {
            throw new \RuntimeException("基线文件不存在: {$baselinePath}");
        }
        $raw = file_get_contents($baselinePath);
        $data = json_decode((string) $raw, true);
        if (!is_array($data) || !isset($data['files']) || !is_array($data['files'])) {
            throw new \RuntimeException("基线文件格式无效: {$baselinePath}");
        }

        /** @var array<string,string> $old */
        $old = $data['files'];
        $current = $this->hashTree($root);

        $findings = [];
        $added = 0;
        $modified = 0;
        $deleted = 0;
        $unchanged = 0;

        foreach ($current as $path => $hash) {
            if (!isset($old[$path])) {
                $added++;
                $findings[] = new Finding(
                    rule: 'integrity-added',
                    level: Finding::MEDIUM,
                    score: 45,
                    title: '基线之后新增的文件',
                    target: $path,
                    detail: '该文件不在完整性基线中，可能是后台更新，也可能是被植入的文件。',
                    meta: ['sha256' => $hash],
                );
                continue;
            }
            if (!hash_equals($old[$path], $hash)) {
                $modified++;
                $findings[] = new Finding(
                    rule: 'integrity-modified',
                    level: Finding::HIGH,
                    score: 68,
                    title: '文件内容与基线不一致（疑似被篡改）',
                    target: $path,
                    detail: '该文件在建立基线后被修改。若非正常运维操作，应视为篡改。',
                    evidence: ['原 SHA-256: ' . $old[$path], '现 SHA-256: ' . $hash],
                    meta: ['old_sha256' => $old[$path], 'new_sha256' => $hash],
                );
                continue;
            }
            $unchanged++;
        }

        foreach ($old as $path => $hash) {
            if (!isset($current[$path])) {
                $deleted++;
                $findings[] = new Finding(
                    rule: 'integrity-deleted',
                    level: Finding::MEDIUM,
                    score: 40,
                    title: '基线中的文件被删除',
                    target: $path,
                    detail: '该文件存在于基线中，但当前已不存在。攻击者常删除日志或后门清理痕迹时也会造成此现象。',
                    meta: ['sha256' => $hash],
                );
            }
        }

        return [
            'findings' => $findings,
            'added' => $added,
            'modified' => $modified,
            'deleted' => $deleted,
            'unchanged' => $unchanged,
        ];
    }

    /**
     * @return array<string,string> relative path => sha256
     */
    private function hashTree(string $root): array
    {
        $out = [];
        if (!is_dir($root)) {
            return $out;
        }
        $extensions = $this->config->getList('scan.extensions');
        $skipDirs = $this->config->getList('skip_dirs');
        $maxBytes = (int) $this->config->get('scan.max_file_bytes', 8388608);

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveCallbackFilterIterator(
                new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
                static function (\SplFileInfo $file) use ($skipDirs): bool {
                    if ($file->isDir()) {
                        foreach ($skipDirs as $skip) {
                            if ($file->getFilename() === $skip) {
                                return false;
                            }
                        }
                    }

                    return true;
                },
            ),
        );

        $rootPrefix = rtrim($root, '/') . '/';
        foreach ($iterator as $file) {
            /** @var \SplFileInfo $file */
            if (!$file->isFile()) {
                continue;
            }
            $path = $file->getPathname();
            $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
            $lower = strtolower($path);
            $match = false;
            foreach ($extensions as $e) {
                if ($ext === $e || str_ends_with($lower, '.' . $e)) {
                    $match = true;
                    break;
                }
            }
            if (!$match) {
                continue;
            }
            $size = $file->getSize();
            if ($size === false || $size > $maxBytes) {
                continue;
            }
            $hash = @hash_file('sha256', $path);
            if ($hash === false) {
                continue;
            }
            $rel = str_starts_with($path, $rootPrefix) ? substr($path, strlen($rootPrefix)) : $path;
            $out[$rel] = $hash;
        }

        ksort($out);

        return $out;
    }
}
