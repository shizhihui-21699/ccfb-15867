<?php

declare(strict_types=1);

namespace WScan\Cli;

use WScan\Detect\CloakingDetector;
use WScan\Detect\GamblingDetector;
use WScan\Detect\HiddenLinkDetector;
use WScan\Detect\ObfuscationDetector;
use WScan\Detect\WebshellDetector;
use WScan\Report\FindingSet;
use WScan\Report\HtmlReporter;
use WScan\Report\TextReporter;
use WScan\Scan\Baseline;
use WScan\Scan\DatabaseScanner;
use WScan\Scan\DynamicScanner;
use WScan\Scan\FileScanner;
use WScan\Scan\HttpClient;
use WScan\Scan\UrlDiscovery;
use WScan\Support\Config;
use WScan\Version;

/**
 * Command line front end.
 *
 * Usage:
 *   wscan scan    <path>  [--config=f] [--db] [--url=...] [--html=out] [--json=out]
 *   wscan db              [--config=f]
 *   wscan diff    <url>... [--config=f]
 *   wscan baseline <path> --out=file.json
 *   wscan verify  <path>  --baseline=file.json
 */
final class Application
{
    public function __construct(private readonly string $root)
    {
    }

    /** @param list<string> $argv */
    public function run(array $argv): int
    {
        $command = $argv[1] ?? 'help';
        $args = array_slice($argv, 2);

        [$positional, $options] = $this->parseArgs($args);

        try {
            return match ($command) {
                'scan' => $this->cmdScan($positional, $options),
                'db' => $this->cmdDb($options),
                'diff' => $this->cmdDiff($positional, $options),
                'baseline' => $this->cmbBaseline($positional, $options),
                'verify' => $this->cmdVerify($positional, $options),
                'rules', 'help', '--help', '-h' => $this->cmdHelp(),
                default => $this->cmdHelp("未知命令: {$command}"),
            };
        } catch (\Throwable $e) {
            fwrite(STDERR, "\033[1;31m错误:\033[0m " . $e->getMessage() . "\n");

            return 2;
        }
    }

    /**
     * @param list<string> $positional
     * @param array<string,string|bool> $opts
     */
    private function cmdScan(array $positional, array $opts): int
    {
        $path = $positional[0] ?? null;
        if ($path === null) {
            fwrite(STDERR, "用法: wscan scan <目录> [--db] [--url=...] [--html=out.html] [--json=out.json]\n");

            return 2;
        }
        if (!is_dir($path)) {
            throw new \RuntimeException("目录不存在: {$path}");
        }

        $config = $this->loadConfig($opts);
        $detectors = $this->detectors($config);
        $set = new FindingSet($config);
        $started = microtime(true);

        $verbose = isset($opts['verbose']) || isset($opts['v']);
        $progress = $verbose ? static function (string $file, int $n): void {
            if ($n % 50 === 0) {
                fwrite(STDERR, "  已扫描 {$n} 个文件…\r");
            }
        } : null;

        $fileScanner = new FileScanner($config, $detectors, $progress);
        $fileResult = $fileScanner->scanTree($path);
        $set->add($fileResult['findings']);

        $meta = [
            '扫描目录' => $path,
            '文件数' => $fileResult['scanned'],
            '跳过' => $fileResult['skipped'],
            '扫描字节' => $this->humanBytes($fileResult['bytes']),
        ];

        if (isset($opts['db']) || $config->get('database.dsn', '') !== '') {
            $dbScanner = new DatabaseScanner($config, $detectors);
            $dbResult = $dbScanner->scan();
            $set->add($dbResult['findings']);
            $meta['数据库表'] = $dbResult['tables'];
            $meta['数据库行'] = $dbResult['rows'];
            foreach ($dbResult['errors'] as $err) {
                $meta['数据库提示'] = $err;
            }
        }

        $urls = $this->collectUrls($opts, $positional, $config);
        if ($urls !== []) {
            $dyn = new DynamicScanner($config, $detectors);
            $set->add($dyn->scanUrls($urls));
            $meta['动态测试 URL'] = count($urls);
        }

        $meta['用时'] = sprintf('%.2fs', microtime(true) - $started);

        return $this->emit($set, $meta, $opts);
    }

    /** @param array<string,string|bool> $opts */
    private function cmdDb(array $opts): int
    {
        $config = $this->loadConfig($opts);
        if ((string) $config->get('database.dsn', '') === '') {
            throw new \RuntimeException('请通过配置文件设置 database.dsn（例如 mysql:host=127.0.0.1;dbname=cms）');
        }
        $detectors = $this->detectors($config);
        $set = new FindingSet($config);
        $result = (new DatabaseScanner($config, $detectors))->scan();
        $set->add($result['findings']);

        return $this->emit($set, [
            '数据库表' => $result['tables'],
            '列数' => $result['columns'],
            '采样行数' => $result['rows'],
            '错误' => $result['errors'] === [] ? '无' : implode('; ', $result['errors']),
        ], $opts);
    }

    /**
     * @param list<string> $positional
     * @param array<string,string|bool> $opts
     */
    private function cmdDiff(array $positional, array $opts): int
    {
        $config = $this->loadConfig($opts);
        $detectors = $this->detectors($config);
        $set = new FindingSet($config);

        $http = new HttpClient(
            (int) $config->get('http.timeout', 8),
            (bool) $config->get('http.verify_tls', false),
            false,
        );
        $limit = (int) $config->get('http.max_urls_per_site', 25);
        $urls = (new UrlDiscovery($config, $http))->discover($positional, $limit);
        if ($urls === []) {
            throw new \RuntimeException('没有可测试的 URL，请提供站点地址。');
        }

        $set->add((new DynamicScanner($config, $detectors))->scanUrls($urls));

        return $this->emit($set, ['动态测试 URL' => count($urls)], $opts);
    }

    /**
     * @param list<string> $positional
     * @param array<string,string|bool> $opts
     */
    private function cmbBaseline(array $positional, array $opts): int
    {
        $path = $positional[0] ?? null;
        if ($path === null || !is_dir($path)) {
            throw new \RuntimeException('用法: wscan baseline <目录> --out=baseline.json [--config=f]');
        }
        $config = $this->loadConfig($opts);
        $out = is_string($opts['out'] ?? null) ? $opts['out'] : 'baseline.json';
        $result = (new Baseline($config))->build($path, $out);
        fwrite(STDOUT, "\033[1;32m✓\033[0m 已建立基线：{$result['count']} 个文件 → {$result['path']}\n");

        return 0;
    }

    /**
     * @param list<string> $positional
     * @param array<string,string|bool> $opts
     */
    private function cmdVerify(array $positional, array $opts): int
    {
        $path = $positional[0] ?? null;
        if ($path === null || !is_dir($path)) {
            throw new \RuntimeException('用法: wscan verify <目录> --baseline=baseline.json [--config=f]');
        }
        $baselineFile = is_string($opts['baseline'] ?? null) ? $opts['baseline'] : null;
        if ($baselineFile === null) {
            throw new \RuntimeException('缺少 --baseline=文件参数');
        }
        $config = $this->loadConfig($opts);
        $set = new FindingSet($config);
        $result = (new Baseline($config))->verify($path, $baselineFile);
        $set->add($result['findings']);

        return $this->emit($set, [
            '新增' => $result['added'],
            '修改' => $result['modified'],
            '删除' => $result['deleted'],
            '未变' => $result['unchanged'],
        ], $opts);
    }

    /**
     * @param array<string,string|bool> $opts
     * @return list<string>
     */
    private function collectUrls(array $opts, array $positional, Config $config): array
    {
        $urls = [];
        // --url can repeat; parseArgs collapses repeats into a list string.
        if (isset($opts['url'])) {
            $raw = $opts['url'];
            foreach ((array) $raw as $u) {
                foreach (preg_split('/[\s,]+/', (string) $u) ?: [] as $one) {
                    if ($one !== '') {
                        $urls[] = $one;
                    }
                }
            }
        }
        $site = $opts['site'] ?? null;
        if (is_string($site) && $site !== '') {
            $urls[] = $site;
        }
        if ($urls === []) {
            return [];
        }

        $http = new HttpClient(
            (int) $config->get('http.timeout', 8),
            (bool) $config->get('http.verify_tls', false),
            false,
        );
        $limit = (int) $config->get('http.max_urls_per_site', 25);

        return (new UrlDiscovery($config, $http))->discover($urls, $limit);
    }

    /**
     * @param array<string,string|bool> $opts
     */
    private function emit(FindingSet $set, array $meta, array $opts): int
    {
        $ranked = $set->ranked();
        $summary = $set->summary();
        $noColor = isset($opts['no-color']) || getenv('NO_COLOR') !== false;

        $report = (new TextReporter(!$noColor))->render($ranked, $summary, $meta + ['工具' => Version::NAME]);
        fwrite(STDOUT, $report . "\n");

        $outputDir = is_string($opts['out'] ?? null) ? $opts['out'] : null;
        if ($outputDir !== null) {
            if (!is_dir($outputDir)) {
                @mkdir($outputDir, 0775, true);
            }
            $stamp = gmdate('Ymd-His');
            $jsonPath = $outputDir . '/wscan-' . $stamp . '.json';
            $htmlPath = $outputDir . '/wscan-' . $stamp . '.html';
            file_put_contents($jsonPath, json_encode([
                'tool' => Version::NAME,
                'version' => Version::VERSION,
                'generated_at' => gmdate('c'),
                'meta' => $meta,
                'summary' => $summary,
                'findings' => array_map(static fn ($f) => $f->toArray(), $ranked),
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
            file_put_contents($htmlPath, (new HtmlReporter())->render($ranked, $summary, $meta));
            fwrite(STDOUT, "报告已保存:\n  JSON: {$jsonPath}\n  HTML: {$htmlPath}\n");
        }

        if (is_string($opts['html'] ?? null)) {
            file_put_contents($opts['html'], (new HtmlReporter())->render($ranked, $summary, $meta));
            fwrite(STDOUT, "HTML 报告: {$opts['html']}\n");
        }
        if (is_string($opts['json'] ?? null)) {
            file_put_contents($opts['json'], json_encode([
                'tool' => Version::NAME,
                'version' => Version::VERSION,
                'generated_at' => gmdate('c'),
                'meta' => $meta,
                'summary' => $summary,
                'findings' => array_map(static fn ($f) => $f->toArray(), $ranked),
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
            fwrite(STDOUT, "JSON 报告: {$opts['json']}\n");
        }

        // Exit code: 1 when high/critical issues exist, so CI/cron can alert.
        $severe = ($summary['by_level']['critical'] ?? 0) + ($summary['by_level']['high'] ?? 0);

        return $severe > 0 ? 1 : 0;
    }

    /**
     * @param array<string,string|bool> $opts
     */
    private function loadConfig(array $opts): Config
    {
        $file = is_string($opts['config'] ?? null) ? $opts['config'] : null;
        if ($file === null) {
            return Config::fromArray([]);
        }

        return Config::fromFile($file);
    }

    /**
     * @return list<\WScan\Detect\DetectorInterface>
     */
    private function detectors(Config $config): array
    {
        return [
            new CloakingDetector($config),
            new GamblingDetector($config),
            new HiddenLinkDetector($config),
            new ObfuscationDetector($config),
            new WebshellDetector($config),
        ];
    }

    /**
     * @param list<string> $args
     * @return array{0:list<string>,1:array<string,string|bool>}
     */
    private function parseArgs(array $args): array
    {
        $positional = [];
        $options = [];
        foreach ($args as $arg) {
            if (str_starts_with($arg, '--')) {
                $parts = explode('=', substr($arg, 2), 2);
                $name = $parts[0];
                $value = $parts[1] ?? true;
                if (isset($options[$name])) {
                    // Repeatable option -> list.
                    if (!is_array($options[$name])) {
                        $options[$name] = [$options[$name]];
                    }
                    $options[$name][] = $value;
                } else {
                    $options[$name] = $value;
                }
            } elseif (str_starts_with($arg, '-') && strlen($arg) > 1) {
                $options[substr($arg, 1)] = true;
            } else {
                $positional[] = $arg;
            }
        }

        return [$positional, $options];
    }

    private function humanBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];
        $i = 0;
        $value = (float) $bytes;
        while ($value >= 1024 && $i < count($units) - 1) {
            $value /= 1024;
            $i++;
        }

        return sprintf('%.1f %s', $value, $units[$i]);
    }

    private function cmdHelp(string $error = ''): int
    {
        $help = <<<TXT

  WScan — 网站群隐蔽跳转 / 暗链检测工具  v%s

  子命令:
    scan <目录>        扫描文件（模板/缓存/上传目录），可选 --db 与 --url/--site 同时做动态检测
    db                 只扫描数据库文本字段（需在配置中设置 database.dsn）
    diff <url>...      对站点多条 URL 做多访客身份差分，抓“只对特定访客生效”的跳转
    baseline <目录>    为站点建立文件完整性基线  --out=baseline.json
    verify <目录>      与基线比对，找出被篡改/新增/删除的文件  --baseline=baseline.json

  选项:
    --config=<文件>    自定义配置（JSON），深合并默认配置
    --db               扫描时附带数据库扫描
    --url=<地址>       动态检测的种子地址，可重复
    --site=<地址>      同上（站点根地址）
    --out=<目录>       把 JSON + HTML 报告写入目录
    --html=<文件>      指定 HTML 报告路径
    --json=<文件>      指定 JSON 报告路径
    --no-color         关闭终端颜色
    --verbose, -v      显示进度

  退出码: 0=无高危  1=存在高危/严重  2=参数或运行错误

  示例:
    wscan scan /var/www/site --out=reports
    wscan scan /var/www/site --db --site=https://www.example.gov.cn --out=reports
    wscan diff https://www.example.gov.cn --config=config/site.json
    wscan baseline /var/www/site --out=baseline.json
    wscan verify  /var/www/site --baseline=baseline.json --out=reports

TXT;
        $text = sprintf($help, Version::VERSION);
        if ($error !== '') {
            fwrite(STDERR, "\033[1;31m{$error}\033[0m\n");
        }
        fwrite(STDOUT, $text);

        return $error === '' ? 0 : 2;
    }
}
