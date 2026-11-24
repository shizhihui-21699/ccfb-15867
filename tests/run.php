<?php

declare(strict_types=1);

/**
 * Zero-dependency test runner.
 *
 * Each test is a closure; the runner reports pass/fail and returns a non-zero
 * exit code on failure so it can gate CI. Run:
 *
 *   php tests/run.php
 */

require dirname(__DIR__) . '/src/autoload.php';

use WScan\Detect\CloakingDetector;
use WScan\Detect\GamblingDetector;
use WScan\Detect\HiddenLinkDetector;
use WScan\Detect\ObfuscationDetector;
use WScan\Detect\Subject;
use WScan\Detect\WebshellDetector;
use WScan\Support\Config;
use WScan\Support\Decoder;
use WScan\Support\Domains;
use WScan\Support\Text;

$pass = 0;
$fail = 0;
$failures = [];

/** @param callable():void $fn */
function test(string $name, callable $fn): void
{
    global $pass, $fail, $failures;
    try {
        $fn();
        $pass++;
        fwrite(STDOUT, "  \033[32m✓\033[0m {$name}\n");
    } catch (\Throwable $e) {
        $fail++;
        $failures[] = [$name, $e->getMessage()];
        fwrite(STDOUT, "  \033[31m✗\033[0m {$name}\n      " . $e->getMessage() . "\n");
    }
}

function assertTrue(bool $cond, string $msg = 'expected true'): void
{
    if (!$cond) {
        throw new \RuntimeException($msg);
    }
}

function assertSame(mixed $expected, mixed $actual, string $msg = ''): void
{
    if ($expected !== $actual) {
        throw new \RuntimeException(($msg !== '' ? $msg . ': ' : '') . 'expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
    }
}

function assertContains(string $needle, string $haystack, string $msg = ''): void
{
    if (!str_contains($haystack, $needle)) {
        throw new \RuntimeException(($msg !== '' ? $msg . ': ' : '') . "'{$needle}' not found");
    }
}

/** @param list<\WScan\Finding> $findings */
function scoreOf(array $findings, string $rule): int
{
    foreach ($findings as $f) {
        if ($f->rule === $rule) {
            return $f->score;
        }
    }

    return 0;
}

function cfg(array $overrides = []): Config
{
    return Config::fromArray($overrides);
}

function subject(string $content, string $origin = 'test.php', array $cfg = []): Subject
{
    return new Subject($content, $origin, 'file', cfg($cfg));
}

fwrite(STDOUT, "\nWScan test suite\n================\n");

// ---------------------------------------------------------------------------
fwrite(STDOUT, "\n[Support: Text]\n");

test('snippet never splits a UTF-8 character', function (): void {
    $text = str_repeat('中', 100);
    $s = Text::snippet($text, 150, 5, 5); // offset lands mid-character
    assertTrue(mb_check_encoding($s, 'UTF-8'), 'snippet produced invalid UTF-8');
    assertContains('中', $s);
});

test('normalizeForDiff strips timestamps and scripts', function (): void {
    $a = '<div>t=1700000000<script>var x=1</script></div>';
    $b = '<div>t=1800000123<script>var x=999</script></div>';
    assertSame(Text::normalizeForDiff($a), Text::normalizeForDiff($b));
});

test('similarity: identical is 1, different is low', function (): void {
    assertSame(1.0, Text::similarity('abc def ghi', 'abc def ghi'));
    assertTrue(Text::similarity('aaa bbb ccc', 'xxx yyy zzz') < 0.2);
});

test('decodeEscapes handles \\x and \\u', function (): void {
    assertSame('http', Text::decodeEscapes('\\x68\\x74\\x74\\x70'));
    assertSame('http', Text::decodeEscapes('\\u0068\\u0074\\u0074\\u0070'));
});

// ---------------------------------------------------------------------------
fwrite(STDOUT, "\n[Support: Domains]\n");

test('registrable handles multi-label suffix', function (): void {
    assertSame('abc.gov.cn', Domains::registrable('www.abc.gov.cn'));
    assertSame('example.com', Domains::registrable('a.b.example.com'));
});

test('allowlist wildcard', function (): void {
    assertTrue(Domains::matchesPattern('hm.baidu.com', '*.baidu.com'));
    assertTrue(Domains::matchesPattern('baidu.com', 'baidu.com'));
    assertTrue(!Domains::matchesPattern('notbaidu.com', '*.baidu.com'), 'false subdomain match');
});

test('extractUrls finds protocol-relative and escaped slashes', function (): void {
    $urls = Domains::extractUrls('x="//evil.top/a" y="https:\\/\\/bad.xyz\\/b"');
    $hosts = array_map(static fn (array $u): string => $u['host'], $urls);
    assertTrue(in_array('evil.top', $hosts, true));
    assertTrue(in_array('bad.xyz', $hosts, true));
});

test('suspicious tld / generated label', function (): void {
    assertTrue(Domains::hasSuspiciousTld('x.vip'));
    assertTrue(Domains::hasGeneratedLabel('8888bet-vip-77.top'));
    assertTrue(!Domains::hasGeneratedLabel('news.example.com'), 'normal domain flagged');
});

// ---------------------------------------------------------------------------
fwrite(STDOUT, "\n[Support: Decoder]\n");

test('decodes base64', function (): void {
    $text = "echo '" . base64_encode('window.location="http://evil.top"') . "';";
    $found = false;
    foreach (Decoder::layers($text) as $layer) {
        if (str_contains($layer['text'], 'window.location')) {
            $found = true;
        }
    }
    assertTrue($found, 'base64 payload not recovered');
});

test('decodes base64+gzinflate nested', function (): void {
    $payload = 'if(strpos($_SERVER["HTTP_USER_AGENT"],"spider")!==false){header("Location: https://x.vip");}';
    $wrapped = "eval(gzinflate(base64_decode('" . base64_encode(gzdeflate($payload)) . "')));";
    $found = false;
    foreach (Decoder::layers($wrapped) as $layer) {
        if (str_contains($layer['text'], 'spider') && str_contains($layer['text'], 'x.vip')) {
            $found = true;
        }
    }
    assertTrue($found, 'nested payload not recovered');
});

test('decodes fromCharCode', function (): void {
    $codes = array_map('ord', str_split('http://evil.top'));
    $text = 'String.fromCharCode(' . implode(',', $codes) . ');';
    $found = false;
    foreach (Decoder::layers($text) as $layer) {
        if (str_contains($layer['text'], 'evil.top')) {
            $found = true;
        }
    }
    assertTrue($found);
});

test('decodes hex escapes', function (): void {
    $text = 'var x="' . implode('', array_map(static fn (string $c): string => sprintf('\\x%02x', ord($c)), str_split('http://evil.top'))) . '";';
    $found = false;
    foreach (Decoder::layers($text) as $layer) {
        if (str_contains($layer['text'], 'evil.top')) {
            $found = true;
        }
    }
    assertTrue($found);
});

test('zip bomb is bounded', function (): void {
    // 7 MB of zeros compresses to a few KB; the decoder must refuse to expand it.
    $bomb = gzdeflate(str_repeat("\0", 7_000_000));
    $text = "eval(gzinflate(base64_decode('" . base64_encode($bomb) . "')));";
    $start = microtime(true);
    foreach (Decoder::layers($text) as $layer) {
        assertTrue(strlen($layer['text']) < 5_000_000, 'expansion not bounded');
    }
    assertTrue(microtime(true) - $start < 5.0, 'decoder took too long');
});

// ---------------------------------------------------------------------------
fwrite(STDOUT, "\n[Detector: Cloaking]\n");

test('PHP UA-gated header redirect is CRITICAL', function (): void {
    $src = '<?php $ua=strtolower($_SERVER["HTTP_USER_AGENT"]);'
        . 'if(strpos($ua,"baiduspider")!==false){header("Location: https://www.bet-vip.top/x");exit;}';
    $f = (new CloakingDetector(cfg()))->inspect(subject($src));
    assertTrue(scoreOf($f, 'cloaking') >= 85, 'expected critical, got ' . scoreOf($f, 'cloaking'));
});

test('JS referer-gated location.replace is flagged', function (): void {
    $js = 'var r=document.referrer;if(r.indexOf("baidu.com")>-1){window.location.replace("https://x.top/r");}';
    $f = (new CloakingDetector(cfg()))->inspect(subject($js, 'a.html'));
    assertTrue(scoreOf($f, 'cloaking') >= 60, 'got ' . scoreOf($f, 'cloaking'));
});

test('plain UA read without redirect is not high', function (): void {
    $js = 'var ua=navigator.userAgent;_hmt.push(["_setDeviceType", ua]);';
    $f = (new CloakingDetector(cfg()))->inspect(subject($js, 'a.html'));
    assertTrue(scoreOf($f, 'cloaking') < 40, 'false positive: ' . scoreOf($f, 'cloaking'));
});

test('reading document.location.href is not a sink', function (): void {
    $js = 'var y=e.location;var b=e.document.location.href||"";';
    $f = (new CloakingDetector(cfg()))->inspect(subject($js, 'vendor.min.js'));
    assertSame(0, scoreOf($f, 'cloaking'));
});

// ---------------------------------------------------------------------------
fwrite(STDOUT, "\n[Detector: Gambling]\n");

test('gambling keyword cluster in hidden links is CRITICAL', function (): void {
    $html = '<a href="https://x.club" style="display:none">博彩 娱乐城 百家乐 老虎机 时时彩</a>';
    $f = (new GamblingDetector(cfg()))->inspect(subject($html, 'a.html'));
    assertTrue(scoreOf($f, 'gambling-keywords') >= 60, 'got ' . scoreOf($f, 'gambling-keywords'));
});

test('allow-listed analytics domains are ignored', function (): void {
    $html = '<script src="https://hm.baidu.com/hm.js"></script><script src="https://v1.cnzz.com/z.js"></script>';
    $f = (new GamblingDetector(cfg()))->inspect(subject($html, 'a.html'));
    assertSame(0, scoreOf($f, 'gambling-domains'));
});

test('suspicious .vip domain is flagged even without keywords', function (): void {
    $html = '<a href="https://www.tyc888.vip/x">查看</a>';
    $f = (new GamblingDetector(cfg()))->inspect(subject($html, 'a.html'));
    assertTrue(scoreOf($f, 'gambling-domains') >= 40, 'got ' . scoreOf($f, 'gambling-domains'));
});

test('single gambling word in article body is not CRITICAL', function (): void {
    $html = '<p>本县开展打击博彩违法犯罪专项行动。</p>';
    $f = (new GamblingDetector(cfg()))->inspect(subject($html, 'a.html'));
    assertTrue(scoreOf($f, 'gambling-keywords') < 60, 'over-scored: ' . scoreOf($f, 'gambling-keywords'));
});

// ---------------------------------------------------------------------------
fwrite(STDOUT, "\n[Detector: HiddenLink]\n");

test('display:none external anchor is flagged', function (): void {
    $html = '<a href="https://www.x.club/" style="display:none">link</a>';
    $f = (new HiddenLinkDetector(cfg()))->inspect(subject($html, 'a.html'));
    assertTrue($f !== [] && $f[0]->score >= 40, 'not flagged');
});

test('normal visible internal link is not flagged', function (): void {
    $html = '<a href="/news/1.html">新闻</a><a href="https://www.gov.cn/">中国政府网</a>';
    $f = (new HiddenLinkDetector(cfg(['site_domains' => ['example.gov.cn']])))->inspect(subject($html, 'a.html'));
    assertSame([], $f);
});

test('colour-equals-background trick is flagged', function (): void {
    $html = '<a href="https://x.top" style="color:#ffffff;background-color:#ffffff;font-size:1px;height:1px">x</a>';
    $f = (new HiddenLinkDetector(cfg()))->inspect(subject($html, 'a.html'));
    assertTrue($f !== [] && $f[0]->score >= 20, 'not flagged');
});

// ---------------------------------------------------------------------------
fwrite(STDOUT, "\n[Detector: Obfuscation]\n");

test('eval+gzinflate+base64 is flagged and decoded', function (): void {
    $payload = 'header("Location: https://x.vip");';
    $src = "<?php eval(gzinflate(base64_decode('" . base64_encode(gzdeflate($payload)) . "')));";
    $f = (new ObfuscationDetector(cfg()))->inspect(subject($src, 'a.php'));
    assertTrue($f !== [] && $f[0]->score >= 60, 'got ' . ($f[0]->score ?? 0));
});

test('minified vendor JS is downgraded', function (): void {
    $js = 'var a=1;' . str_repeat('function x(e){return e}', 50);
    $f = (new ObfuscationDetector(cfg()))->inspect(subject($js, 'static/lib/vendor.min.js'));
    foreach ($f as $finding) {
        assertTrue($finding->score < 40, 'vendor not downgraded: ' . $finding->score);
    }
});

// ---------------------------------------------------------------------------
fwrite(STDOUT, "\n[Detector: Webshell]\n");

test('eval($_POST) one-liner is flagged', function (): void {
    $f = (new WebshellDetector(cfg()))->inspect(subject('<?php @eval($_POST["cmd"]);', 'upload/2024/x.php'));
    assertTrue($f !== [] && $f[0]->score >= 60, 'not flagged');
});

test('normal database query file is not flagged', function (): void {
    $src = '<?php $stmt=$pdo->prepare("SELECT * FROM t WHERE id=?");$stmt->execute([$id]);';
    $f = (new WebshellDetector(cfg()))->inspect(subject($src, 'includes/db.php'));
    assertSame([], $f);
});

// ---------------------------------------------------------------------------
fwrite(STDOUT, "\n[Integration: fixtures]\n");

test('benign analytics fixture produces no high findings', function (): void {
    $root = dirname(__DIR__) . '/fixtures/site/templates/index.html';
    $content = file_get_contents($root);
    assertTrue($content !== false);
    $config = cfg();
    $sub = new Subject($content, 'templates/index.html', 'file', $config);
    $detectors = [
        new CloakingDetector($config),
        new GamblingDetector($config),
        new HiddenLinkDetector($config),
        new WebshellDetector($config),
    ];
    foreach ($detectors as $d) {
        foreach ($d->inspect($sub) as $finding) {
            assertTrue($finding->score < 40, $d->name() . ' false positive: ' . $finding->score);
        }
    }
});

test('obfuscated cache fixture is flagged', function (): void {
    $path = dirname(__DIR__) . '/fixtures/site/cache/tpl_news_001.php';
    $content = file_get_contents($path);
    assertTrue($content !== false);
    $config = cfg();
    $sub = new Subject($content, 'cache/tpl_news_001.php', 'cache', $config);
    $cloak = (new CloakingDetector($config))->inspect($sub);
    assertTrue(scoreOf($cloak, 'cloaking') >= 85, 'obfuscated cloaking missed');
});

// ---------------------------------------------------------------------------
fwrite(STDOUT, "\n" . str_repeat('─', 48) . "\n");
fwrite(STDOUT, sprintf("结果: %d 通过, %d 失败\n", $pass, $fail));
if ($fail > 0) {
    fwrite(STDOUT, "\n失败项:\n");
    foreach ($failures as [$name, $msg]) {
        fwrite(STDOUT, "  - {$name}: {$msg}\n");
    }
}

exit($fail > 0 ? 1 : 0);
