<?php
/**
 * 模拟被入侵站点的前台，用于测试动态差分检测 (wscan diff)。
 * 运行: php -S 127.0.0.1:8899 fixtures/server/router.php
 *
 * 行为:
 *  - 桌面浏览器: 返回正常政务页面 + 正常第三方统计
 *  - 百度/谷歌爬虫 或 手机 UA: 返回 302 跳转到博彩站
 *  - /refcloak: 从搜索引擎进入时正文被替换为暗链+跳转（状态码仍是 200）
 */
$ua = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
$ref = strtolower($_SERVER['HTTP_REFERER'] ?? '');
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

$isBot = str_contains($ua, 'baiduspider') || str_contains($ua, 'googlebot') || str_contains($ua, 'bingbot');
$isMobile = str_contains($ua, 'mobile') || str_contains($ua, 'android') || str_contains($ua, 'iphone');
$fromSearch = str_contains($ref, 'baidu.com') || str_contains($ref, 'google.') || str_contains($ref, 'so.com');

$normalPage = function (): string {
    return <<<HTML
<!DOCTYPE html><html><head><meta charset="utf-8"><title>某某县人民政府</title>
<script src="https://hm.baidu.com/hm.js?abc"></script>
<script src="https://res.wx.qq.com/open/js/jweixin-1.6.0.js"></script>
</head><body>
<h1>某某县人民政府</h1>
<nav><a href="/">首页</a><a href="/news/">新闻</a></nav>
<main><p>今日要闻：经济工作会议召开。</p></main>
<script>var _hmt=_hmt||[];(function(){var hm=document.createElement("script");hm.src="https://hm.baidu.com/hm.js?abc";document.body.appendChild(hm);})();</script>
</body></html>
HTML;
};

if ($path === '/sitemap.xml') {
    header('Content-Type: application/xml');
    echo '<?xml version="1.0"?><urlset>';
    echo '<url><loc>http://127.0.0.1:8899/</loc></url>';
    echo '<url><loc>http://127.0.0.1:8899/news/1.html</loc></url>';
    echo '<url><loc>http://127.0.0.1:8899/refcloak</loc></url>';
    echo '</urlset>';
    return true;
}

// 正文差分：仅"从搜索引擎进入"的访客看到被注入的暗链与跳转脚本，
// 状态码保持 200，用于测试 DynamicScanner 的 differential 分支。
if ($path === '/refcloak') {
    $page = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>政策</title></head><body>';
    $page .= '<h1>政策公开</h1><p>正文内容。</p>';
    if ($fromSearch) {
        $page .= '<div style="display:none"><a href="https://www.tyc888.vip/">娱乐城</a></div>';
        $page .= '<script>window.location.replace("https://www.tyc888.vip/r");</script>';
    }
    $page .= '</body></html>';
    header('Content-Type: text/html; charset=utf-8');
    echo $page;
    return true;
}

// 对爬虫/手机：直接 302 到博彩站。
if ($isBot || $isMobile) {
    header('Location: https://www.8888bet-vip.top/landing?id=1', true, 302);
    echo 'redirecting';
    return true;
}

// 来自搜索引擎：页尾注入隐藏暗链 + 跳转脚本（状态码仍为 200）。
if ($fromSearch) {
    $page = str_replace('</body>', '
    <a href="https://www.tyc888.vip/" style="display:none">娱乐城 百家乐</a>
    <script>if(document.referrer.indexOf("baidu")>-1){window.location.href="https://www.tyc888.vip/x";}</script>
    </body>', $normalPage());
    header('Content-Type: text/html; charset=utf-8');
    echo $page;
    return true;
}

header('Content-Type: text/html; charset=utf-8');
echo $normalPage();
return true;
