<?php

declare(strict_types=1);

/**
 * Default configuration for WScan.
 *
 * Everything is overridable from a user config passed with --config, which is
 * deep-merged on top of these defaults. Keep this file free of secrets.
 */
return [
    'version' => 1,

    // Registrable domains owned by this site group. Links to these are never
    // treated as injected external links.
    'site_domains' => [
        // 'gov.example.cn',
    ],

    // Hosts that are normal, expected third-party dependencies. Anything here is
    // ignored by the link/script detectors. The defaults cover the analytics and
    // ad scripts that legitimately appear on most government sites.
    'allowlist_domains' => [
        // Chinese analytics / statistics commonly bundled with CMS templates.
        'hm.baidu.com', '*.baidu.com', '*.bdstatic.com', '*.google-analytics.com',
        '*.googletagmanager.com', '*.cnzz.com', '*.51.la', '*.51yes.com',
        '*.umeng.com', '*.mmstat.com', '*.bdimg.com', '*.qq.com', '*.gtimg.com',
        '*.sina.com.cn', '*.weibo.com', '*.tanx.com', '*.alicdn.com', '*.aliyun.com',
        '*.unionpay.com', '*.gtags.net', '*.histats.com', '*.statcounter.com',
        // CDNs / font / UI libs.
        '*.bootcdn.net', '*.staticfile.org', '*.cdnjs.cloudflare.com', '*.jsdelivr.net',
        '*.jquery.com', '*.w3.org', '*.schema.org', '*.fonts.googleapis.com',
        '*.gstatic.com', '*.qqmail.com', '*.cdn.gov.cn',
    ],

    // Paths that are expected to contain obfuscation or third-party JS; findings
    // here are downgraded rather than dropped so a human can review.
    'downgrade_paths' => [
        'vendor/', 'node_modules/', 'static/lib/', 'static/plugins/', 'assets/lib/',
    ],

    // Files never scanned (large binaries, backups, media).
    'skip_extensions' => [
        'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'ico', 'svg', 'woff', 'woff2',
        'ttf', 'eot', 'otf', 'mp3', 'mp4', 'avi', 'mov', 'flv', 'wmv', 'zip', 'rar',
        '7z', 'gz', 'tar', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    ],

    // Directories skipped during a filesystem scan.
    'skip_dirs' => ['.git', '.svn', 'node_modules', '.idea', '.vscode', 'runtime/log'],

    'scan' => [
        'max_file_bytes' => 8388608,
        'extensions' => [
            'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar', 'inc',
            'html', 'htm', 'shtml', 'js', 'tpl', 'twig', 'smarty', 'theme',
            'tpl.php', 'blade.php', 'cache', 'json', 'xml', 'txt',
        ],
        'follow_symlinks' => false,
    ],

    // Weights and toggles for each detector.
    'rules' => [
        'cloaking' => ['enabled' => true, 'weight' => 1.0],
        'gambling' => ['enabled' => true, 'weight' => 1.0],
        'redirect' => ['enabled' => true, 'weight' => 1.0],
        'hidden_link' => ['enabled' => true, 'weight' => 1.0],
        'obfuscation' => ['enabled' => true, 'weight' => 0.9],
        'webshell' => ['enabled' => true, 'weight' => 1.0],
        'integrity' => ['enabled' => true, 'weight' => 1.0],
        'database' => ['enabled' => true, 'weight' => 1.0],
    ],

    // Keywords that indicate gambling / adult-redirect landing traffic. Used on
    // both raw and decoded text. Lower-cased; matched as substrings on decoded
    // text and as tokens on raw text to keep false positives down.
    'gambling_keywords' => [
        '博彩', '赌博', '下注', '押注', '娱乐城', '真人荷官', '百家乐', '老虎机',
        '彩票', '时时彩', '六合彩', '棋牌', '赌场', '澳门金沙', '葡京', '威尼斯人',
        '太阳城', 'bet365', '太阳成', '捕鱼', '电子游艺', '体育投注', '足球投注',
        'ag真人', 'mg电子', 'pg电子', '开元棋牌', '乐游', '新葡京', '银河娱乐',
        'casino', 'slot', 'jackpot', 'betting', 'sportsbook', 'poker',
    ],

    // Phrases seen in SEO-redirect injectors.
    'redirect_keywords' => [
        'window.location', 'location.href', 'location.replace', 'top.location',
        'document.location', 'self.location', 'window.open(',
    ],

    // Markers of conditional delivery to crawlers / mobile visitors.
    'cloak_signals' => [
        'user-agent' => ['user_agent', 'http_user_agent', 'useragent', 'strpos($_server[\'http_user_agent\']'],
        'bot' => ['bot', 'spider', 'baiduspider', 'googlebot', 'bingbot', 'yisouspider', 'sogou', '360spider', 'bytespider'],
        'mobile' => ['mobile', 'android', 'iphone', 'ipad', 'micromessenger', 'wechat', 'harmonyos'],
        'referer' => ['http_referer', 'referer', 'referrer', '$_server[\'http_referer\']'],
        'crawler_domains' => ['baidu.com', 'google.', 'bing.com', 'so.com', 'sogou.com', 'sm.cn', 'yandex.', 'yahoo.'],
    ],

    // Known webshell / backdoor markers.
    'webshell_markers' => [
        'eval(', 'assert(', 'system(', 'passthru(', 'shell_exec(', 'popen(', 'proc_open(',
        'base64_decode(', 'gzinflate(', 'str_rot13(', 'create_function(', 'preg_replace(',
        '$_request', '$_post', '$_get', '$_cookie', 'call_user_func', 'array_map(',
    ],

    // Dynamic scanning (HTTP) settings.
    'http' => [
        'enabled' => true,
        'timeout' => 8,
        'max_urls_per_site' => 25,
        'concurrency' => 4,
        'verify_tls' => false,
        'follow_redirects' => false,
        // Visitor profiles used to detect cloaking: the same URL is fetched
        // once per profile and the responses are diffed.
        'profiles' => [
            'desktop' => [
                'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
                'headers' => [],
            ],
            'mobile' => [
                'user_agent' => 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
                'headers' => ['X-Wap-Profile' => 'http://wap.samsungmobile.com/uaprof/'],
            ],
            'baiduspider' => [
                'user_agent' => 'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
                'headers' => ['Referer' => 'https://www.baidu.com/'],
            ],
            'googlebot' => [
                'user_agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
                'headers' => ['Referer' => 'https://www.google.com/'],
            ],
            'wechat' => [
                'user_agent' => 'Mozilla/5.0 (Linux; Android 13; M2012K11AC Build/TKQ1.220829.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/116.0 Mobile Safari/537.36 MicroMessenger/8.0.47.2560',
                'headers' => [],
            ],
        ],
        // Diff similarity below this means the page differs materially between
        // visitor profiles -> suspected cloaking.
        'cloak_similarity_threshold' => 0.82,
    ],

    // Database scanning.
    'database' => [
        'dsn' => '',                 // e.g. mysql:host=127.0.0.1;dbname=cms
        'user' => '',
        'password' => '',
        'sample_rows' => 200,        // rows sampled per table for deep decoding
        'text_columns_only' => true,
        'tables' => [],              // empty = auto-discover all text columns
        'include_tables' => [],
        'exclude_tables' => ['*_log', '*_logs', 'session*', 'sys_*'],
    ],

    // Reporting.
    'report' => [
        'min_level' => 'low',        // low|medium|high|critical
        'max_evidence_per_finding' => 5,
        'output_dir' => 'reports',
    ],
];
