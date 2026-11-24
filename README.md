# WScan — 网站群隐蔽跳转 / 暗链检测工具

针对老旧 PHP 内容管理系统的**隐蔽跳转（cloaking）**与**暗链**检测工具。
它同时做三件事，覆盖恶意代码可能藏身的全部位置：

1. **静态检测**：扫描服务器上的模板、缓存、上传目录、数据文件，并递归解码混淆载荷。
2. **数据库检测**：扫描 CMS 数据库中的文本字段（文章正文、模板片段、站点配置），找出写进库里的注入代码。
3. **动态差分检测**：用多种访客身份（桌面 / 手机 / 百度蜘蛛 / 谷歌蜘蛛 / 微信）实际抓取同一页面，找出"只对特定访客生效"的跳转或暗链。

另外提供**文件完整性基线**功能，用于发现与已知良好状态不一致的被篡改文件。

---

## 它解决的典型症状

> 网站被植入博彩跳转，**只有从搜索引擎点进来或者用手机访问时才跳走**，
> 管理员自己用电脑直接打开一切正常。

这种攻击叫 cloaking（伪装），其特征是**同一 URL 对不同访客返回不同内容**。
因此单纯扫文件是不够的——必须动态地"扮演不同访客"去访问，才能把差异暴露出来。
WScan 的 `diff` 子命令正是为此设计。

同时，恶意代码往往**编码混淆**（`eval(gzinflate(base64_decode(...)))`、`\x68\x74\x74\x70`、
`String.fromCharCode(...)`、`str_rot13` 等），WScan 会逐层解码后再匹配，
所以能看穿包裹在多层编码里的真实载荷。

---

## 快速开始

```bash
# 1. 扫描整个站点目录（模板 + 缓存 + 上传目录 + 数据文件）
php bin/wscan scan /var/www/site --out=reports

# 2. 同时扫描数据库（需先在配置里填写 database.dsn）
php bin/wscan scan /var/www/site --db --config=config/site.json --out=reports

# 3. 动态差分：用 5 种访客身份抓取站点，专抓"只对特定访客生效"的跳转
php bin/wscan diff https://www.example.gov.cn --config=config/site.json

# 4. 建立文件完整性基线，之后定期比对
php bin/wscan baseline /var/www/site --out=baseline.json
php bin/wscan verify  /var/www/site --baseline=baseline.json --out=reports
```

> 运行环境：PHP 8.1+（CLI），需要 `pdo_mysql`（或 `pdo_sqlite`）、`curl`、`mbstring`、`json`、`zlib`。
> 无第三方依赖。

退出码：`0` = 无高危；`1` = 存在高危/严重；`2` = 参数或运行错误。
可直接接入 cron / CI，有高危时触发告警。

---

## 子命令

| 命令 | 作用 |
|------|------|
| `scan <目录>` | 扫描文件；加 `--db` 同时扫数据库；加 `--url/--site` 同时做动态检测 |
| `db` | 只扫描数据库文本字段 |
| `diff <url>...` | 多访客身份差分，抓取"只对特定访客生效"的跳转/暗链 |
| `baseline <目录> --out=f.json` | 建立文件完整性基线（SHA-256） |
| `verify <目录> --baseline=f.json` | 与基线比对，找出被篡改/新增/删除的文件 |

常用选项：`--config=文件`、`--out=目录`（同时输出 JSON+HTML）、`--html=文件`、`--json=文件`、`--no-color`、`-v`。

---

## 扫描位置：恶意代码藏在哪里

`scan` 会遍历目录下所有匹配扩展名的文件，**包括通常不被当作"源码"的地方**：

- `templates/`、`includes/` 等模板与包含文件
- `cache/`、`templates_c/`、`runtime/cache/` 等**编译缓存**（攻击者常改这里，因为不易被察觉）
- `upload/`、`uploads/`、`data/` 等**上传/数据目录**（常见的 webshell 落点）
- `.php .html .htm .js .tpl .twig .cache .json .xml .txt` 等文本文件

超过 `scan.max_file_bytes`（默认 8MB）的文件会跳过，二进制文件会自动忽略。

---

## 检测规则

每条发现带 0–100 的风险分，并归入 `critical / high / medium / low / info` 五档。

### 1. 伪装跳转 `cloaking`（静态）

正常页面**不会**在读取访客特征（UA / Referer / Cookie）之后再跳转。规则打分基于以下信号的组合：

- 读取访客特征（UA / Referer）
- 检测搜索引擎爬虫（Baiduspider / Googlebot / bingbot …，或 Referer 命中搜索引擎域名）
- 检测移动端 / 微信
- 存在跳转动作（`location.href=` / `location.replace(` / `header('Location:')` / meta refresh）
- 跳转目标指向站外、且不在白名单的域名

"爬虫检测 + 跳转"是最强组合；再叠加站外目标即判为严重。

### 2. 博彩内容 `gambling-keywords` / `gambling-domains`

- **关键词**：中文博彩词（博彩、娱乐城、百家乐、时时彩、六合彩……）与已知品牌词。
  单一关键词出现在新闻正文里不会重判；多个不同词、或词出现在**链接文字 / script / 隐藏元素**中才升级。
- **域名**：高风险后缀（`.vip .xyz .top .club .bet .cc …`）、机器生成域名、IP 直连。
  **白名单内的域名（百度统计、CNZZ、Google Analytics、CDN 等）一律忽略。**

### 3. 隐藏暗链 `hidden_link`

视觉隐藏的站外链接（SEO 暗链的典型特征）。识别手法：

- `display:none` / `visibility:hidden` / `font-size:0` / `text-indent:-9999px`
- `height:1px` + `overflow:hidden`、`position:absolute; left:-9999px`
- 前景色与背景色相同、`opacity:0`、`clip:rect(0…)`、HTML `hidden` 属性

隐藏手法 + 站外域名才计分；域名形态可疑或链接文字含博彩词再加分。
指向站内或白名单域名的正常链接不会误报。

### 4. 代码混淆 `obfuscation`

- `eval` / `assert` / `create_function` 组合 `base64_decode` / `gzinflate` / `str_rot13` / `strrev` / `hex2bin`
- 分段拼接函数名、可变函数调用
- 多层嵌套编码、超长高熵 base64 字面量
- **解码后**若含跳转动作或博彩词，显著升级
- PHP 上下文比 JS 更可疑

`static/lib/`、`vendor/` 等第三方库目录中的发现会**降级**（minify 的库代码本来就"像"混淆）。

### 5. WebShell 后门 `webshell`

- 请求参数（`$_POST/$_GET/$_REQUEST`）直接进入执行函数
- `eval(base64_decode($_POST[...]))` 之类的编码请求执行
- 极短文件仅含一个执行调用
- 上传/缓存目录中随机命名的 PHP

### 6. 伪装跳转 `cloaking-redirect` / `cloaking-dynamic`（动态）

由 `diff` 命令产生，见下节。

### 7. 文件完整性 `integrity-*`

由 `verify` 命令产生：新增 / 修改 / 删除的文件，与基线比对得出。

---

## 动态差分检测（`diff`）——本工具的核心

旧式跳转只对特定访客生效，静态扫描无法证明"条件性"。`diff` 用 5 个访客档案
（`http.profiles` 可配置）访问同一批 URL：

| 档案 | 用途 |
|------|------|
| `desktop` | 基线（管理员/普通用户） |
| `mobile` | 手机 |
| `baiduspider` | 百度蜘蛛（带百度 Referer） |
| `googlebot` | 谷歌蜘蛛（带谷歌 Referer） |
| `wechat` | 微信内置浏览器 |

对比维度和判定：

- **HTTP 状态 / Location**：某档案收到 3xx 而基线是 200 → `cloaking-redirect`。跳转目标是站外可疑域名时直接判严重。
- **正文结构**：先归一化（去掉时间戳、随机数、脚本内容等易变 token），算 token 相似度；
  低于阈值（默认 0.82）记为显著差异。
- **差异切片**：只提取"嫌疑档案有、基线没有"的行，这就是"条件内容"。
  再对这段差异跑博彩/暗链/跳转等检测器。
- **差异域名**：只出现在嫌疑档案、基线里没有的站外域名。

**为什么要先做差分**：正常站点的统计像素、广告脚本在所有档案里都会加载，
差分后自然抵消；只有"有条件才出现"的内容会留在差异里，从而压住误报。

URL 来源：命令行 `--url/--site`、站点 `sitemap.xml`、首页同站链接。

---

## 配置

默认配置见 `config/defaults.php`。用 `--config=文件.json` 传入自定义配置，
会与默认配置**深合并**（只覆盖你写的键）。示例见 `config/site.example.json`。

最关键的几项：

```jsonc
{
  // 本站群拥有的注册域名（其链接永不被当作外链）
  "site_domains": ["example.gov.cn", "news.example.gov.cn"],

  // 正常的第三方依赖（统计/广告/CDN），命中即忽略
  "allowlist_domains": ["hm.baidu.com", "*.baidu.com", "*.cnzz.com"],

  // 数据库连接
  "database": {
    "dsn": "mysql:host=127.0.0.1;dbname=cms;charset=utf8mb4",
    "user": "readonly",
    "password": "******",
    "sample_rows": 200
  },

  // 动态差分
  "http": {
    "enabled": true,
    "max_urls_per_site": 25,
    "cloak_similarity_threshold": 0.82
  }
}
```

> **安全提示**：数据库账号请使用**只读**账号；`*.json`/`.env` 已在 `.gitignore` 中，
> 但请勿把真实密码提交进版本库。建议通过环境变量或独立的配置文件（妥善保管）提供。

---

## 在网站群上如何落地

几十个部门网站跑在同一套 CMS 上，建议这样用：

1. **建立基线**：对每个站点目录跑一次 `baseline`，作为"已知良好"的起点（放在各站自己的目录或统一仓库）。
2. **定期全量静态扫描**：`scan` 每个站点目录 + 数据库，输出到统一报告目录。
3. **定期完整性比对**：`verify` 与基线比对，优先看 `integrity-modified`。
4. **重点站做动态差分**：对暴露在公网的站点跑 `diff`（可配合 sitemap 扩大覆盖）。
5. **收敛白名单**：首次运行很可能在白名单外的正常第三方脚本上产生低分提示，
   把这些域名加入 `allowlist_domains` 再跑，误报会迅速下降。

因为多站共用一套 CMS，**同一处模板/包含文件**的改动会在多个站点同时出现——
这反而是线索：若某个 `includes/*.php` 在多个站点都被改，基本可确定是 CMS 层被入侵。

---

## 处置建议（发现后）

1. **先隔离**：记录 `verify`/`scan` 报告（含文件 SHA-256、精确行号、数据库表/列/主键），
   再对站点做只读或下线，避免继续扩散。
2. **清理三类位置**：被篡改的模板/包含文件、编译缓存（全部清空重建）、数据库中被注入的字段（先备份再修）。
3. **加固入口**：检查上传目录是否可执行 PHP、CMS 及插件版本漏洞、后台弱口令、
   webshell 落点（`upload/`、`data/` 下的随机命名 PHP）。
4. **复查**：清理后重跑 `scan` + `diff`，确认归零；把清理后的干净状态作为新基线。

---

## 报告

- **终端**：按风险排序、带颜色的明细（`--no-color` 关闭颜色）。
- **JSON**：机器可读，含每条发现的规则、分数、目标、行号、证据、`meta`。
- **HTML**：单文件、无外部资源，可离线打开、附进工单。

---

## 局限与说明

- 基于规则与启发式，**不是杀毒软件**：高分强烈提示，但仍需人工确认证据后再处置。
- 动态检测需要目标站点可达；内网站点请在能访问的位置运行，或改用被动日志分析。
- 编码混淆的解码有深度/体积/膨胀比上限（防 zip bomb 与死循环），极端构造的载荷可能解不全。
- 数据库扫描按表抽样（`sample_rows`），超大表不会全量深扫；可用 `include_tables` 精确指定。
- `site_domains` 与 `allowlist_domains` 的准确性直接决定误报率，请按实际站点群维护。

## 开发与测试

```bash
php tests/run.php           # 30 项单元/集成测试
```

测试夹具在 `fixtures/site/`（含正常页、被注入的头部、混淆缓存、暗链、webshell），
`fixtures/server/router.php` 是一个会按访客身份 cloaking 的模拟站点，用于验证 `diff`：

```bash
php -S 127.0.0.1:8899 fixtures/server/router.php &
php bin/wscan diff http://127.0.0.1:8899
```
