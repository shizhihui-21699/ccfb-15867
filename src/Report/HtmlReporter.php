<?php

declare(strict_types=1);

namespace WScan\Report;

use WScan\Finding;
use WScan\Support\Text;
use WScan\Version;

/**
 * Self-contained HTML report. No external assets, so it opens offline and is
 * safe to attach to an incident ticket.
 */
final class HtmlReporter
{
    /**
     * @param list<Finding> $findings
     * @param array{total:int,by_level:array<string,int>,by_rule:array<string,int>,max_score:int} $summary
     */
    public function render(array $findings, array $summary, array $meta = []): string
    {
        $e = static fn (string $s): string => htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        $levelColor = [
            Finding::CRITICAL => '#b91c1c',
            Finding::HIGH => '#dc2626',
            Finding::MEDIUM => '#d97706',
            Finding::LOW => '#0284c7',
            Finding::INFO => '#64748b',
        ];

        $rows = '';
        foreach ($findings as $i => $f) {
            $color = $levelColor[$f->level] ?? '#64748b';
            $evidence = '';
            foreach ($f->evidence as $ev) {
                $evidence .= '<div class="ev"><code>' . $e(Text::toUtf8($ev)) . '</code></div>';
            }
            $metaJson = $f->meta !== []
                ? '<details class="meta"><summary>技术细节</summary><pre>' . $e(json_encode($f->meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?: '') . '</pre></details>'
                : '';

            $rows .= <<<HTML
<article class="finding" data-level="{$e($f->level)}">
  <header>
    <span class="badge" style="background:{$color}">{$e(strtoupper($f->level))} · {$f->score}</span>
    <h3>{$e($f->title)}</h3>
  </header>
  <dl>
    <dt>目标</dt><dd><code>{$e($f->target)}</code>{$this->lineBadge($f)}</dd>
    <dt>规则</dt><dd>{$e($f->rule)}</dd>
    <dt>说明</dt><dd>{$e(Text::toUtf8($f->detail))}</dd>
  </dl>
  {$evidence}
  {$metaJson}
</article>
HTML;
        }

        $counts = '';
        foreach ([Finding::CRITICAL, Finding::HIGH, Finding::MEDIUM, Finding::LOW, Finding::INFO] as $lvl) {
            $n = $summary['by_level'][$lvl] ?? 0;
            $color = $levelColor[$lvl];
            $counts .= "<div class=\"stat\"><span class=\"num\" style=\"color:{$color}\">{$n}</span><span class=\"lbl\">{$e($lvl)}</span></div>";
        }

        $metaRows = '';
        foreach ($meta as $k => $v) {
            $val = is_scalar($v) ? (string) $v : (json_encode($v, JSON_UNESCAPED_UNICODE) ?: '');
            $metaRows .= "<tr><th>{$e((string)$k)}</th><td>{$e($val)}</td></tr>";
        }

        $rules = '';
        foreach ($summary['by_rule'] as $rule => $count) {
            $rules .= "<li><code>{$e((string)$rule)}</code> × {$count}</li>";
        }

        $empty = $findings === [] ? '<p class="clean">未发现达到阈值的问题。</p>' : '';
        $ver = Version::VERSION;
        $gen = $e(gmdate('Y-m-d H:i:s'));
        $total = $summary['total'];

        return <<<HTML
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WScan 检测报告</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
         background: #f8fafc; color: #0f172a; line-height: 1.6; }
  header.top { background: #0f172a; color: #e2e8f0; padding: 24px 20px; }
  header.top h1 { margin: 0; font-size: 20px; letter-spacing: .5px; }
  header.top .sub { color: #94a3b8; font-size: 13px; margin-top: 4px; }
  main { max-width: 1000px; margin: 0 auto; padding: 20px; }
  .stats { display: flex; flex-wrap: wrap; gap: 12px; margin: 16px 0 24px; }
  .stat { background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 12px 18px;
          display: flex; flex-direction: column; min-width: 110px; }
  .stat .num { font-size: 26px; font-weight: 700; }
  .stat .lbl { font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: .5px; }
  .panels { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
  @media (max-width: 680px) { .panels { grid-template-columns: 1fr; } }
  .panel { background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 16px; }
  .panel h2 { margin: 0 0 10px; font-size: 14px; color: #475569; text-transform: uppercase; letter-spacing: .5px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 4px 6px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
  th { color: #64748b; font-weight: 500; width: 34%; }
  ul.rules { margin: 0; padding-left: 18px; font-size: 13px; }
  .finding { background: #fff; border: 1px solid #e2e8f0; border-left-width: 5px; border-radius: 8px;
             padding: 14px 16px; margin-bottom: 14px; }
  .finding[data-level="critical"] { border-left-color: #b91c1c; }
  .finding[data-level="high"] { border-left-color: #dc2626; }
  .finding[data-level="medium"] { border-left-color: #d97706; }
  .finding[data-level="low"] { border-left-color: #0284c7; }
  .finding[data-level="info"] { border-left-color: #94a3b8; }
  .finding header { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .finding h3 { margin: 0; font-size: 15px; }
  .badge { color: #fff; border-radius: 999px; padding: 2px 10px; font-size: 11px; font-weight: 700; letter-spacing: .5px; }
  dl { margin: 10px 0; font-size: 13px; }
  dt { color: #64748b; font-size: 11px; text-transform: uppercase; letter-spacing: .4px; margin-top: 6px; }
  dd { margin: 2px 0 0; }
  code { background: #f1f5f9; padding: 1px 5px; border-radius: 4px; font-size: 12px; word-break: break-all; }
  .ev code { display: block; background: #0f172a; color: #e2e8f0; padding: 6px 8px; margin-top: 4px;
             white-space: pre-wrap; }
  details.meta pre { background: #0f172a; color: #cbd5e1; padding: 10px; border-radius: 6px; overflow-x: auto; font-size: 12px; }
  .clean { text-align: center; color: #16a34a; font-size: 16px; padding: 40px; }
  footer { text-align: center; color: #94a3b8; font-size: 12px; padding: 24px; }
  @media (prefers-color-scheme: dark) {
    body { background: #0b1220; color: #e2e8f0; }
    .stat, .panel, .finding { background: #111a2b; border-color: #1e293b; }
    code { background: #1e293b; color: #e2e8f0; }
  }
</style>
</head>
<body>
<header class="top">
  <h1>WScan 网站群隐蔽跳转 / 暗链检测报告</h1>
  <div class="sub">共 {$total} 项发现 · 生成于 {$gen} UTC · v{$ver}</div>
</header>
<main>
  <div class="stats">{$counts}</div>
  <div class="panels">
    <div class="panel"><h2>扫描信息</h2><table>{$metaRows}</table></div>
    <div class="panel"><h2>规则命中分布</h2><ul class="rules">{$rules}</ul></div>
  </div>
  {$empty}
  {$rows}
</main>
<footer>WScan · 本报告为离线静态 HTML，不含外部资源。</footer>
</body>
</html>
HTML;
    }

    private function lineBadge(Finding $f): string
    {
        return $f->line !== null ? ' <span class="line">行 ' . $f->line . '</span>' : '';
    }
}
