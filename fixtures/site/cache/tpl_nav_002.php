<?php
/**
 * 正常模板缓存文件（编译后的 Smarty 模板）。
 * 无恶意内容，用于对照。
 */
?><div class="nav">
<?php foreach ($navs as $nav): ?>
  <a href="<?= $nav['url'] ?>"><?= htmlspecialchars($nav['name']) ?></a>
<?php endforeach; ?>
</div>
