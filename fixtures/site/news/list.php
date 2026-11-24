<?php
/**
 * 正常业务文件：新闻列表，无恶意内容。
 */
require_once __DIR__ . '/../includes/db.php';

$page = (int) ($_GET['page'] ?? 1);
$stmt = $pdo->prepare('SELECT id, title, addtime FROM cms_article ORDER BY id DESC LIMIT 20 OFFSET ?');
$stmt->execute([($page - 1) * 20]);
$articles = $stmt->fetchAll();

include __DIR__ . '/../includes/header.php';
?>
<ul>
<?php foreach ($articles as $a): ?>
  <li><a href="/news/<?= (int) $a['id'] ?>.html"><?= htmlspecialchars($a['title']) ?></a></li>
<?php endforeach; ?>
</ul>
<?php include __DIR__ . '/../includes/footer.php'; ?>
