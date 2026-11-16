<?php
// 正常业务首页
require __DIR__ . '/inc/db.php';
$id = (int)($_GET['id'] ?? 1);
$row = db_get($id);
echo "<html><body><h1>" . htmlspecialchars($row['title']) . "</h1></body></html>";
