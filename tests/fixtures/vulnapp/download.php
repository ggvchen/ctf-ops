<?php
require 'config.php';
$id = $_GET['id'];
$sql = "SELECT * FROM files WHERE id = " . $id;
$row = mysqli_query($conn, $sql)->fetch_assoc();
$file = $_GET['file'];
$content = file_get_contents('/var/data/' . $file);
echo $content;
