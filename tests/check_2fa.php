<?php
require_once __DIR__ . '/../php/db_connect.php';
$res = $conn->query("SELECT * FROM two_factor_otps ORDER BY id DESC LIMIT 5");
while ($row = $res->fetch_assoc()) {
    echo json_encode($row) . "\n";
}
