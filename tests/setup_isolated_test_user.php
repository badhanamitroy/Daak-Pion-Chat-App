<?php
require_once __DIR__ . '/../php/bootstrap_security.php';
use Daakpion\Security\CryptoService;

$email = 'test_login@example.com';
$password = 'TestPassword123!';
$hash = CryptoService::hashPassword($password);

$stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$res = $stmt->get_result();

if ($row = $res->fetch_assoc()) {
    $id = (int)$row['id'];
    $upd = $conn->prepare("UPDATE users SET password = ?, status = 'Offline', two_factor_enabled = 1, is_temporary_password = 0, password_version = 1 WHERE id = ?");
    $upd->bind_param("si", $hash, $id);
    $upd->execute();
    echo "Updated test user ID: $id\n";
} else {
    $ins = $conn->prepare("INSERT INTO users (fname, lname, email, password, status, two_factor_enabled, password_version) VALUES ('Test', 'User', ?, ?, 'Offline', 1, 1)");
    $ins->bind_param("ss", $email, $hash);
    $ins->execute();
    $id = $conn->insert_id;
    echo "Created test user ID: $id\n";
}
