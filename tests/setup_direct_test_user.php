<?php
require_once __DIR__ . '/../php/bootstrap_security.php';
use Daakpion\Security\CryptoService;

// Setup test_direct@example.com with 2FA disabled
$email = 'test_direct@example.com';
$password = 'TestPassword123!';
$hash = CryptoService::hashPassword($password);

$conn->query("DELETE FROM users WHERE email = '{$email}'");
$stmt = $conn->prepare("INSERT INTO users (fname, lname, email, password, status, two_factor_enabled, password_version) VALUES ('Direct', 'User', ?, ?, 'Offline', 0, 1)");
$stmt->bind_param("ss", $email, $hash);
$stmt->execute();
$directId = $conn->insert_id;
echo "Created test_direct@example.com ID: {$directId}\n";
