<?php
// check_auth.php — Lightweight endpoint to verify authenticated status
declare(strict_types=1);

require_once __DIR__ . '/bootstrap_security.php';

header('Content-Type: application/json');
header('Cache-Control: no-store, no-cache, must-revalidate');

$isAuthenticated = isset($_SESSION['user_id']) && (int)$_SESSION['user_id'] > 0;
$mustChangePassword = !empty($_SESSION['must_change_password']);

echo json_encode([
    'authenticated'        => $isAuthenticated,
    'must_change_password' => $mustChangePassword,
    'redirect'             => $mustChangePassword ? 'force_change_password.php' : 'user-profile.php'
]);
exit;
