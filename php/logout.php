<?php
// logout.php — Hardened session termination with CSRF protection (Resolves DP-P3-004)
declare(strict_types=1);

require_once __DIR__ . '/bootstrap_security.php';

use Daakpion\Security\SessionManager;
use Daakpion\Security\AuditLogger;
use Daakpion\Security\CsrfProtection;

// Enforce POST method to prevent GET-based Logout CSRF
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit("Method Not Allowed: Logout requires a POST request.");
}

// Enforce CSRF token validation
$submittedCsrf = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
if (!CsrfProtection::validateToken($submittedCsrf)) {
    http_response_code(403);
    exit("CSRF token validation failed.");
}

$logger = new AuditLogger($conn);
$userId = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
$email  = $_SESSION['user_email'] ?? null;

if ($userId) {
    $logger->log('LOGOUT', 'SUCCESS', $userId, $email);
}

SessionManager::destroySession($conn);

header("Location: ../index.html");
exit;

