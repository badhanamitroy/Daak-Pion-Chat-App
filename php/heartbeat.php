<?php
// heartbeat.php — Authenticated presence heartbeat endpoint (Resolves DP-P4-009)
declare(strict_types=1);

require_once __DIR__ . '/bootstrap_security.php';

use Daakpion\Security\SessionManager;
use Daakpion\Security\CsrfProtection;

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('X-Content-Type-Options: nosniff');

// 1. Authentication check
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    exit(json_encode(['error' => 'Not logged in']));
}

SessionManager::checkRestrictedAccess();

// 2. Enforce POST method
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit(json_encode(['error' => 'Method Not Allowed: Heartbeat requires POST']));
}

// 3. CSRF Validation
$submittedCsrf = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
if (!CsrfProtection::validateToken($submittedCsrf)) {
    http_response_code(403);
    exit(json_encode(['error' => 'CSRF validation failed']));
}

// 4. Update ONLY the authenticated user's own activity (never trust client-supplied ID)
$userId = (int)$_SESSION['user_id'];
$stmt = $conn->prepare("UPDATE users SET status = 'Active now', last_activity_at = NOW() WHERE id = ?");
if ($stmt) {
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $stmt->close();
}

echo json_encode([
    'success'   => true,
    'timestamp' => time(),
]);
