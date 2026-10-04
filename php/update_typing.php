<?php
// update_typing.php — Authenticated typing indicator update endpoint
declare(strict_types=1);

require_once __DIR__ . '/bootstrap_security.php';
global $conn;

use Daakpion\Security\SessionManager;
use Daakpion\Security\CsrfProtection;

if (!headers_sent()) {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('X-Content-Type-Options: nosniff');
}

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    exit(json_encode(['error' => 'Unauthorized']));
}

SessionManager::checkRestrictedAccess();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit(json_encode(['error' => 'Method Not Allowed: POST required']));
}

$submittedCsrf = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
if (!CsrfProtection::validateToken($submittedCsrf)) {
    http_response_code(403);
    exit(json_encode(['error' => 'CSRF validation failed']));
}

$userId   = (int)$_SESSION['user_id'];
$friendId = (int)($_POST['friend_id'] ?? 0);
$isTyping = !empty($_POST['is_typing']) && $_POST['is_typing'] !== '0' && $_POST['is_typing'] !== 'false';

if ($friendId <= 0 || $friendId === $userId) {
    http_response_code(400);
    exit(json_encode(['error' => 'Invalid friend ID']));
}

// Authorization check: Verify active friendship
$authCheck = $conn->prepare("
    SELECT 1 FROM friends
    WHERE ((user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?))
      AND status = 'active'
    LIMIT 1
");

if (!$authCheck) {
    http_response_code(500);
    exit(json_encode(['error' => 'A system error occurred']));
}

$authCheck->bind_param("iiii", $userId, $friendId, $friendId, $userId);
$authCheck->execute();
$authCheck->store_result();

if ($authCheck->num_rows === 0) {
    $authCheck->close();
    http_response_code(403);
    exit(json_encode(['error' => 'Unauthorized: Typing status only available for confirmed friends']));
}
$authCheck->close();

if ($isTyping) {
    $stmt = $conn->prepare("
        INSERT INTO typing_indicators (user_id, friend_id, updated_at)
        VALUES (?, ?, NOW())
        ON DUPLICATE KEY UPDATE updated_at = NOW()
    ");
    $stmt->bind_param("ii", $userId, $friendId);
    $stmt->execute();
    $stmt->close();
} else {
    $stmt = $conn->prepare("DELETE FROM typing_indicators WHERE user_id = ? AND friend_id = ?");
    $stmt->bind_param("ii", $userId, $friendId);
    $stmt->execute();
    $stmt->close();
}

echo json_encode([
    'success'   => true,
    'is_typing' => $isTyping,
    'friend_id' => $friendId
]);
