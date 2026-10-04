<?php
// mark_messages_read.php — Securely mark messages as read for active conversation
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

$userId = (int)$_SESSION['user_id'];
$friendId = (int)($_POST['friend_id'] ?? 0);
$maxId = isset($_POST['max_id']) ? (int)$_POST['max_id'] : 0;

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
    exit(json_encode(['error' => 'Unauthorized: Only messages from confirmed friends can be marked read']));
}
$authCheck->close();

// Mark messages as read and delivered (strictly incoming messages where receiver_id = $userId)
if ($maxId > 0) {
    $stmt = $conn->prepare("
        UPDATE messages
        SET is_read = 1, is_delivered = 1
        WHERE receiver_id = ? AND sender_id = ? AND is_read = 0 AND id <= ?
    ");
    $stmt->bind_param("iii", $userId, $friendId, $maxId);
} else {
    $stmt = $conn->prepare("
        UPDATE messages
        SET is_read = 1, is_delivered = 1
        WHERE receiver_id = ? AND sender_id = ? AND is_read = 0
    ");
    $stmt->bind_param("ii", $userId, $friendId);
}

if (!$stmt) {
    http_response_code(500);
    exit(json_encode(['error' => 'Database prepare failed']));
}

$stmt->execute();
$markedCount = $stmt->affected_rows;
$stmt->close();

echo json_encode([
    'success'      => true,
    'marked_count' => $markedCount,
    'friend_id'    => $friendId
]);
