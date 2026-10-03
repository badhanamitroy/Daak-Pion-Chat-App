<?php
require_once __DIR__ . "/bootstrap_security.php";

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    header('Content-Type: application/json');
    exit(json_encode([]));
}

use Daakpion\Security\CryptoService;
use Daakpion\Security\SessionManager;

SessionManager::checkRestrictedAccess();

if (!isset($_GET['friend_id'])) {
    http_response_code(400);
    header('Content-Type: application/json');
    exit(json_encode([]));
}

$user_id   = (int)$_SESSION['user_id'];
$friend_id = (int)$_GET['friend_id'];
$since_id  = isset($_GET['since_id']) ? max(0, (int)$_GET['since_id']) : 0;
$before_id = isset($_GET['before_id']) ? max(0, (int)$_GET['before_id']) : 0;

// ── Resource Limit Enforcement (Resolves DP-VULN-06) ─────────────────────────
// Enforce strict upper bound on limit to prevent memory exhaustion DoS
$limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 50;
if ($limit <= 0) {
    $limit = 50;
}
if ($limit > 100) {
    $limit = 100; // Strict maximum page size
}

// Security: verify friend_id actually belongs to an active friend of this user
$friendCheck = $conn->prepare("
    SELECT 1 FROM friends
    WHERE ((user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?))
      AND status = 'active'
    LIMIT 1
");

if (!$friendCheck) {
    error_log("Friend check prepare failed: " . $conn->error);
    http_response_code(500);
    header('Content-Type: application/json');
    exit(json_encode(['error' => 'A server error occurred.']));
}

$friendCheck->bind_param("iiii", $user_id, $friend_id, $friend_id, $user_id);
$friendCheck->execute();
$friendCheck->store_result();
if ($friendCheck->num_rows === 0) {
    http_response_code(403);
    header('Content-Type: application/json');
    $friendCheck->close();
    exit(json_encode(['error' => 'Not authorized']));
}
$friendCheck->close();

// ── Bounded & Indexed Pagination Query (Resolves DP-VULN-06) ──────────────────
if ($before_id > 0) {
    // Historical pagination (scroll-up): Fetch older messages before cursor
    $sql = "
        SELECT id, sender_id, receiver_id, message, sent_at, is_read
        FROM messages
        WHERE ((sender_id = ? AND receiver_id = ?)
            OR (sender_id = ? AND receiver_id = ?))
          AND id < ?
        ORDER BY id DESC
        LIMIT ?
    ";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("iiiiii", $user_id, $friend_id, $friend_id, $user_id, $before_id, $limit);
    $needReverse = true;
} elseif ($since_id > 0) {
    // Polling pagination: Fetch new messages after cursor
    $sql = "
        SELECT id, sender_id, receiver_id, message, sent_at, is_read
        FROM messages
        WHERE ((sender_id = ? AND receiver_id = ?)
            OR (sender_id = ? AND receiver_id = ?))
          AND id > ?
        ORDER BY id ASC
        LIMIT ?
    ";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("iiiiii", $user_id, $friend_id, $friend_id, $user_id, $since_id, $limit);
    $needReverse = false;
} else {
    // Initial conversation load: Fetch most recent messages within limit
    $sql = "
        SELECT id, sender_id, receiver_id, message, sent_at, is_read
        FROM messages
        WHERE ((sender_id = ? AND receiver_id = ?)
            OR (sender_id = ? AND receiver_id = ?))
        ORDER BY id DESC
        LIMIT ?
    ";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("iiiii", $user_id, $friend_id, $friend_id, $user_id, $limit);
    $needReverse = true;
}

if (!$stmt) {
    error_log("Message fetch prepare failed: " . $conn->error);
    http_response_code(500);
    header('Content-Type: application/json');
    exit(json_encode(['error' => 'Failed to load messages.']));
}

$stmt->execute();
$res = $stmt->get_result();

$messages = [];
while ($row = $res->fetch_assoc()) {
    $stored = $row['message'];

    // ── Authenticated Decryption (Resolves DP-VULN-03) ─────────────────────────
    // Supports authenticated AES-256-GCM and controlled legacy AES-256-CBC
    $decrypted = CryptoService::decryptMessage($stored);

    // Fail-closed placeholder on tampering or decryption failure
    $row['message'] = ($decrypted !== null) ? $decrypted : '[message unavailable]';

    $messages[] = $row;
}
$stmt->close();

// Restore chronological display order if fetched in reverse (DESC) order
if ($needReverse && !empty($messages)) {
    $messages = array_reverse($messages);
}

header('Content-Type: application/json');
echo json_encode($messages);
