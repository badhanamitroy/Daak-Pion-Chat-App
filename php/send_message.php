<?php
// send_message.php — Send encrypted message with authorization, CSRF protection, idempotency & reply support
declare(strict_types=1);

require_once __DIR__ . "/bootstrap_security.php";
global $conn;

use Daakpion\Security\SessionManager;
use Daakpion\Security\CsrfProtection;
use Daakpion\Security\CryptoService;

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

// ── 1. CSRF Protection ────────────────────────────────────────────────────────
$submittedCsrf = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
if (!CsrfProtection::validateToken($submittedCsrf)) {
    http_response_code(403);
    exit(json_encode(['error' => 'CSRF token validation failed']));
}

if (!isset($_POST['receiver_id'], $_POST['message'])) {
    http_response_code(400);
    exit(json_encode(['error' => 'Missing required fields']));
}

$user_id     = (int)$_SESSION['user_id'];
$receiver_id = (int)$_POST['receiver_id'];
$message     = trim($_POST['message']);
$reply_to_id = isset($_POST['reply_to_id']) && (int)$_POST['reply_to_id'] > 0 ? (int)$_POST['reply_to_id'] : null;
$client_msg_id = isset($_POST['client_message_id']) && is_string($_POST['client_message_id']) && trim($_POST['client_message_id']) !== '' 
    ? substr(trim($_POST['client_message_id']), 0, 64) 
    : null;

if (empty($message) || $receiver_id <= 0) {
    http_response_code(400);
    exit(json_encode(['error' => 'Invalid input: Message cannot be empty']));
}

if ($user_id === $receiver_id) {
    http_response_code(400);
    exit(json_encode(['error' => 'You cannot send a message to yourself']));
}

// Enforce message length cap (prevents DB abuse with huge payloads)
if (mb_strlen($message) > 2000) {
    http_response_code(400);
    exit(json_encode(['error' => 'Message too long. Maximum is 2000 characters.']));
}

// ── 2. Idempotency Check (Resolves DP-P1-008: Message retry & duplicate prevention) ───
if ($client_msg_id !== null) {
    $idemStmt = $conn->prepare("
        SELECT id, sent_at, is_delivered, is_read
        FROM messages
        WHERE sender_id = ? AND client_message_id = ?
        LIMIT 1
    ");
    if ($idemStmt) {
        $idemStmt->bind_param("is", $user_id, $client_msg_id);
        $idemStmt->execute();
        $idemRow = $idemStmt->get_result()->fetch_assoc();
        $idemStmt->close();

        if ($idemRow) {
            // Already safely processed, return existing message state
            echo json_encode([
                'success'           => true,
                'id'                => (int)$idemRow['id'],
                'client_message_id' => $client_msg_id,
                'sent_at'           => $idemRow['sent_at'],
                'is_delivered'      => (int)$idemRow['is_delivered'],
                'is_read'           => (int)$idemRow['is_read'],
                'duplicate'         => true
            ]);
            exit;
        }
    }
}

// ── 3. Authorization: Verify Active Friendship ───────────────────────────────
$friendCheck = $conn->prepare("
    SELECT 1 FROM friends
    WHERE ((user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?))
      AND status = 'active'
    LIMIT 1
");

if (!$friendCheck) {
    error_log("Friend check prepare failed: " . $conn->error);
    http_response_code(500);
    exit(json_encode(['error' => 'A system error occurred. Please try again later.']));
}

$friendCheck->bind_param("iiii", $user_id, $receiver_id, $receiver_id, $user_id);
$friendCheck->execute();
$friendCheck->store_result();

if ($friendCheck->num_rows === 0) {
    $friendCheck->close();
    http_response_code(403);
    exit(json_encode(['error' => 'Unauthorized: You can only message confirmed friends.']));
}
$friendCheck->close();

// ── 4. Verify Reply Reference (if provided) ──────────────────────────────────
if ($reply_to_id !== null) {
    $replyCheck = $conn->prepare("
        SELECT id, is_deleted_all
        FROM messages
        WHERE id = ?
          AND ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
        LIMIT 1
    ");
    if ($replyCheck) {
        $replyCheck->bind_param("iiiii", $reply_to_id, $user_id, $receiver_id, $receiver_id, $user_id);
        $replyCheck->execute();
        $replyRow = $replyCheck->get_result()->fetch_assoc();
        $replyCheck->close();

        if (!$replyRow || (int)$replyRow['is_deleted_all'] === 1) {
            http_response_code(400);
            exit(json_encode(['error' => 'Invalid reply reference: Target message is invalid or deleted.']));
        }
    }
}

// ── 5. Check if Receiver is Online (Accurate Delivered State) ─────────────────
$is_delivered = 0;
$userCheck = $conn->prepare("
    SELECT (CASE WHEN status != 'Offline' 
                 AND last_activity_at IS NOT NULL 
                 AND TIMESTAMPDIFF(SECOND, last_activity_at, NOW()) <= 120 
            THEN 1 ELSE 0 END) AS is_online
    FROM users WHERE id = ? LIMIT 1
");
if ($userCheck) {
    $userCheck->bind_param("i", $receiver_id);
    $userCheck->execute();
    $uRow = $userCheck->get_result()->fetch_assoc();
    $userCheck->close();
    if ($uRow && (int)$uRow['is_online'] === 1) {
        $is_delivered = 1;
    }
}

// ── 6. Authenticated Encryption & Storage (Resolves DP-VULN-03) ───────────────
try {
    $stored_message = CryptoService::encryptMessage($message);
} catch (\Throwable $e) {
    error_log("Message encryption failure: " . $e->getMessage());
    http_response_code(500);
    exit(json_encode(['error' => 'A system error occurred. Please try again later.']));
}

$sql = "
    INSERT INTO messages (sender_id, receiver_id, message, reply_to_id, client_message_id, sent_at, is_read, is_delivered, message_type)
    VALUES (?, ?, ?, ?, ?, NOW(), 0, ?, 'text')
";
$stmt = $conn->prepare($sql);
if (!$stmt) {
    error_log("Message insert prepare failed: " . $conn->error);
    http_response_code(500);
    exit(json_encode(['error' => 'A system error occurred. Please try again later.']));
}

$stmt->bind_param("iisisi", $user_id, $receiver_id, $stored_message, $reply_to_id, $client_msg_id, $is_delivered);
if (!$stmt->execute()) {
    error_log("Message insert execute failed: " . $stmt->error);
    $stmt->close();
    http_response_code(500);
    exit(json_encode(['error' => 'Failed to send message. Please try again.']));
}

$insertedId = (int)$stmt->insert_id;
$stmt->close();

// Clear active typing indicator for this user -> friend
$clearTyping = $conn->prepare("DELETE FROM typing_indicators WHERE user_id = ? AND friend_id = ?");
if ($clearTyping) {
    $clearTyping->bind_param("ii", $user_id, $receiver_id);
    $clearTyping->execute();
    $clearTyping->close();
}

// Fetch generated timestamp
$timeStmt = $conn->prepare("SELECT sent_at FROM messages WHERE id = ? LIMIT 1");
$sent_at = date('Y-m-d H:i:s');
if ($timeStmt) {
    $timeStmt->bind_param("i", $insertedId);
    $timeStmt->execute();
    $tRow = $timeStmt->get_result()->fetch_assoc();
    $timeStmt->close();
    if ($tRow && !empty($tRow['sent_at'])) {
        $sent_at = $tRow['sent_at'];
    }
}

echo json_encode([
    'success'           => true,
    'id'                => $insertedId,
    'client_message_id' => $client_msg_id,
    'sent_at'           => $sent_at,
    'is_delivered'      => $is_delivered,
    'is_read'           => 0
]);
