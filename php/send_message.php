<?php
// send_message.php — Send encrypted message with authorization & CSRF protection
declare(strict_types=1);

require_once __DIR__ . "/bootstrap_security.php";

use Daakpion\Security\SessionManager;
use Daakpion\Security\CsrfProtection;

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    exit("Unauthorized");
}

SessionManager::checkRestrictedAccess();

// ── 1. CSRF Protection ────────────────────────────────────────────────────────
$submittedCsrf = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
if (!CsrfProtection::validateToken($submittedCsrf)) {
    http_response_code(403);
    exit("CSRF token validation failed");
}

if (!isset($_POST['receiver_id'], $_POST['message'])) {
    http_response_code(400);
    exit("Missing required fields");
}

$user_id     = (int)$_SESSION['user_id'];
$receiver_id = (int)$_POST['receiver_id'];
$message     = trim($_POST['message']);

if (empty($message) || $receiver_id <= 0) {
    http_response_code(400);
    exit("Invalid input");
}

if ($user_id === $receiver_id) {
    http_response_code(400);
    exit("You cannot send a message to yourself");
}

// Enforce message length cap (prevents DB abuse with huge payloads)
if (mb_strlen($message) > 2000) {
    http_response_code(400);
    exit("Message too long. Maximum is 2000 characters.");
}

// ── 2. Authorization: Verify Active Friendship ───────────────────────────────
// Resolves DP-VULN-01: Prohibits messaging users who are not active confirmed friends.
$friendCheck = $conn->prepare("
    SELECT 1 FROM friends
    WHERE ((user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?))
      AND status = 'active'
    LIMIT 1
");

if (!$friendCheck) {
    error_log("Friend check prepare failed: " . $conn->error);
    http_response_code(500);
    exit("A system error occurred. Please try again later.");
}

$friendCheck->bind_param("iiii", $user_id, $receiver_id, $receiver_id, $user_id);
$friendCheck->execute();
$friendCheck->store_result();

if ($friendCheck->num_rows === 0) {
    $friendCheck->close();
    http_response_code(403);
    exit("Unauthorized: You can only message confirmed friends.");
}
$friendCheck->close();

// ── 3. Encryption & Storage ──────────────────────────────────────────────────
// SECRET_KEY is loaded from app_config.php
$iv             = random_bytes(16);
$iv_b64         = base64_encode($iv);
$encrypted      = openssl_encrypt($message, 'AES-256-CBC', SECRET_KEY, 0, $iv);
$stored_message = $iv_b64 . ':' . $encrypted;

$sql  = "INSERT INTO messages (sender_id, receiver_id, message, sent_at, is_read) VALUES (?, ?, ?, NOW(), 0)";
$stmt = $conn->prepare($sql);
if (!$stmt) {
    error_log("Message insert prepare failed: " . $conn->error);
    http_response_code(500);
    exit("A system error occurred. Please try again later.");
}

$stmt->bind_param("iis", $user_id, $receiver_id, $stored_message);
if (!$stmt->execute()) {
    error_log("Message insert execute failed: " . $stmt->error);
    $stmt->close();
    http_response_code(500);
    exit("Failed to send message. Please try again.");
}
$stmt->close();

echo "Message sent";
