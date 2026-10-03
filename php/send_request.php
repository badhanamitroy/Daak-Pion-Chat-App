<?php
// send_request.php — Send a friend request with CSRF protection
declare(strict_types=1);

require_once __DIR__ . "/bootstrap_security.php";

use Daakpion\Security\SessionManager;
use Daakpion\Security\CsrfProtection;

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    exit("Not logged in");
}

SessionManager::checkRestrictedAccess();

// ── 1. CSRF Protection (Resolves DP-VULN-02) ─────────────────────────────────
$submittedCsrf = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
if (!CsrfProtection::validateToken($submittedCsrf)) {
    http_response_code(403);
    exit("CSRF token validation failed");
}

$sender_id   = (int)$_SESSION['user_id'];
$receiver_id = (int)($_POST['receiver_id'] ?? 0);

// Validate receiver
if ($receiver_id <= 0) {
    http_response_code(400);
    exit("Invalid receiver");
}

// Block self-requests
if ($sender_id === $receiver_id) {
    http_response_code(400);
    exit("You cannot send a friend request to yourself");
}

// Check if already friends
$friendsCheck = $conn->prepare("
    SELECT id FROM friends
    WHERE ((user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?))
      AND status = 'active'
    LIMIT 1
");
if (!$friendsCheck) {
    error_log("Friend request friendsCheck failed: " . $conn->error);
    http_response_code(500);
    exit("A system error occurred. Please try again later.");
}

$friendsCheck->bind_param("iiii", $sender_id, $receiver_id, $receiver_id, $sender_id);
$friendsCheck->execute();
$friendsCheck->store_result();
if ($friendsCheck->num_rows > 0) {
    $friendsCheck->close();
    exit("You are already friends");
}
$friendsCheck->close();

// Check if A → B pending request already exists
$checkAB = $conn->prepare("
    SELECT id FROM friendrequests
    WHERE sender_id = ? AND receiver_id = ? AND status = 'pending'
    LIMIT 1
");
if (!$checkAB) {
    error_log("Friend request checkAB failed: " . $conn->error);
    http_response_code(500);
    exit("A system error occurred. Please try again later.");
}

$checkAB->bind_param("ii", $sender_id, $receiver_id);
$checkAB->execute();
$checkAB->store_result();
if ($checkAB->num_rows > 0) {
    $checkAB->close();
    exit("You already sent a request to this person");
}
$checkAB->close();

// Check if B → A pending request already exists (reverse direction)
$checkBA = $conn->prepare("
    SELECT id FROM friendrequests
    WHERE sender_id = ? AND receiver_id = ? AND status = 'pending'
    LIMIT 1
");
if (!$checkBA) {
    error_log("Friend request checkBA failed: " . $conn->error);
    http_response_code(500);
    exit("A system error occurred. Please try again later.");
}

$checkBA->bind_param("ii", $receiver_id, $sender_id);
$checkBA->execute();
$checkBA->store_result();
if ($checkBA->num_rows > 0) {
    $checkBA->close();
    exit("This person has already sent you a friend request — check your requests");
}
$checkBA->close();

// All clear — insert the request
$stmt = $conn->prepare("
    INSERT INTO friendrequests (sender_id, receiver_id, status, sent_at)
    VALUES (?, ?, 'pending', NOW())
");
if (!$stmt) {
    error_log("Friend request insert prepare failed: " . $conn->error);
    http_response_code(500);
    exit("Error sending request. Please try again later.");
}

$stmt->bind_param("ii", $sender_id, $receiver_id);
if ($stmt->execute()) {
    echo "Friend request sent!";
} else {
    error_log("Friend request insert execute failed: " . $stmt->error);
    http_response_code(500);
    echo "Error sending request. Please try again.";
}
$stmt->close();
