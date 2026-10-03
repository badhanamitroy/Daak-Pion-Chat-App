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

// Check if relationship is blocked or already active friends (Resolves DP-P3-001)
$relCheck = $conn->prepare("
    SELECT status FROM friends
    WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
    LIMIT 1
");
if (!$relCheck) {
    error_log("Friend request relCheck failed: " . $conn->error);
    http_response_code(500);
    exit("A system error occurred. Please try again later.");
}

$relCheck->bind_param("iiii", $sender_id, $receiver_id, $receiver_id, $sender_id);
$relCheck->execute();
$relRes = $relCheck->get_result();
$relRow = $relRes->fetch_assoc();
$relCheck->close();

if ($relRow) {
    if ($relRow['status'] === 'blocked') {
        http_response_code(403);
        exit("Action not allowed.");
    }
    if ($relRow['status'] === 'active') {
        exit("You are already friends");
    }
}

// Check if A → B request already exists (Resolves DP-P3-003)
$checkAB = $conn->prepare("
    SELECT id, status FROM friendrequests
    WHERE sender_id = ? AND receiver_id = ?
    LIMIT 1
");
if (!$checkAB) {
    error_log("Friend request checkAB failed: " . $conn->error);
    http_response_code(500);
    exit("A system error occurred. Please try again later.");
}

$checkAB->bind_param("ii", $sender_id, $receiver_id);
$checkAB->execute();
$resAB = $checkAB->get_result();
$rowAB = $resAB->fetch_assoc();
$checkAB->close();

if ($rowAB) {
    if ($rowAB['status'] === 'pending') {
        exit("You already sent a request to this person");
    }
    if ($rowAB['status'] === 'accepted') {
        exit("You are already friends");
    }
    // If previous request was rejected, safely reset to pending (re-send)
    $reSendStmt = $conn->prepare("
        UPDATE friendrequests
        SET status = 'pending', sent_at = NOW(), responded_at = NULL
        WHERE id = ?
    ");
    if (!$reSendStmt) {
        error_log("Friend request reSend prepare failed: " . $conn->error);
        http_response_code(500);
        exit("A system error occurred. Please try again later.");
    }
    $reSendStmt->bind_param("i", $rowAB['id']);
    if ($reSendStmt->execute()) {
        $reSendStmt->close();
        echo "Friend request sent!";
        exit;
    } else {
        error_log("Friend request reSend execute failed: " . $reSendStmt->error);
        $reSendStmt->close();
        http_response_code(500);
        exit("Error sending request. Please try again.");
    }
}

// Check if B → A request already exists (reverse direction)
$checkBA = $conn->prepare("
    SELECT id, status FROM friendrequests
    WHERE sender_id = ? AND receiver_id = ?
    LIMIT 1
");
if (!$checkBA) {
    error_log("Friend request checkBA failed: " . $conn->error);
    http_response_code(500);
    exit("A system error occurred. Please try again later.");
}

$checkBA->bind_param("ii", $receiver_id, $sender_id);
$checkBA->execute();
$resBA = $checkBA->get_result();
$rowBA = $resBA->fetch_assoc();
$checkBA->close();

if ($rowBA) {
    if ($rowBA['status'] === 'pending') {
        exit("This person has already sent you a friend request — check your requests");
    }
    if ($rowBA['status'] === 'accepted') {
        exit("You are already friends");
    }
}

// All clear — insert the brand new request
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

