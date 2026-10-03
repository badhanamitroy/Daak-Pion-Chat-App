<?php
// respond_request.php — Accept or decline friend request with CSRF protection
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

$request_id = intval($_POST['request_id'] ?? 0);
$action     = $_POST['action'] ?? '';

if ($request_id <= 0 || !in_array($action, ['accept', 'decline'], true)) {
    http_response_code(400);
    exit("Invalid input");
}

// Find request
$stmt = $conn->prepare("SELECT sender_id, receiver_id FROM friendrequests WHERE id=? AND receiver_id=? AND status='pending'");
if (!$stmt) {
    error_log("Friend request find prepare failed: " . $conn->error);
    http_response_code(500);
    exit("A system error occurred. Please try again later.");
}

$stmt->bind_param("ii", $request_id, $_SESSION['user_id']);
$stmt->execute();
$res = $stmt->get_result();
$row = $res->fetch_assoc();
$stmt->close();

if (!$row) {
    http_response_code(404);
    exit("Request not found");
}

if ($action === 'accept') {
    // Defense-in-depth: Ensure relationship is not blocked (Resolves DP-P3-001)
    $blockCheck = $conn->prepare("
        SELECT id FROM friends
        WHERE ((user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?))
          AND status = 'blocked'
        LIMIT 1
    ");
    if ($blockCheck) {
        $blockCheck->bind_param("iiii", $row['sender_id'], $row['receiver_id'], $row['receiver_id'], $row['sender_id']);
        $blockCheck->execute();
        $blockCheck->store_result();
        if ($blockCheck->num_rows > 0) {
            $blockCheck->close();
            http_response_code(403);
            exit("Action not allowed.");
        }
        $blockCheck->close();
    }

    $conn->begin_transaction();
    try {
        $up = $conn->prepare("UPDATE friendrequests SET status='accepted', responded_at=NOW() WHERE id=?");
        $up->bind_param("i", $request_id);
        $up->execute();
        $up->close();

        // Check if already active friends
        $activeCheck = $conn->prepare("
            SELECT id FROM friends
            WHERE ((user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?))
              AND status = 'active'
            LIMIT 1
        ");
        $activeCheck->bind_param("iiii", $row['sender_id'], $row['receiver_id'], $row['receiver_id'], $row['sender_id']);
        $activeCheck->execute();
        $activeCheck->store_result();
        $alreadyActive = ($activeCheck->num_rows > 0);
        $activeCheck->close();

        if (!$alreadyActive) {
            $ins = $conn->prepare("INSERT INTO friends (user1_id, user2_id, friends_since, status) VALUES (?,?, NOW(),'active')");
            $ins->bind_param("ii", $row['sender_id'], $row['receiver_id']);
            $ins->execute();
            $ins->close();
        }

        $conn->commit();
        echo "Friend request accepted!";
    } catch (\Throwable $e) {
        $conn->rollback();
        // Resolves DP-VULN-04: Log technical diagnostics on the server, return safe generic message to client
        error_log("Friend request accept transaction failed: " . $e->getMessage());
        http_response_code(500);
        echo "An error occurred while accepting the request. Please try again.";
    }
} else {
    // Resolves DP-P3-003: Database enum is 'pending','accepted','rejected'. Use canonical 'rejected'.
    $up = $conn->prepare("UPDATE friendrequests SET status='rejected', responded_at=NOW() WHERE id=?");
    if ($up) {
        $up->bind_param("i", $request_id);
        $up->execute();
        $up->close();
        echo "Friend request declined!";
    } else {
        error_log("Friend request decline prepare failed: " . $conn->error);
        http_response_code(500);
        echo "An error occurred while declining the request.";
    }
}
