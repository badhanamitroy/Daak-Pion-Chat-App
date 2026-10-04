<?php
// delete_message.php — Securely delete messages (Delete for me & Delete for everyone)
declare(strict_types=1);

require_once __DIR__ . '/bootstrap_security.php';
global $conn;

use Daakpion\Security\SessionManager;
use Daakpion\Security\CsrfProtection;
use Daakpion\Security\AuditLogger;

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

$userId     = (int)$_SESSION['user_id'];
$messageId  = (int)($_POST['message_id'] ?? 0);
$deleteType = $_POST['delete_type'] ?? 'for_me';

if ($messageId <= 0) {
    http_response_code(400);
    exit(json_encode(['error' => 'Invalid message ID']));
}

if (!in_array($deleteType, ['for_me', 'for_everyone'], true)) {
    http_response_code(400);
    exit(json_encode(['error' => 'Invalid delete type. Must be "for_me" or "for_everyone"']));
}

// Fetch message to verify participation and existence
$stmt = $conn->prepare("
    SELECT id, sender_id, receiver_id, is_deleted_all, deleted_by_sender, deleted_by_receiver
    FROM messages
    WHERE id = ?
    LIMIT 1
");

if (!$stmt) {
    http_response_code(500);
    exit(json_encode(['error' => 'Database prepare failed']));
}

$stmt->bind_param("i", $messageId);
$stmt->execute();
$msg = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$msg) {
    http_response_code(404);
    exit(json_encode(['error' => 'Message not found']));
}

$senderId   = (int)$msg['sender_id'];
$receiverId = (int)$msg['receiver_id'];

// Authorization: User must be either the sender or the receiver
if ($userId !== $senderId && $userId !== $receiverId) {
    http_response_code(403);
    exit(json_encode(['error' => 'Unauthorized: You are not a participant in this conversation']));
}

if ($deleteType === 'for_everyone') {
    // Only the original sender may delete for everyone
    if ($userId !== $senderId) {
        http_response_code(403);
        exit(json_encode(['error' => 'Unauthorized: Only the sender can delete a message for everyone']));
    }

    $updateStmt = $conn->prepare("UPDATE messages SET is_deleted_all = 1 WHERE id = ?");
    $updateStmt->bind_param("i", $messageId);
    $updateStmt->execute();
    $updateStmt->close();

    // Clean up physical files and soft-delete attachments
    $attStmt = $conn->prepare("SELECT storage_path, thumbnail_path FROM message_attachments WHERE message_id = ?");
    if ($attStmt) {
        $attStmt->bind_param("i", $messageId);
        $attStmt->execute();
        $attRes = $attStmt->get_result();
        $rootDir = realpath(__DIR__ . '/..');
        while ($attRow = $attRes->fetch_assoc()) {
            if (!empty($attRow['storage_path']) && $rootDir) {
                $p = $rootDir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $attRow['storage_path']);
                if (file_exists($p)) @unlink($p);
            }
            if (!empty($attRow['thumbnail_path']) && $rootDir) {
                $tp = $rootDir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $attRow['thumbnail_path']);
                if (file_exists($tp)) @unlink($tp);
            }
        }
        $attStmt->close();
    }

    $updateAtt = $conn->prepare("UPDATE message_attachments SET deleted_at = NOW() WHERE message_id = ?");
    if ($updateAtt) {
        $updateAtt->bind_param("i", $messageId);
        $updateAtt->execute();
        $updateAtt->close();
    }

    $logger = new AuditLogger($conn);
    $logger->log('message_delete_everyone', 'SUCCESS', $userId, null, ['message_id' => $messageId]);
} else {
    // Delete for me
    if ($userId === $senderId) {
        $updateStmt = $conn->prepare("UPDATE messages SET deleted_by_sender = 1 WHERE id = ?");
    } else {
        $updateStmt = $conn->prepare("UPDATE messages SET deleted_by_receiver = 1 WHERE id = ?");
    }
    $updateStmt->bind_param("i", $messageId);
    $updateStmt->execute();
    $updateStmt->close();

    $logger = new AuditLogger($conn);
    $logger->log('message_delete_for_me', 'SUCCESS', $userId, null, ['message_id' => $messageId]);
}

echo json_encode([
    'success'     => true,
    'message_id'  => $messageId,
    'delete_type' => $deleteType
]);
