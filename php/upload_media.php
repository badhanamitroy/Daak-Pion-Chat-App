<?php
// upload_media.php — Authenticated media attachment upload endpoint with transaction consistency
declare(strict_types=1);

require_once __DIR__ . '/bootstrap_security.php';
global $conn;

use Daakpion\Security\SessionManager;
use Daakpion\Security\CsrfProtection;
use Daakpion\Security\CryptoService;
use Daakpion\Security\MediaUploadService;

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

// 1. CSRF Validation
$submittedCsrf = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
if (!CsrfProtection::validateToken($submittedCsrf)) {
    http_response_code(403);
    exit(json_encode(['error' => 'CSRF validation failed']));
}

$userId     = (int)$_SESSION['user_id'];
$receiverId = (int)($_POST['receiver_id'] ?? 0);
$caption    = trim((string)($_POST['caption'] ?? ''));
$replyToId  = isset($_POST['reply_to_id']) && (int)$_POST['reply_to_id'] > 0 ? (int)$_POST['reply_to_id'] : null;
$clientMsgId = isset($_POST['client_message_id']) && is_string($_POST['client_message_id']) && trim($_POST['client_message_id']) !== ''
    ? substr(trim($_POST['client_message_id']), 0, 64)
    : null;

if ($receiverId <= 0 || $receiverId === $userId) {
    http_response_code(400);
    exit(json_encode(['error' => 'Invalid receiver ID']));
}

if (!isset($_FILES['file'])) {
    http_response_code(400);
    exit(json_encode(['error' => 'No file was uploaded']));
}

// 2. Authorization: Verify Active Friendship
$friendCheck = $conn->prepare("
    SELECT 1 FROM friends
    WHERE ((user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?))
      AND status = 'active'
    LIMIT 1
");

if (!$friendCheck) {
    http_response_code(500);
    exit(json_encode(['error' => 'System error verifying friendship']));
}

$friendCheck->bind_param("iiii", $userId, $receiverId, $receiverId, $userId);
$friendCheck->execute();
if ($friendCheck->get_result()->num_rows === 0) {
    $friendCheck->close();
    http_response_code(403);
    exit(json_encode(['error' => 'Unauthorized: Media messaging is restricted to active friends']));
}
$friendCheck->close();

// 3. Validate Upload via MediaUploadService
try {
    $validated = MediaUploadService::validateUpload($_FILES['file']);
} catch (\Throwable $e) {
    http_response_code(400);
    exit(json_encode(['error' => $e->getMessage()]));
}

// 4. Verify Reply Reference (if provided)
if ($replyToId !== null) {
    $replyCheck = $conn->prepare("
        SELECT id, is_deleted_all
        FROM messages
        WHERE id = ?
          AND ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
        LIMIT 1
    ");
    if ($replyCheck) {
        $replyCheck->bind_param("iiiii", $replyToId, $userId, $receiverId, $receiverId, $userId);
        $replyCheck->execute();
        $rRow = $replyCheck->get_result()->fetch_assoc();
        $replyCheck->close();

        if (!$rRow || (int)$rRow['is_deleted_all'] === 1) {
            http_response_code(400);
            exit(json_encode(['error' => 'Invalid reply reference']));
        }
    }
}

// 5. Check if Receiver is Online
$isDelivered = 0;
$userCheck = $conn->prepare("
    SELECT (CASE WHEN status != 'Offline' 
                 AND last_activity_at IS NOT NULL 
                 AND TIMESTAMPDIFF(SECOND, last_activity_at, NOW()) <= 120 
            THEN 1 ELSE 0 END) AS is_online
    FROM users WHERE id = ? LIMIT 1
");
if ($userCheck) {
    $userCheck->bind_param("i", $receiverId);
    $userCheck->execute();
    $uRow = $userCheck->get_result()->fetch_assoc();
    $userCheck->close();
    if ($uRow && (int)$uRow['is_online'] === 1) {
        $isDelivered = 1;
    }
}

// 6. Encrypt Caption / Message Text
try {
    $storedMessage = CryptoService::encryptMessage($caption);
} catch (\Throwable $e) {
    http_response_code(500);
    exit(json_encode(['error' => 'Encryption failure']));
}

// 7. Atomic Database Transaction: Insert Message + Attachment Record
$conn->begin_transaction();

try {
    $mediaType = $validated['media_type'];
    $msgStmt = $conn->prepare("
        INSERT INTO messages 
        (sender_id, receiver_id, message, reply_to_id, client_message_id, sent_at, is_read, is_delivered, message_type)
        VALUES (?, ?, ?, ?, ?, NOW(), 0, ?, ?)
    ");
    if (!$msgStmt) {
        throw new \RuntimeException("Prepare failed for message: " . $conn->error);
    }

    $msgStmt->bind_param("iisisis", $userId, $receiverId, $storedMessage, $replyToId, $clientMsgId, $isDelivered, $mediaType);
    if (!$msgStmt->execute()) {
        $err = $msgStmt->error;
        $msgStmt->close();
        throw new \RuntimeException("Execute failed for message: " . $err);
    }

    $messageId = (int)$msgStmt->insert_id;
    $msgStmt->close();

    // Store physical file and create attachment record
    $attachment = MediaUploadService::storeAttachment($validated, $userId, $messageId, $conn);

    $conn->commit();

    // Fetch sent timestamp
    $timeStmt = $conn->prepare("SELECT sent_at FROM messages WHERE id = ? LIMIT 1");
    $sentAt = date('Y-m-d H:i:s');
    if ($timeStmt) {
        $timeStmt->bind_param("i", $messageId);
        $timeStmt->execute();
        $tRow = $timeStmt->get_result()->fetch_assoc();
        $timeStmt->close();
        if ($tRow && !empty($tRow['sent_at'])) $sentAt = $tRow['sent_at'];
    }

    echo json_encode([
        'success'           => true,
        'id'                => $messageId,
        'client_message_id' => $clientMsgId,
        'sender_id'         => $userId,
        'receiver_id'       => $receiverId,
        'message'           => $caption,
        'message_type'      => $mediaType,
        'attachment'        => $attachment,
        'sent_at'           => $sentAt,
        'is_delivered'      => $isDelivered,
        'is_read'           => 0
    ]);
} catch (\Throwable $e) {
    $conn->rollback();
    error_log("upload_media failure: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Failed to upload media: ' . $e->getMessage()]);
}
