<?php
// download_attachment.php — Controlled, authenticated attachment streaming endpoint (Resolves DP-P2-014)
declare(strict_types=1);

require_once __DIR__ . '/bootstrap_security.php';
global $conn;

use Daakpion\Security\SessionManager;

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    exit("Unauthorized");
}

SessionManager::checkRestrictedAccess();

$userId = (int)$_SESSION['user_id'];
$attachId = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$wantThumb = isset($_GET['thumb']) && $_GET['thumb'] === '1';
$wantDownload = isset($_GET['download']) && $_GET['download'] === '1';

if ($attachId <= 0) {
    http_response_code(400);
    exit("Invalid attachment ID");
}

// 1. Fetch attachment record and parent message participant metadata
$stmt = $conn->prepare("
    SELECT a.id, a.message_id, a.uploader_id, a.original_name, a.stored_name,
           a.mime_type, a.extension, a.size_bytes, a.media_type, a.storage_path,
           a.thumbnail_path, a.deleted_at,
           m.sender_id, m.receiver_id, m.is_deleted_all,
           m.deleted_by_sender, m.deleted_by_receiver
    FROM message_attachments a
    JOIN messages m ON m.id = a.message_id
    WHERE a.id = ?
    LIMIT 1
");

if (!$stmt) {
    http_response_code(500);
    exit("System error");
}

$stmt->bind_param("i", $attachId);
$stmt->execute();
$attach = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$attach || $attach['deleted_at'] !== null || (int)$attach['is_deleted_all'] === 1) {
    http_response_code(404);
    exit("Attachment not found or has been deleted.");
}

$senderId   = (int)$attach['sender_id'];
$receiverId = (int)$attach['receiver_id'];

// 2. Strict Authorization Check: Requester must be an active participant in this message
if ($userId !== $senderId && $userId !== $receiverId) {
    http_response_code(403);
    exit("Unauthorized: You do not have permission to access this attachment.");
}

// Check per-user soft deletion
if (($userId === $senderId && (int)$attach['deleted_by_sender'] === 1) ||
    ($userId === $receiverId && (int)$attach['deleted_by_receiver'] === 1)) {
    http_response_code(404);
    exit("Attachment is no longer available.");
}

// 3. Resolve Target Physical File
$rootDir = realpath(__DIR__ . '/..');
$baseUploadDir = realpath($rootDir . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . 'message_media');

if (!$baseUploadDir) {
    http_response_code(500);
    exit("Storage directory configuration error.");
}

$relPath = $attach['storage_path'];
$mimeType = $attach['mime_type'];

if ($wantThumb && !empty($attach['thumbnail_path'])) {
    $relPath = $attach['thumbnail_path'];
    $mimeType = 'image/jpeg';
}

$fullPath = realpath($rootDir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relPath));

// Prevent Path Traversal
if (!$fullPath || !str_starts_with($fullPath, $baseUploadDir) || !file_exists($fullPath)) {
    http_response_code(404);
    exit("Attachment file not found on disk.");
}

// 4. Send Secure Streaming Headers
$cleanFileName = preg_replace('/[^\w\.\-\_]/', '_', $attach['original_name']);
$dispositionType = $wantDownload ? 'attachment' : 'inline';

if (!headers_sent()) {
    header('Content-Type: ' . $mimeType);
    header('Content-Length: ' . (string)filesize($fullPath));
    header('Content-Disposition: ' . $dispositionType . '; filename="' . $cleanFileName . '"');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: private, max-age=86400');
}

// Clear any open output buffers and stream file (except in CLI test runners)
if (php_sapi_name() !== 'cli') {
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
}

readfile($fullPath);
exit;
