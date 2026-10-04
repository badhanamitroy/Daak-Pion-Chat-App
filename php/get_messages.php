<?php
// get_messages.php — Fetch encrypted messages with pagination, delivery status, deletion filtering & reply references
declare(strict_types=1);

require_once __DIR__ . "/bootstrap_security.php";
global $conn;

use Daakpion\Security\CryptoService;
use Daakpion\Security\SessionManager;

if (!headers_sent()) {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('X-Content-Type-Options: nosniff');
}

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    exit(json_encode([]));
}

SessionManager::checkRestrictedAccess();

if (!isset($_GET['friend_id'])) {
    http_response_code(400);
    exit(json_encode([]));
}

$user_id   = (int)$_SESSION['user_id'];
$friend_id = (int)$_GET['friend_id'];
$since_id  = isset($_GET['since_id']) ? max(0, (int)$_GET['since_id']) : 0;
$before_id = isset($_GET['before_id']) ? max(0, (int)$_GET['before_id']) : 0;

// Resource Limit Enforcement
$limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 50;
if ($limit <= 0) $limit = 50;
if ($limit > 100) $limit = 100;

// Security: Verify friend_id belongs to an active friend
$friendCheck = $conn->prepare("
    SELECT u.fname, u.lname
    FROM friends f
    JOIN users u ON u.id = ?
    WHERE ((f.user1_id = ? AND f.user2_id = ?) OR (f.user1_id = ? AND f.user2_id = ?))
      AND f.status = 'active'
    LIMIT 1
");

if (!$friendCheck) {
    error_log("Friend check prepare failed: " . $conn->error);
    http_response_code(500);
    exit(json_encode(['error' => 'A server error occurred.']));
}

$friendCheck->bind_param("iiiii", $friend_id, $user_id, $friend_id, $friend_id, $user_id);
$friendCheck->execute();
$friendRes = $friendCheck->get_result();
$friendInfo = $friendRes->fetch_assoc();
$friendCheck->close();

if (!$friendInfo) {
    http_response_code(403);
    exit(json_encode(['error' => 'Not authorized']));
}
$friendName = trim($friendInfo['fname'] . ' ' . $friendInfo['lname']);

// Mark any unread incoming messages as delivered (since receiver is now actively fetching)
$markDelivered = $conn->prepare("
    UPDATE messages
    SET is_delivered = 1
    WHERE receiver_id = ? AND sender_id = ? AND is_delivered = 0
");
if ($markDelivered) {
    $markDelivered->bind_param("ii", $user_id, $friend_id);
    $markDelivered->execute();
    $markDelivered->close();
}

// ── Bounded & Indexed Query with Reply, Attachment & Deletion Resolution ─────
$selectClause = "
    SELECT m.id, m.sender_id, m.receiver_id, m.message, m.reply_to_id, m.client_message_id,
           m.sent_at, m.is_read, m.is_delivered, m.is_deleted_all, m.message_type,
           p.sender_id AS parent_sender_id, p.message AS parent_message, p.is_deleted_all AS parent_is_deleted,
           pu.fname AS parent_fname, pu.lname AS parent_lname,
           a.id AS attach_id, a.original_name AS attach_name, a.mime_type AS attach_mime,
           a.extension AS attach_ext, a.size_bytes AS attach_size, a.media_type AS attach_media_type,
           a.thumbnail_path AS attach_thumb
    FROM messages m
    LEFT JOIN messages p ON p.id = m.reply_to_id
    LEFT JOIN users pu ON pu.id = p.sender_id
    LEFT JOIN message_attachments a ON a.message_id = m.id AND a.deleted_at IS NULL
";

$whereBase = "
    WHERE ((m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?))
      AND NOT (m.sender_id = ? AND m.deleted_by_sender = 1)
      AND NOT (m.receiver_id = ? AND m.deleted_by_receiver = 1)
";

if ($before_id > 0) {
    $sql = $selectClause . $whereBase . " AND m.id < ? ORDER BY m.id DESC LIMIT ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("iiiiiiii", $user_id, $friend_id, $friend_id, $user_id, $user_id, $user_id, $before_id, $limit);
    $needReverse = true;
} elseif ($since_id > 0) {
    $sql = $selectClause . $whereBase . " AND m.id > ? ORDER BY m.id ASC LIMIT ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("iiiiiiii", $user_id, $friend_id, $friend_id, $user_id, $user_id, $user_id, $since_id, $limit);
    $needReverse = false;
} else {
    $sql = $selectClause . $whereBase . " ORDER BY m.id DESC LIMIT ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("iiiiiii", $user_id, $friend_id, $friend_id, $user_id, $user_id, $user_id, $limit);
    $needReverse = true;
}

if (!$stmt) {
    error_log("Message fetch prepare failed: " . $conn->error);
    http_response_code(500);
    exit(json_encode(['error' => 'Failed to load messages.']));
}

$stmt->execute();
$res = $stmt->get_result();

$messages = [];
while ($row = $res->fetch_assoc()) {
    $isDeletedAll = (int)($row['is_deleted_all'] ?? 0) === 1;

    if ($isDeletedAll) {
        $row['message'] = 'This message was deleted';
        $row['is_deleted'] = true;
        $row['attachment'] = null;
    } else {
        $stored = $row['message'];
        $decrypted = CryptoService::decryptMessage($stored);
        $row['message'] = ($decrypted !== null) ? $decrypted : '[message unavailable]';
        $row['is_deleted'] = false;

        // Attachment metadata resolution
        if (!empty($row['attach_id'])) {
            $row['attachment'] = [
                'id'            => (int)$row['attach_id'],
                'original_name' => $row['attach_name'],
                'mime_type'     => $row['attach_mime'],
                'media_type'    => $row['attach_media_type'],
                'size_bytes'    => (int)$row['attach_size'],
                'has_thumbnail' => !empty($row['attach_thumb'])
            ];
        } else {
            $row['attachment'] = null;
        }
    }

    // Resolve reply metadata if present
    if (!empty($row['reply_to_id'])) {
        $parentSnippet = '';
        if ((int)($row['parent_is_deleted'] ?? 0) === 1) {
            $parentSnippet = 'This message was deleted';
        } elseif (!empty($row['parent_message'])) {
            $parentPlain = CryptoService::decryptMessage($row['parent_message']);
            if ($parentPlain !== null) {
                $parentSnippet = mb_strlen($parentPlain) > 60 ? mb_substr($parentPlain, 0, 57) . '...' : $parentPlain;
            } else {
                $parentSnippet = '[message unavailable]';
            }
        }

        $parentAuthor = '';
        if ((int)($row['parent_sender_id'] ?? 0) === $user_id) {
            $parentAuthor = 'You';
        } else {
            $parentAuthor = trim(($row['parent_fname'] ?? '') . ' ' . ($row['parent_lname'] ?? ''));
            if ($parentAuthor === '') $parentAuthor = $friendName;
        }

        $row['reply_to'] = [
            'id'      => (int)$row['reply_to_id'],
            'author'  => $parentAuthor,
            'snippet' => $parentSnippet
        ];
    } else {
        $row['reply_to'] = null;
    }

    // Clean up internal join columns
    unset(
        $row['parent_sender_id'], $row['parent_message'], $row['parent_is_deleted'],
        $row['parent_fname'], $row['parent_lname'],
        $row['attach_id'], $row['attach_name'], $row['attach_mime'],
        $row['attach_ext'], $row['attach_size'], $row['attach_media_type'], $row['attach_thumb']
    );

    // Ensure typed integers
    $row['id']           = (int)$row['id'];
    $row['sender_id']    = (int)$row['sender_id'];
    $row['receiver_id']  = (int)$row['receiver_id'];
    $row['is_read']      = (int)$row['is_read'];
    $row['is_delivered'] = (int)$row['is_delivered'];

    $messages[] = $row;
}
$stmt->close();

if ($needReverse && !empty($messages)) {
    $messages = array_reverse($messages);
}

echo json_encode($messages);
