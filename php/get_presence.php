<?php
// get_presence.php — Authenticated friend presence, typing indicators, and unread counts API
declare(strict_types=1);

require_once __DIR__ . '/bootstrap_security.php';
global $conn;

use Daakpion\Security\SessionManager;

if (!headers_sent()) {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('X-Content-Type-Options: nosniff');
}

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    exit(json_encode(['error' => 'Not logged in']));
}

SessionManager::checkRestrictedAccess();

$currentUserId = (int)$_SESSION['user_id'];
$PRESENCE_TIMEOUT_SECONDS = 120; // 2 minutes server-side presence timeout

// ── 1. Single Friend Inquiry ──────────────────────────────────────────────────
if (isset($_GET['friend_id']) && $_GET['friend_id'] !== '') {
    $friendId = (int)$_GET['friend_id'];
    if ($friendId <= 0) {
        http_response_code(400);
        exit(json_encode(['error' => 'Invalid friend ID']));
    }

    // Step 7 Authorization: Requester can only retrieve presence for confirmed active friends
    $authCheck = $conn->prepare("
        SELECT status FROM friends
        WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
        LIMIT 1
    ");
    if (!$authCheck) {
        http_response_code(500);
        exit(json_encode(['error' => 'A system error occurred']));
    }

    $authCheck->bind_param("iiii", $currentUserId, $friendId, $friendId, $currentUserId);
    $authCheck->execute();
    $authRes = $authCheck->get_result();
    $relRow = $authRes->fetch_assoc();
    $authCheck->close();

    if (!$relRow || $relRow['status'] !== 'active') {
        http_response_code(403);
        exit(json_encode(['error' => 'Unauthorized: Presence only available for confirmed friends']));
    }

    // Query friend's presence
    $stmt = $conn->prepare("
        SELECT id, status,
               (CASE WHEN status != 'Offline' 
                          AND last_activity_at IS NOT NULL 
                          AND TIMESTAMPDIFF(SECOND, last_activity_at, NOW()) <= ? 
                     THEN 1 ELSE 0 END) AS is_online
        FROM users
        WHERE id = ?
        LIMIT 1
    ");
    if (!$stmt) {
        http_response_code(500);
        exit(json_encode(['error' => 'A system error occurred']));
    }

    $stmt->bind_param("ii", $PRESENCE_TIMEOUT_SECONDS, $friendId);
    $stmt->execute();
    $userRow = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$userRow) {
        http_response_code(404);
        exit(json_encode(['error' => 'User not found']));
    }

    $isOnline = ((int)$userRow['is_online']) === 1;

    // Check if this friend is typing to current user
    $isTyping = false;
    $typeStmt = $conn->prepare("
        SELECT 1 FROM typing_indicators
        WHERE user_id = ? AND friend_id = ? AND TIMESTAMPDIFF(SECOND, updated_at, NOW()) <= 4
        LIMIT 1
    ");
    if ($typeStmt) {
        $typeStmt->bind_param("ii", $friendId, $currentUserId);
        $typeStmt->execute();
        $isTyping = $typeStmt->get_result()->num_rows > 0;
        $typeStmt->close();
    }

    // Check unread count from this friend
    $unreadCount = 0;
    $unreadStmt = $conn->prepare("
        SELECT COUNT(*) AS cnt
        FROM messages
        WHERE receiver_id = ? AND sender_id = ? AND is_read = 0 AND deleted_by_receiver = 0 AND is_deleted_all = 0
    ");
    if ($unreadStmt) {
        $unreadStmt->bind_param("ii", $currentUserId, $friendId);
        $unreadStmt->execute();
        $unRow = $unreadStmt->get_result()->fetch_assoc();
        $unreadStmt->close();
        if ($unRow) $unreadCount = (int)$unRow['cnt'];
    }

    echo json_encode([
        'user_id'      => $friendId,
        'is_online'    => $isOnline,
        'status_text'  => $isOnline ? 'Active now' : 'Offline',
        'is_typing'    => $isTyping,
        'unread_count' => $unreadCount
    ]);
    exit;
}

// ── 2. Batch Query for All Confirmed Friends ──────────────────────────────────
$sql = "
    SELECT u.id,
           (CASE WHEN u.status != 'Offline' 
                      AND u.last_activity_at IS NOT NULL 
                      AND TIMESTAMPDIFF(SECOND, u.last_activity_at, NOW()) <= ? 
                 THEN 1 ELSE 0 END) AS is_online
    FROM users u
    JOIN friends f ON ((f.user1_id = ? AND f.user2_id = u.id) OR (f.user2_id = ? AND f.user1_id = u.id))
    WHERE f.status = 'active'
    LIMIT 100
";

$stmt = $conn->prepare($sql);
if (!$stmt) {
    http_response_code(500);
    exit(json_encode(['error' => 'A system error occurred']));
}

$stmt->bind_param("iii", $PRESENCE_TIMEOUT_SECONDS, $currentUserId, $currentUserId);
$stmt->execute();
$res = $stmt->get_result();

$friendsPresence = [];
while ($row = $res->fetch_assoc()) {
    $fId = (int)$row['id'];
    $isOnline = ((int)$row['is_online']) === 1;
    $friendsPresence[$fId] = [
        'is_online'   => $isOnline,
        'status_text' => $isOnline ? 'Active now' : 'Offline',
    ];
}
$stmt->close();

// Batch active typing indicators targeting current user
$activeTyping = [];
$typingStmt = $conn->prepare("
    SELECT user_id FROM typing_indicators
    WHERE friend_id = ? AND TIMESTAMPDIFF(SECOND, updated_at, NOW()) <= 4
");
if ($typingStmt) {
    $typingStmt->bind_param("i", $currentUserId);
    $typingStmt->execute();
    $tRes = $typingStmt->get_result();
    while ($tRow = $tRes->fetch_assoc()) {
        $activeTyping[(int)$tRow['user_id']] = true;
    }
    $typingStmt->close();
}

// Batch unread counts per friend for current user
$unreadCounts = [];
$totalUnread = 0;
$unreadStmt = $conn->prepare("
    SELECT sender_id, COUNT(*) AS cnt
    FROM messages
    WHERE receiver_id = ? AND is_read = 0 AND deleted_by_receiver = 0 AND is_deleted_all = 0
    GROUP BY sender_id
");
if ($unreadStmt) {
    $unreadStmt->bind_param("i", $currentUserId);
    $unreadStmt->execute();
    $uRes = $unreadStmt->get_result();
    while ($uRow = $uRes->fetch_assoc()) {
        $sId = (int)$uRow['sender_id'];
        $c = (int)$uRow['cnt'];
        $unreadCounts[$sId] = $c;
        $totalUnread += $c;
    }
    $unreadStmt->close();
}

echo json_encode([
    'success'       => true,
    'presence'      => $friendsPresence,
    'typing'        => $activeTyping,
    'unread_counts' => $unreadCounts,
    'total_unread'  => $totalUnread
]);
