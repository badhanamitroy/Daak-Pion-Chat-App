<?php
// get_presence.php — Authenticated friend presence and online status API (Resolves DP-P4-009)
declare(strict_types=1);

require_once __DIR__ . '/bootstrap_security.php';

use Daakpion\Security\SessionManager;

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('X-Content-Type-Options: nosniff');

// 1. Authentication check
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    exit(json_encode(['error' => 'Not logged in']));
}

SessionManager::checkRestrictedAccess();

$currentUserId = (int)$_SESSION['user_id'];
$PRESENCE_TIMEOUT_SECONDS = 120; // 2 minutes server-side presence timeout

// 2. Single friend inquiry vs batch active friends inquiry
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
        // Not friends or blocked — reject request without leaking details
        http_response_code(403);
        exit(json_encode(['error' => 'Unauthorized: Presence only available for confirmed friends']));
    }

    // Query friend's presence using server-authoritative timeout
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

    echo json_encode([
        'user_id'     => $friendId,
        'is_online'   => $isOnline,
        'status_text' => $isOnline ? 'Active now' : 'Offline',
    ]);
    exit;
}

// Batch query for all confirmed friends
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

echo json_encode([
    'success'  => true,
    'presence' => $friendsPresence,
]);
