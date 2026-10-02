<?php
session_start();
require_once "db_connect.php";
require_once "app_config.php"; // Centralized secrets (Step 2.5)


if (!isset($_SESSION['user_id']) || !isset($_GET['friend_id'])) {
    http_response_code(400);
    header('Content-Type: application/json');
    exit(json_encode([]));
}

$user_id   = (int)$_SESSION['user_id'];
$friend_id = (int)$_GET['friend_id'];
$since_id  = isset($_GET['since_id']) ? (int)$_GET['since_id'] : 0;

// SECRET_KEY loaded from app_config.php

// Security: verify friend_id actually belongs to a friend of this user
$friendCheck = $conn->prepare("
    SELECT 1 FROM friends
    WHERE ((user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?))
      AND status = 'active'
    LIMIT 1
");
$friendCheck->bind_param("iiii", $user_id, $friend_id, $friend_id, $user_id);
$friendCheck->execute();
$friendCheck->store_result();
if ($friendCheck->num_rows === 0) {
    http_response_code(403);
    header('Content-Type: application/json');
    $friendCheck->close();
    exit(json_encode(['error' => 'Not authorized']));
}
$friendCheck->close();

$sql = "
    SELECT id, sender_id, receiver_id, message, sent_at, is_read
    FROM messages
    WHERE ((sender_id = ? AND receiver_id = ?)
        OR (sender_id = ? AND receiver_id = ?))
      AND id > ?
    ORDER BY sent_at ASC
";
$stmt = $conn->prepare($sql);
$stmt->bind_param("iiiii", $user_id, $friend_id, $friend_id, $user_id, $since_id);
$stmt->execute();
$res = $stmt->get_result();

$messages = [];
while ($row = $res->fetch_assoc()) {
    $stored = $row['message'];

    if (strpos($stored, ':') !== false) {
        // নতুন format — random IV:ciphertext
        [$iv_b64, $cipher] = explode(':', $stored, 2);
        $iv  = base64_decode($iv_b64);
        $row['message'] = openssl_decrypt($cipher, 'AES-256-CBC', SECRET_KEY, 0, $iv);
    } else {
        // পুরনো format — static IV (DB তে এখন এটাই আছে)
        $iv = substr(hash('sha256', SECRET_KEY), 0, 16);
        $row['message'] = openssl_decrypt($stored, 'AES-256-CBC', SECRET_KEY, 0, $iv);
    }

    // decrypt fail হলে placeholder দেখাবে
    if ($row['message'] === false) {
        $row['message'] = '[message unavailable]';
    }

    $messages[] = $row;
}
$stmt->close();

header('Content-Type: application/json');
echo json_encode($messages);