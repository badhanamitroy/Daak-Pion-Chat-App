<?php
session_start();
require_once "db_connect.php";

if (!isset($_SESSION['user_id'])) {
    exit("Not logged in");
}

$sender_id   = $_SESSION['user_id'];
$receiver_id = intval($_POST['receiver_id'] ?? 0);

if ($receiver_id <= 0) {
    exit("Invalid receiver");
}

// check if already friends or request exists
$check = $conn->prepare("SELECT id FROM friendrequests WHERE sender_id=? AND receiver_id=? AND status='pending'");
$check->bind_param("ii", $sender_id, $receiver_id);
$check->execute();
$res = $check->get_result();
if ($res->num_rows > 0) {
    exit("Request already sent");
}
$check->close();

$stmt = $conn->prepare("INSERT INTO friendrequests (sender_id, receiver_id, status, sent_at) VALUES (?,?, 'pending', NOW())");
$stmt->bind_param("ii", $sender_id, $receiver_id);
if ($stmt->execute()) {
    echo "Friend request sent!";
} else {
    echo "Error: " . $conn->error;
}
$stmt->close();
