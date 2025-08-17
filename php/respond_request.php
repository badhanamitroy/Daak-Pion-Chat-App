<?php
session_start();
require_once "db_connect.php";

if (!isset($_SESSION['user_id'])) {
    exit("Not logged in");
}

$request_id = intval($_POST['request_id'] ?? 0);
$action     = $_POST['action'] ?? '';

if ($request_id <= 0 || !in_array($action, ['accept','decline'])) {
    exit("Invalid input");
}

// find request
$stmt = $conn->prepare("SELECT sender_id, receiver_id FROM friendrequests WHERE id=? AND receiver_id=? AND status='pending'");
$stmt->bind_param("ii", $request_id, $_SESSION['user_id']);
$stmt->execute();
$res = $stmt->get_result();
if (!$row = $res->fetch_assoc()) {
    exit("Request not found");
}
$stmt->close();

if ($action === 'accept') {
    $conn->begin_transaction();
    try {
        $up = $conn->prepare("UPDATE friendrequests SET status='accepted', responded_at=NOW() WHERE id=?");
        $up->bind_param("i", $request_id);
        $up->execute();
        $up->close();

        $ins = $conn->prepare("INSERT INTO friends (user1_id, user2_id, friends_since, status) VALUES (?,?, NOW(),'active')");
        $ins->bind_param("ii", $row['sender_id'], $row['receiver_id']);
        $ins->execute();
        $ins->close();

        $conn->commit();
        echo "Friend request accepted!";
    } catch (Exception $e) {
        $conn->rollback();
        echo "Error: " . $e->getMessage();
    }
} else {
    $up = $conn->prepare("UPDATE friendrequests SET status='declined', responded_at=NOW() WHERE id=?");
    $up->bind_param("i", $request_id);
    $up->execute();
    $up->close();
    echo "Friend request declined!";
}
