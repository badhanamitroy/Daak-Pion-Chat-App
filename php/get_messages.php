<?php
session_start();
require_once "db_connect.php";
if(!isset($_SESSION['user_id']) || !isset($_GET['friend_id'])) exit;

$user_id = $_SESSION['user_id'];
$friend_id = (int)$_GET['friend_id'];

// Secret key
define('SECRET_KEY', 'your-strong-secret-key');

$sql = "SELECT * FROM messages 
        WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?) 
        ORDER BY sent_at ASC";
$stmt = $conn->prepare($sql);
$stmt->bind_param("iiii", $user_id,$friend_id,$friend_id,$user_id);
$stmt->execute();
$res = $stmt->get_result();

$messages = [];
while($row = $res->fetch_assoc()){
    // Decrypt the message
    $row['message'] = openssl_decrypt($row['message'], 'AES-256-CBC', SECRET_KEY, 0, substr(hash('sha256', SECRET_KEY), 0, 16));
    $messages[] = $row;
}

header('Content-Type: application/json');
echo json_encode($messages);
