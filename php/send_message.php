<?php
session_start();
require_once "db_connect.php";
if(!isset($_SESSION['user_id']) || !isset($_POST['receiver_id'], $_POST['message'])) exit;

$user_id = $_SESSION['user_id'];
$receiver_id = (int)$_POST['receiver_id'];
$message = trim($_POST['message']);
if(empty($message)) exit;

// Secret key (should be unique per user ideally)
define('SECRET_KEY', 'your-strong-secret-key');

// Encrypt the message
$encrypted_message = openssl_encrypt($message, 'AES-256-CBC', SECRET_KEY, 0, substr(hash('sha256', SECRET_KEY), 0, 16));

$sql = "INSERT INTO messages (sender_id, receiver_id, message, sent_at, is_read) VALUES (?,?,?,NOW(),0)";
$stmt = $conn->prepare($sql);
$stmt->bind_param("iis", $user_id, $receiver_id, $encrypted_message);
$stmt->execute();
$stmt->close();

echo "Message sent";
