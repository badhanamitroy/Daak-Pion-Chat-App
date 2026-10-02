<?php
// send_message.php
session_start();
require_once "db_connect.php";
require_once "app_config.php"; // Centralized secrets & constants (Step 2.5)

if (!isset($_SESSION['user_id']) || !isset($_POST['receiver_id'], $_POST['message'])) {
    http_response_code(400);
    exit("Missing required fields");
}

$user_id     = (int)$_SESSION['user_id'];
$receiver_id = (int)$_POST['receiver_id'];
$message     = trim($_POST['message']);

if (empty($message) || $receiver_id <= 0) {
    http_response_code(400);
    exit("Invalid input");
}

// Enforce message length cap (prevents DB abuse with huge payloads)
if (mb_strlen($message) > 2000) {
    http_response_code(400);
    exit("Message too long. Maximum is 2000 characters.");
}

// SECRET_KEY is loaded from app_config.php

// FIX BUG-03: Use a random IV per message and store as "iv_b64:ciphertext"
$iv               = random_bytes(16);
$iv_b64           = base64_encode($iv);
$encrypted        = openssl_encrypt($message, 'AES-256-CBC', SECRET_KEY, 0, $iv);
$stored_message   = $iv_b64 . ':' . $encrypted;

$sql  = "INSERT INTO messages (sender_id, receiver_id, message, sent_at, is_read) VALUES (?, ?, ?, NOW(), 0)";
$stmt = $conn->prepare($sql);
$stmt->bind_param("iis", $user_id, $receiver_id, $stored_message);
$stmt->execute();
$stmt->close();

echo "Message sent";
