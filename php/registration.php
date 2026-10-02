<?php
// registration.php
session_start();
require_once "db_connect.php";
require_once "app_config.php";

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit(json_encode(['error' => 'Invalid request method']));
}
$fname    = trim($_POST['fname'] ?? '');
$lname    = trim($_POST['lname'] ?? '');
$email    = trim($_POST['email'] ?? '');
$password = $_POST['password'] ?? '';

if (empty($fname) || empty($lname) || empty($email) || empty($password)) {
    exit(json_encode(['error' => 'All input fields are required!']));
}

if (strlen($fname) > 80 || strlen($lname) > 80) {
    exit(json_encode(['error' => 'Name must be 80 characters or fewer.']));
}

if (strlen($password) < MIN_PASSWORD_LENGTH) {
    exit(json_encode(['error' => 'Password must be at least ' . MIN_PASSWORD_LENGTH . ' characters long.']));
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    exit(json_encode(['error' => 'This is not a valid email address.']));
}

$check = $conn->prepare("SELECT id FROM users WHERE email = ?");
$check->bind_param("s", $email);
$check->execute();
$check->store_result();
if ($check->num_rows > 0) {
    $check->close();
    exit(json_encode(['error' => 'This email address is already registered.']));
}
$check->close();

$hashedPassword = password_hash($password, PASSWORD_DEFAULT);

$stmt = $conn->prepare("INSERT INTO users (fname, lname, email, password) VALUES (?, ?, ?, ?)");
$stmt->bind_param("ssss", $fname, $lname, $email, $hashedPassword);

if ($stmt->execute()) {
    $stmt->close();
    exit(json_encode(['success' => true]));
} else {
    $stmt->close();
    http_response_code(500);
    exit(json_encode(['error' => 'Registration failed. Please try again.']));
}
?>
