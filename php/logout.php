<?php
// logout.php
session_start();
require_once "db_connect.php";

// Step 3 bonus: Mark user as offline before destroying the session
if (isset($_SESSION['user_id'])) {
    $userId = (int)$_SESSION['user_id'];
    $stmt   = $conn->prepare("UPDATE users SET status = 'Offline' WHERE id = ?");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $stmt->close();
}

session_unset();
session_destroy();

// Redirect to login page
header("Location: ../index.html");
exit;
?>
