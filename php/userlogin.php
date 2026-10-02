<?php
// userlogin.php
session_start(); // FIX BUG-04: Must be the very first call
require_once "db_connect.php"; // Single shared DB connection

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email    = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    // Validate inputs
    if (empty($email) || empty($password)) {
        echo "Email and password are required!";
        exit;
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo "Invalid email format!";
        exit;
    }

    // Fetch user by email using prepared statement
    $stmt = $conn->prepare("SELECT id, fname, lname, password FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {
        $row = $result->fetch_assoc();
        $stmt->close();

        // Verify hashed password
        if (password_verify($password, $row['password'])) {
            // Update user status to 'Active now'
            $upd = $conn->prepare("UPDATE users SET status = 'Active now' WHERE id = ?");
            $upd->bind_param("i", $row['id']);
            $upd->execute();
            $upd->close();

            // Prevent session fixation: issue a new session ID after successful auth
            session_regenerate_id(true);

            // Store user info in session
            $_SESSION['user_id']   = $row['id'];
            $_SESSION['user_name'] = $row['fname'] . ' ' . $row['lname'];

            header("Location: chatboard.php");
            exit;
        } else {
            echo "Incorrect password!";
        }
    } else {
        $stmt->close();
        echo "User not found!";
    }
} else {
    echo "Invalid request!";
}
?>
