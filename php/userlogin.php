<?php
include_once "config.php";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitize inputs
    $email = mysqli_real_escape_string($conn, $_POST['email']);
    $password = $_POST['password']; // Password will be verified, no need to escape

    if (empty($email) || empty($password)) {
        echo "Email and password are required!";
        exit;
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo "Invalid email format!";
        exit;
    }

    // Check if user exists
    $sql = "SELECT * FROM users WHERE email = '{$email}'";
    $result = mysqli_query($conn, $sql);

    if (mysqli_num_rows($result) === 1) {
        $row = mysqli_fetch_assoc($result);

        // Verify password using password_verify()
        if (password_verify($password, $row['password'])) {
            // Update user status to 'Active now' on successful login
            $updateStatus = "UPDATE users SET status = 'Active now' WHERE id = {$row['id']}";
            mysqli_query($conn, $updateStatus);

            // Here you can start a session and store user info as needed
            session_start();
            $_SESSION['user_id'] = $row['id'];
            $_SESSION['user_name'] = $row['fname'] . ' ' . $row['lname'];

            // echo "login successfull"; // For AJAX or redirection logic
            header("Location: chatboard.php");
            exit;

        } else {
            echo "Incorrect password!";
        }
    } else {
        echo "User not found!";
    }
} else {
    echo "Invalid request!";
}
?>
