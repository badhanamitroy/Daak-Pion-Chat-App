<?php
include_once "config.php"; // Database connection

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Escape form inputs
    $fname = mysqli_real_escape_string($conn, $_POST['fname']);
    $lname = mysqli_real_escape_string($conn, $_POST['lname']);
    $email = mysqli_real_escape_string($conn, $_POST['email']);
    $password = mysqli_real_escape_string($conn, $_POST['password']);

    // Check if all fields are filled
    if (empty($fname) || empty($lname) || empty($email) || empty($password)) {
        echo "All input fields are required!";
        exit;
    }

    // Validate email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo "$email - This is not a valid email!";
        exit;
    }

    // Check if email already exists
    $checkEmail = mysqli_query($conn, "SELECT * FROM users WHERE email = '{$email}'");
    if (mysqli_num_rows($checkEmail) > 0) {
        echo "Email already exists!";
        exit;
    }

    // Securely hash password
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    // Insert new user
    $sql = "INSERT INTO users (fname, lname, email, password) 
            VALUES ('{$fname}', '{$lname}', '{$email}', '{$hashedPassword}')";

    if (mysqli_query($conn, $sql)) {
        echo "success";
    } else {
        echo "Database error: " . mysqli_error($conn);
    }
} else {
    echo "Invalid request!";
}
?>
