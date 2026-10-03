<?php
$servername = "localhost";
$username   = "root"; // change if needed
$password   = "";     // change if needed
$dbname     = "daakpion";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    error_log("Database connection failed: " . $conn->connect_error);
    http_response_code(500);
    die("A system error occurred. Please try again later.");
}
?>
