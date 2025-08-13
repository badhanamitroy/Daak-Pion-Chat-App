<?php
session_start();
session_unset();
session_destroy();
header("Location: index.html"); // Your login page
exit;
?>
