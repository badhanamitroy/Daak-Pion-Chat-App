<?php
// index.php — Root entry point for DaakPion
declare(strict_types=1);

require_once __DIR__ . '/php/bootstrap_security.php';

// If user is already authenticated (or restored via persistent login cookie), redirect to profile
if (isset($_SESSION['user_id']) && (int)$_SESSION['user_id'] > 0) {
    if (!empty($_SESSION['must_change_password'])) {
        header("Location: php/force_change_password.php");
    } else {
        header("Location: php/user-profile.php");
    }
    exit;
}

// Otherwise, render landing/login interface
require_once __DIR__ . '/index.html';
