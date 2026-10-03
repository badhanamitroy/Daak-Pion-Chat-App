<?php
// logout.php — Hardened session termination
declare(strict_types=1);

require_once __DIR__ . '/bootstrap_security.php';

use Daakpion\Security\SessionManager;
use Daakpion\Security\AuditLogger;

$logger = new AuditLogger($conn);
$userId = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
$email  = $_SESSION['user_email'] ?? null;

if ($userId) {
    $logger->log('LOGOUT', 'SUCCESS', $userId, $email);
}

SessionManager::destroySession($conn);

header("Location: ../index.html");
exit;
