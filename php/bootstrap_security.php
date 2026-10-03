<?php
// bootstrap_security.php — Initializes DaakPion Security System, Autoloader & Hardened Sessions

require_once __DIR__ . '/app_config.php';
require_once __DIR__ . '/db_connect.php';

// Class autoloader for Daakpion\Security namespace
spl_autoload_register(function ($class) {
    $prefix = 'Daakpion\\Security\\';
    $baseDir = __DIR__ . '/Security/';

    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }

    $relativeClass = substr($class, $len);
    $file = $baseDir . str_replace('\\', '/', $relativeClass) . '.php';

    if (file_exists($file)) {
        require_once $file;
    }
});

// Fail-closed pepper check on application startup
use Daakpion\Security\CryptoService;
use Daakpion\Security\SessionManager;
use Daakpion\Security\RateLimiter;
use Daakpion\Security\AuditLogger;
use Daakpion\Security\PasswordPolicy;
use Daakpion\Security\TwoFactorService;
use Daakpion\Security\PasswordResetService;
use Daakpion\Security\CsrfProtection;

// Validate pepper immediately; if missing/invalid, throws RuntimeException
CryptoService::getPepper();

// Start hardened secure session
SessionManager::startSecureSession();

// Check if user is logged in and session is still valid (cross-device invalidation check)
if (isset($_SESSION['user_id'])) {
    SessionManager::validateSessionState($conn);
}
