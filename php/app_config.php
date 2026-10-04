<?php
// app_config.php — Centralized application secrets and constants.
// SECURITY NOTE: In production, move this file ABOVE the web root
//   (e.g., one level up from public_html) and update the require_once path.
//
// All PHP files that need these values must: require_once 'app_config.php';

// ─── Legacy Backward-Compatibility Key (Deprecated) ─────────────────────────
// DEPRECATED: Retained strictly for decrypting legacy pre-v2 AES-256-CBC messages.
// Active message encryption strictly requires MESSAGE_ENCRYPTION_KEY from security_secrets.php.
if (!defined('SECRET_KEY')) {
    define('SECRET_KEY', 'your-strong-secret-key-change-me-in-production');
}

// ─── File Upload Constraints ────────────────────────────────────────────────
define('MAX_UPLOAD_BYTES',   5 * 1024 * 1024);              // 5 MB hard limit
define('ALLOWED_MIME_TYPES', [                               // Whitelist of MIME types
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
]);
define('ALLOWED_EXTENSIONS', ['jpg', 'jpeg', 'png', 'gif', 'webp']); // Extension whitelist

// ─── Security Secrets Loader ────────────────────────────────────────────────
if (file_exists(__DIR__ . '/security_secrets.php')) {
    require_once __DIR__ . '/security_secrets.php';
}

// ─── Password Policy ────────────────────────────────────────────────────────
define('MIN_PASSWORD_LENGTH', 12);

// ─── Application Environment (Resolves DP-VULN-07) ───────────────────────────
// Valid: 'development', 'test', 'production'.
// In production, OTPs and reset tokens are strictly hidden from HTTP responses.
if (!defined('APP_ENV')) {
    $env = getenv('APP_ENV') ?: 'production';
    define('APP_ENV', $env);
}

// ─── Session Security ───────────────────────────────────────────────────────
define('SESSION_LIFETIME_SECONDS', 1800); // 30 minutes idle timeout

?>
