<?php
// security_secrets.example.php — Template for DaakPion Security Secrets.
// Copy this file to 'security_secrets.php' and set a cryptographically random pepper.
// NEVER commit 'security_secrets.php' to source control.
// Generate a 64-character hex pepper using: php -r "echo bin2hex(random_bytes(32));"

if (!defined('PASSWORD_PEPPER')) {
    // Must be at least 32 characters (prefer 64-char hex string)
    define('PASSWORD_PEPPER', 'REPLACE_WITH_CRYPTOGRAPHICALLY_RANDOM_64_CHAR_HEX_PEPPER');
}

if (!defined('MESSAGE_ENCRYPTION_KEY')) {
    // Must be at least 32 bytes (prefer 64-char hex string from bin2hex(random_bytes(32)))
    define('MESSAGE_ENCRYPTION_KEY', 'REPLACE_WITH_CRYPTOGRAPHICALLY_RANDOM_64_CHAR_HEX_KEY');
}

// ─── SMTP Email Delivery Configuration ─────────────────────────────────────
// Configure for your SMTP mail provider (e.g., Mailtrap, SendGrid, Gmail, local Postfix)
if (!defined('SMTP_HOST')) {
    define('SMTP_HOST', 'sandbox.smtp.mailtrap.io'); // or smtp.example.com
}
if (!defined('SMTP_PORT')) {
    define('SMTP_PORT', 587); // 587 (TLS/STARTTLS) or 465 (SMTPS) or 2525
}
if (!defined('SMTP_USERNAME')) {
    define('SMTP_USERNAME', 'REPLACE_WITH_SMTP_USERNAME');
}
if (!defined('SMTP_PASSWORD')) {
    define('SMTP_PASSWORD', 'REPLACE_WITH_SMTP_PASSWORD');
}
if (!defined('SMTP_ENCRYPTION')) {
    define('SMTP_ENCRYPTION', 'tls'); // 'tls' (STARTTLS) or 'ssl' (SMTPS) or 'none'
}
if (!defined('MAIL_FROM_ADDRESS')) {
    define('MAIL_FROM_ADDRESS', 'noreply@daakpion.com');
}
if (!defined('MAIL_FROM_NAME')) {
    define('MAIL_FROM_NAME', 'DaakPion');
}
if (!defined('APP_URL')) {
    define('APP_URL', 'http://localhost/Daakpion');
}

