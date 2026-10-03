<?php
// security_secrets.example.php — Template for DaakPion Security Secrets.
// Copy this file to 'security_secrets.php' and set a cryptographically random pepper.
// NEVER commit 'security_secrets.php' to source control.
// Generate a 64-character hex pepper using: php -r "echo bin2hex(random_bytes(32));"

if (!defined('PASSWORD_PEPPER')) {
    // Must be at least 32 characters (prefer 64-char hex string)
    define('PASSWORD_PEPPER', 'REPLACE_WITH_CRYPTOGRAPHICALLY_RANDOM_64_CHAR_HEX_PEPPER');
}
