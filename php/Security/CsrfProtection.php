<?php
namespace Daakpion\Security;

/**
 * CsrfProtection — Anti-CSRF Token Generation and Timing-Safe Validation.
 */
class CsrfProtection
{
    private const SESSION_KEY = 'csrf_token';

    /**
     * Retrieves existing token or generates a new cryptographically secure token.
     */
    public static function getToken(): string
    {
        if (session_status() === PHP_SESSION_NONE) {
            SessionManager::startSecureSession();
        }

        if (empty($_SESSION[self::SESSION_KEY])) {
            $_SESSION[self::SESSION_KEY] = bin2hex(random_bytes(32));
        }

        return $_SESSION[self::SESSION_KEY];
    }

    /**
     * Renders an HTML hidden input element with the CSRF token.
     */
    public static function renderHiddenField(): string
    {
        $token = htmlspecialchars(self::getToken(), ENT_QUOTES, 'UTF-8');
        return '<input type="hidden" name="csrf_token" value="' . $token . '">';
    }

    /**
     * Validates a submitted CSRF token using constant-time comparison.
     */
    public static function validateToken(?string $submittedToken): bool
    {
        if (session_status() === PHP_SESSION_NONE) {
            SessionManager::startSecureSession();
        }

        $storedToken = $_SESSION[self::SESSION_KEY] ?? null;
        if (empty($storedToken) || empty($submittedToken) || !is_string($submittedToken)) {
            return false;
        }

        return hash_equals($storedToken, $submittedToken);
    }
}
