<?php
namespace Daakpion\Security;

use mysqli;

/**
 * PersistentAuthService — Manages secure "Remember Me" persistent authentication.
 *
 * Security Architecture (Selector + Validator Pattern):
 * - Separation from ordinary PHP session identifier.
 * - Selector: 16 cryptographically secure random bytes (32 hex characters). Used for indexed DB lookup.
 * - Validator: 32 cryptographically secure random bytes (64 hex characters). Authentic secret.
 * - Server stores SHA-256 hash of the validator; raw validator is only present in client cookie.
 * - Cookie Attributes: HttpOnly, SameSite=Lax, Secure (when HTTPS enabled), path=/.
 * - Token Rotation: Validator is rotated on every successful authentication restoration.
 * - Replay/Theft Detection: If a valid selector presents an invalid validator, all tokens for the user are revoked.
 * - Invalidation: Revoked on explicit logout, password change, or account status change.
 */
class PersistentAuthService
{
    public const COOKIE_NAME = 'daakpion_remember';
    public const TOKEN_LIFETIME_SECONDS = 2592000; // 30 days

    /**
     * Determines whether the current request is over HTTPS.
     */
    private static function isHttps(): bool
    {
        return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443);
    }

    /**
     * Sets the persistent login cookie with hardened flags.
     */
    private static function setRememberCookie(string $value, int $expires): void
    {
        if (headers_sent()) {
            return;
        }

        setcookie(
            self::COOKIE_NAME,
            $value,
            [
                'expires'  => $expires,
                'path'     => '/',
                'domain'   => '',
                'secure'   => self::isHttps(),
                'httponly' => true,
                'samesite' => 'Lax',
            ]
        );
    }

    /**
     * Clears the persistent login cookie.
     */
    public static function clearRememberCookie(): void
    {
        unset($_COOKIE[self::COOKIE_NAME]);

        if (headers_sent()) {
            return;
        }

        setcookie(
            self::COOKIE_NAME,
            '',
            [
                'expires'  => time() - 3600,
                'path'     => '/',
                'domain'   => '',
                'secure'   => self::isHttps(),
                'httponly' => true,
                'samesite' => 'Lax',
            ]
        );
    }


    /**
     * Issues a fresh persistent login token for the user and sets the browser cookie.
     */
    public static function issueToken(int $userId, mysqli $db, ?string $ip = null, ?string $userAgent = null): bool
    {
        if ($userId <= 0) {
            return false;
        }

        try {
            $selector = bin2hex(random_bytes(16));  // 32 chars
            $validator = bin2hex(random_bytes(32)); // 64 chars
        } catch (\Throwable $e) {
            return false;
        }

        $validatorHash = hash('sha256', $validator);
        $expiresAt = date('Y-m-d H:i:s', time() + self::TOKEN_LIFETIME_SECONDS);
        $clientIp = $ip ?? RateLimiter::getClientIp();
        $clientUa = $userAgent ?? substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);

        $stmt = $db->prepare(
            "INSERT INTO persistent_logins (user_id, selector, validator_hash, expires_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)"
        );
        if (!$stmt) {
            return false;
        }

        $stmt->bind_param("isssss", $userId, $selector, $validatorHash, $expiresAt, $clientIp, $clientUa);
        $success = $stmt->execute();
        $stmt->close();

        if ($success) {
            $cookieValue = $selector . ':' . $validator;
            self::setRememberCookie($cookieValue, time() + self::TOKEN_LIFETIME_SECONDS);
        }

        return $success;
    }

    /**
     * Validates persistent login cookie and restores authenticated session if valid.
     *
     * @return int|null Returns user_id on successful restoration, null otherwise.
     */
    public static function validateAndRestore(mysqli $db): ?int
    {
        $rawCookie = $_COOKIE[self::COOKIE_NAME] ?? '';
        if (empty($rawCookie) || !is_string($rawCookie) || strpos($rawCookie, ':') === false) {
            return null;
        }

        $parts = explode(':', $rawCookie, 2);
        if (count($parts) !== 2) {
            self::clearRememberCookie();
            return null;
        }

        $selector  = $parts[0];
        $validator = $parts[1];

        // Format validation: selector 32 hex chars, validator 64 hex chars
        if (strlen($selector) !== 32 || strlen($validator) !== 64 || !ctype_xdigit($selector) || !ctype_xdigit($validator)) {
            self::clearRememberCookie();
            return null;
        }

        $stmt = $db->prepare(
            "SELECT id, user_id, validator_hash, expires_at FROM persistent_logins WHERE selector = ? LIMIT 1"
        );
        if (!$stmt) {
            return null;
        }

        $stmt->bind_param("s", $selector);
        $stmt->execute();
        $res = $stmt->get_result();
        $tokenRow = $res->fetch_assoc();
        $stmt->close();

        if (!$tokenRow) {
            self::clearRememberCookie();
            return null;
        }

        $tokenId = (int)$tokenRow['id'];
        $userId  = (int)$tokenRow['user_id'];

        // 1. Check token expiration
        if (strtotime($tokenRow['expires_at']) < time()) {
            $del = $db->prepare("DELETE FROM persistent_logins WHERE id = ?");
            if ($del) {
                $del->bind_param("i", $tokenId);
                $del->execute();
                $del->close();
            }
            self::clearRememberCookie();
            return null;
        }

        // 2. Validate token hash using constant-time comparison
        $expectedHash = hash('sha256', $validator);
        if (!hash_equals($tokenRow['validator_hash'], $expectedHash)) {
            // Potential token theft or tampering: revoke all tokens for this user as a precaution
            self::revokeAllForUser($userId, $db);
            self::clearRememberCookie();

            $logger = new AuditLogger($db);
            $logger->log('PERSISTENT_LOGIN_THEFT_DETECTED', 'VALIDATOR_MISMATCH', $userId, null, [
                'selector' => $selector,
                'ip'       => RateLimiter::getClientIp()
            ]);
            return null;
        }

        // 3. Verify user account eligibility
        $uStmt = $db->prepare(
            "SELECT id, fname, lname, email, password_version, is_temporary_password, temp_password_expires_at FROM users WHERE id = ? LIMIT 1"
        );
        if (!$uStmt) {
            return null;
        }

        $uStmt->bind_param("i", $userId);
        $uStmt->execute();
        $uRes = $uStmt->get_result();
        $user = $uRes->fetch_assoc();
        $uStmt->close();

        if (!$user) {
            // User no longer exists
            $del = $db->prepare("DELETE FROM persistent_logins WHERE user_id = ?");
            if ($del) {
                $del->bind_param("i", $userId);
                $del->execute();
                $del->close();
            }
            self::clearRememberCookie();
            return null;
        }

        // Check if temporary password has expired
        if (!empty($user['is_temporary_password']) && !empty($user['temp_password_expires_at'])) {
            if (strtotime($user['temp_password_expires_at']) < time()) {
                self::clearRememberCookie();
                return null;
            }
        }

        // 4. Token Rotation: generate a fresh validator for the same selector
        try {
            $newValidator = bin2hex(random_bytes(32));
        } catch (\Throwable $e) {
            return null;
        }

        $newValidatorHash = hash('sha256', $newValidator);
        $newExpiresAt = date('Y-m-d H:i:s', time() + self::TOKEN_LIFETIME_SECONDS);
        $clientIp = RateLimiter::getClientIp();
        $clientUa = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);

        $upd = $db->prepare(
            "UPDATE persistent_logins SET validator_hash = ?, expires_at = ?, last_used_at = NOW(), ip_address = ?, user_agent = ? WHERE id = ?"
        );
        if ($upd) {
            $upd->bind_param("ssssi", $newValidatorHash, $newExpiresAt, $clientIp, $clientUa, $tokenId);
            $upd->execute();
            $upd->close();
        }

        // Update cookie with rotated credential
        $newCookieValue = $selector . ':' . $newValidator;
        self::setRememberCookie($newCookieValue, time() + self::TOKEN_LIFETIME_SECONDS);

        // 5. Establish authenticated session
        $isTemp = !empty($user['is_temporary_password']);
        SessionManager::loginUser($user, $isTemp);

        // Update user activity and status
        $updStatus = $db->prepare("UPDATE users SET status = 'Active now', last_activity_at = NOW() WHERE id = ?");
        if ($updStatus) {
            $updStatus->bind_param("i", $userId);
            $updStatus->execute();
            $updStatus->close();
        }

        // Audit log restoration
        $logger = new AuditLogger($db);
        $logger->log('PERSISTENT_LOGIN_RESTORED', 'SUCCESS', $userId, $user['email'] ?? null, [
            'selector' => $selector,
            'ip'       => $clientIp
        ]);

        return $userId;
    }

    /**
     * Revokes the current persistent login token and clears the cookie (used on explicit logout).
     */
    public static function revokeToken(mysqli $db): void
    {
        $rawCookie = $_COOKIE[self::COOKIE_NAME] ?? '';
        if (!empty($rawCookie) && is_string($rawCookie) && strpos($rawCookie, ':') !== false) {
            $parts = explode(':', $rawCookie, 2);
            $selector = $parts[0] ?? '';
            if (strlen($selector) === 32 && ctype_xdigit($selector)) {
                $stmt = $db->prepare("DELETE FROM persistent_logins WHERE selector = ?");
                if ($stmt) {
                    $stmt->bind_param("s", $selector);
                    $stmt->execute();
                    $stmt->close();
                }
            }
        }

        self::clearRememberCookie();
    }

    /**
     * Revokes all persistent login tokens for a specific user (used on password change/reset).
     */
    public static function revokeAllForUser(int $userId, mysqli $db): void
    {
        if ($userId <= 0) {
            return;
        }

        $stmt = $db->prepare("DELETE FROM persistent_logins WHERE user_id = ?");
        if ($stmt) {
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            $stmt->close();
        }

        self::clearRememberCookie();
    }
}
