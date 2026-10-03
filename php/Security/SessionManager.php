<?php
namespace Daakpion\Security;

use mysqli;

/**
 * SessionManager — Hardened session security and lifecycle management.
 * 
 * Features:
 * - Strict cookie flags (HttpOnly, SameSite=Lax, Secure when HTTPS)
 * - Session fixation protection via session_regenerate_id(true)
 * - Idle timeout (30 min) and Absolute lifetime (12 hr)
 * - Cross-device session invalidation via password_version tracking
 * - Server-side enforcement for temporary password / restricted sessions
 */
class SessionManager
{
    public const IDLE_TIMEOUT_SECONDS = 1800;    // 30 minutes
    public const ABSOLUTE_LIFETIME_SECONDS = 43200; // 12 hours

    /**
     * Initializes a hardened PHP session.
     */
    public static function startSecureSession(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            // Enforce strict session mode
            ini_set('session.use_strict_mode', '1');
            ini_set('session.use_only_cookies', '1');

            $isSecure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
                     || (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443);

            session_set_cookie_params([
                'lifetime' => 0, // Until browser closes
                'path'     => '/',
                'domain'   => '',
                'secure'   => $isSecure,
                'httponly' => true,
                'samesite' => 'Lax',
            ]);

            session_start();
        }

        // Validate session timeouts if logged in
        if (isset($_SESSION['user_id'])) {
            $now = time();

            // Check absolute lifetime
            if (isset($_SESSION['created_at']) && ($now - $_SESSION['created_at'] > self::ABSOLUTE_LIFETIME_SECONDS)) {
                self::destroySession();
                return;
            }

            // Check idle timeout
            if (isset($_SESSION['last_activity']) && ($now - $_SESSION['last_activity'] > self::IDLE_TIMEOUT_SECONDS)) {
                self::destroySession();
                return;
            }

            $_SESSION['last_activity'] = $now;
        }
    }

    /**
     * Establishes authenticated user session state.
     * Regenerates session ID to prevent session fixation.
     */
    public static function loginUser(array $user, bool $isTemporary = false): void
    {
        self::startSecureSession();

        // Prevent session fixation
        if (!headers_sent()) {
            session_regenerate_id(true);
        }

        // Store minimum required session attributes
        $_SESSION['user_id']              = (int)$user['id'];
        $_SESSION['user_name']            = trim(($user['fname'] ?? '') . ' ' . ($user['lname'] ?? ''));
        $_SESSION['user_email']           = $user['email'] ?? '';
        $_SESSION['password_version']     = (int)($user['password_version'] ?? 1);
        $_SESSION['must_change_password'] = $isTemporary || !empty($user['is_temporary_password']);
        $_SESSION['created_at']           = time();
        $_SESSION['last_activity']        = time();
    }

    /**
     * Server-side guard to enforce temporary-password restriction.
     * Blocks access to any dashboard/chat/profile endpoint until permanent password is created.
     */
    public static function checkRestrictedAccess(?string $redirectUrl = 'force_change_password.php'): void
    {
        self::startSecureSession();

        if (!empty($_SESSION['must_change_password'])) {
            $currentScript = basename($_SERVER['PHP_SELF'] ?? '');
            $allowedScripts = ['force_change_password.php', 'logout.php'];

            if (!in_array($currentScript, $allowedScripts, true)) {
                // If it's an API request, return 403 JSON
                if (
                    (!empty($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false) ||
                    (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest')
                ) {
                    http_response_code(403);
                    header('Content-Type: application/json');
                    echo json_encode([
                        'error' => 'Temporary credential active. Password change required before accessing this resource.',
                        'must_change_password' => true
                    ]);
                    exit;
                }

                header("Location: {$redirectUrl}");
                exit;
            }
        }
    }

    /**
     * Validates whether current session's password_version is still synchronized with database.
     * If user changed password on another device, this session is terminated.
     */
    public static function validateSessionState(mysqli $db): bool
    {
        self::startSecureSession();

        if (!isset($_SESSION['user_id'])) {
            return false;
        }

        $userId = (int)$_SESSION['user_id'];
        $stmt = $db->prepare("SELECT password_version, is_temporary_password FROM users WHERE id = ?");
        if (!$stmt) {
            return true;
        }

        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $res = $stmt->get_result();
        $row = $res->fetch_assoc();
        $stmt->close();

        if (!$row) {
            self::destroySession();
            return false;
        }

        // Check if password_version changed (e.g. password changed or reset)
        $dbVersion = (int)$row['password_version'];
        $sessionVersion = (int)($_SESSION['password_version'] ?? 0);

        if ($sessionVersion !== $dbVersion) {
            // Password was changed elsewhere; invalidate this session
            self::destroySession();
            return false;
        }

        return true;
    }

    /**
     * Invalidates all other active sessions for a user by incrementing password_version in DB.
     * Retains the current session by syncing its version.
     */
    public static function invalidateOtherSessions(int $userId, mysqli $db): int
    {
        $stmt = $db->prepare("UPDATE users SET password_version = password_version + 1 WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $stmt->close();

        // Get new version
        $get = $db->prepare("SELECT password_version FROM users WHERE id = ?");
        $get->bind_param("i", $userId);
        $get->execute();
        $res = $get->get_result();
        $row = $res->fetch_assoc();
        $get->close();

        $newVersion = (int)($row['password_version'] ?? 1);

        if (session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION['password_version'] = $newVersion;
            if (!headers_sent()) {
                session_regenerate_id(true);
            }
        }

        return $newVersion;
    }

    /**
     * Safely terminates session and clears cookies.
     */
    public static function destroySession(?mysqli $db = null): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        if ($db && isset($_SESSION['user_id'])) {
            $userId = (int)$_SESSION['user_id'];
            $stmt = $db->prepare("UPDATE users SET status = 'Offline', last_activity_at = NULL WHERE id = ?");
            if ($stmt) {
                $stmt->bind_param("i", $userId);
                $stmt->execute();
                $stmt->close();
            }
        }

        $_SESSION = [];

        if (ini_get("session.use_cookies") && !headers_sent()) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                time() - 42000,
                $params["path"],
                $params["domain"],
                $params["secure"],
                $params["httponly"]
            );
        }

        session_destroy();
    }
}

