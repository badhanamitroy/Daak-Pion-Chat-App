<?php
namespace Daakpion\Security;

use mysqli;

/**
 * PasswordResetService — Hardened password reset architecture.
 * 
 * Rules:
 * - Anti-enumeration: Always returns generic response regardless of whether account exists.
 * - Cryptographically random reset tokens (256 bits).
 * - Tokens are NEVER stored plaintext; only SHA-256 hashes are persisted.
 * - Short expiry (15 minutes).
 * - Single-use: Token is marked used immediately.
 * - Invalidation of all other sessions via password_version increment.
 * - Audit logging with zero secret leakage.
 */
class PasswordResetService
{
    public const TOKEN_EXPIRY_SECONDS = 900; // 15 minutes

    private mysqli $db;
    private AuditLogger $logger;
    private RateLimiter $rateLimiter;

    public function __construct(mysqli $db, ?AuditLogger $logger = null, ?RateLimiter $rateLimiter = null)
    {
        $this->db = $db;
        $this->logger = $logger ?? new AuditLogger($db);
        $this->rateLimiter = $rateLimiter ?? new RateLimiter($db);
    }

    /**
     * Initiates a password reset request.
     * Guaranteed anti-enumeration behavior: Returns identical message whether email exists or not.
     *
     * @param string $email User entered email
     * @return array{success: bool, message: string, dev_token?: string}
     */
    public function requestReset(string $email): array
    {
        $email = trim($email);
        $clientIp = RateLimiter::getClientIp();

        // 1. Rate Limiting: Max 3 reset requests per IP / email per 30 minutes
        $ipKey = RateLimiter::buildKey('reset_ip', $clientIp);
        $emailKey = RateLimiter::buildKey('reset_email', $email);

        $ipLimit = $this->rateLimiter->hit($ipKey, 5, 1800, 1800);
        $emailLimit = $this->rateLimiter->hit($emailKey, 3, 1800, 1800);

        if ($ipLimit['blocked'] || $emailLimit['blocked']) {
            $this->logger->log('PASSWORD_RESET_REQUESTED', 'RATE_LIMITED', null, $email);
            return [
                'success' => false,
                'message' => 'Too many reset attempts. Please wait before trying again.'
            ];
        }

        // Generic response string for anti-enumeration
        $genericResponse = [
            'success' => true,
            'message' => 'If the account exists, password reset instructions have been sent.'
        ];

        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            // Constant-time dummy delay
            CryptoService::dummyVerify();
            return $genericResponse;
        }

        // 2. Fetch user
        $stmt = $this->db->prepare("SELECT id, fname, lname FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $res = $stmt->get_result();
        $user = $res->fetch_assoc();
        $stmt->close();

        if (!$user) {
            // Constant-time dummy verification so execution time matches real lookup
            CryptoService::dummyVerify();
            $this->logger->log('PASSWORD_RESET_REQUESTED', 'NONEXISTENT_USER', null, $email);
            return $genericResponse;
        }

        $userId = (int)$user['id'];

        // 3. Invalidate prior active tokens
        $inv = $this->db->prepare("UPDATE password_resets SET used_at = NOW() WHERE user_id = ? AND used_at IS NULL");
        $inv->bind_param("i", $userId);
        $inv->execute();
        $inv->close();

        // 4. Generate cryptographically secure random token (32 bytes = 64 hex chars)
        $rawToken = CryptoService::generateSecureToken(32);
        $tokenHash = CryptoService::hashToken($rawToken);

        $now = date('Y-m-d H:i:s');
        $expiresAt = date('Y-m-d H:i:s', time() + self::TOKEN_EXPIRY_SECONDS);

        // 5. Store ONLY token hash in database (NEVER plaintext token)
        $ins = $this->db->prepare(
            "INSERT INTO password_resets (user_id, token_hash, expires_at, created_at, used_at) VALUES (?, ?, ?, ?, NULL)"
        );
        $ins->bind_param("isss", $userId, $tokenHash, $expiresAt, $now);
        $ins->execute();
        $ins->close();

        // 6. Audit event
        $this->logger->log('PASSWORD_RESET_REQUESTED', 'SUCCESS', $userId, $email, [
            'expires_in' => self::TOKEN_EXPIRY_SECONDS
        ]);

        // 7. Dispatch Password Reset email via centralized MailService
        $baseUrl = MailService::getAppBaseUrl();
        $resetUrl = $baseUrl . '/php/reset_password.php?token=' . urlencode($rawToken);
        $userName = trim(($user['fname'] ?? '') . ' ' . ($user['lname'] ?? ''));

        $mailService = new MailService($this->db, $this->logger);
        $emailSent = $mailService->sendPasswordReset($email, $userName, $resetUrl, $userId);

        // For development/testing verification, return dev_token and dev diagnostics only if permitted by Environment
        if (Environment::allowDevSecrets()) {
            $genericResponse['dev_token'] = $rawToken;
            if (!$emailSent && $mailService->getLastError()) {
                $genericResponse['dev_mail_error'] = $mailService->getLastError();
            }
        }
        return $genericResponse;
    }

    /**
     * Verifies if a reset token is valid and unexpired.
     */
    public function verifyToken(string $rawToken): ?array
    {
        $rawToken = trim($rawToken);
        if (empty($rawToken)) {
            return null;
        }

        $tokenHash = CryptoService::hashToken($rawToken);
        $now = date('Y-m-d H:i:s');

        $stmt = $this->db->prepare(
            "SELECT r.id, r.user_id, r.expires_at, u.email, u.fname, u.lname, u.password 
             FROM password_resets r
             JOIN users u ON u.id = r.user_id
             WHERE r.token_hash = ? AND r.used_at IS NULL"
        );
        $stmt->bind_param("s", $tokenHash);
        $stmt->execute();
        $res = $stmt->get_result();
        $record = $res->fetch_assoc();
        $stmt->close();

        if (!$record) {
            return null;
        }

        if (strtotime($record['expires_at']) < time()) {
            return null;
        }

        return $record;
    }

    /**
     * Completes password reset by applying new password and invalidating sessions.
     */
    public function completeReset(string $rawToken, string $newPassword): array
    {
        $record = $this->verifyToken($rawToken);
        if (!$record) {
            $this->logger->log('PASSWORD_RESET_FAILED', 'INVALID_OR_EXPIRED_TOKEN');
            return ['success' => false, 'error' => 'This password reset link is invalid or has expired.'];
        }

        $userId = (int)$record['user_id'];
        $userContext = [
            'email' => $record['email'],
            'fname' => $record['fname'],
            'lname' => $record['lname'],
        ];

        // 1. Validate new password against policy
        $policy = PasswordPolicy::validate($newPassword, $userContext);
        if (!$policy['valid']) {
            return ['success' => false, 'error' => implode(' ', $policy['errors'])];
        }

        // 2. Ensure new password is not identical to current password
        $needsRehash = false;
        if (CryptoService::verifyPassword($newPassword, $record['password'], $needsRehash)) {
            return ['success' => false, 'error' => 'Your new password cannot be the same as your previous password.'];
        }

        // 3. Hash with pepper + Argon2id
        $newHash = CryptoService::hashPassword($newPassword);

        // 4. Update database in transaction: update password, invalidate reset token, increment password_version
        $this->db->begin_transaction();
        try {
            $tokenHash = CryptoService::hashToken($rawToken);

            // Mark token as used
            $updToken = $this->db->prepare("UPDATE password_resets SET used_at = NOW() WHERE token_hash = ?");
            $updToken->bind_param("s", $tokenHash);
            $updToken->execute();
            $updToken->close();

            // Update user password and clear any temporary flag
            $updUser = $this->db->prepare(
                "UPDATE users SET password = ?, password_version = password_version + 1, is_temporary_password = 0, temp_password_expires_at = NULL WHERE id = ?"
            );
            $updUser->bind_param("si", $newHash, $userId);
            $updUser->execute();
            $updUser->close();

            $this->db->commit();

            // 5. Audit event
            $this->logger->log('PASSWORD_RESET_COMPLETED', 'SUCCESS', $userId, $record['email']);

            return ['success' => true];
        } catch (\Throwable $e) {
            $this->db->rollback();
            return ['success' => false, 'error' => 'An error occurred while resetting your password. Please try again.'];
        }
    }
}
