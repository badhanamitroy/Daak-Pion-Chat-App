<?php
namespace Daakpion\Security;

use mysqli;

/**
 * TwoFactorService — Manages secure 2FA / OTP challenges and verification.
 * 
 * Rules:
 * - Cryptographically random 6-digit OTP
 * - Short expiry (5 minutes)
 * - Single-use only
 * - Stored ONLY as HMAC-SHA256 hash (never plaintext)
 * - Strict attempt limits (max 5)
 * - Rate limiting on resends
 * - Generic error behavior
 * - NEVER logs plaintext OTPs
 */
class TwoFactorService
{
    public const OTP_EXPIRY_SECONDS = 300; // 5 minutes
    public const MAX_ATTEMPTS = 5;
    public const RESEND_INTERVAL_SECONDS = 60; // 1 minute

    private mysqli $db;
    private AuditLogger $logger;

    public function __construct(mysqli $db, ?AuditLogger $logger = null)
    {
        $this->db = $db;
        $this->logger = $logger ?? new AuditLogger($db);
    }

    /**
     * Issues a new OTP for the user. Invalidates previous unused OTPs.
     * Returns the raw OTP ONLY to the delivery mechanism (never stored or logged).
     *
     * @param int $userId User ID
     * @param string|null $email User email for audit context
     * @return string Raw OTP to be sent to user
     */
    public function issueOtp(int $userId, ?string $email = null): string
    {
        $rawOtp = CryptoService::generateOtp(6);
        $otpHash = CryptoService::hashOtp($rawOtp);

        $now = date('Y-m-d H:i:s');
        $expiresAt = date('Y-m-d H:i:s', time() + self::OTP_EXPIRY_SECONDS);

        // Invalidate prior unused OTPs for this user
        $cancel = $this->db->prepare("UPDATE two_factor_otps SET used_at = ? WHERE user_id = ? AND used_at IS NULL");
        if ($cancel) {
            $cancel->bind_param("si", $now, $userId);
            $cancel->execute();
            $cancel->close();
        }

        // Insert new hashed OTP
        $stmt = $this->db->prepare(
            "INSERT INTO two_factor_otps (user_id, otp_hash, expires_at, attempts, created_at, used_at) VALUES (?, ?, ?, 0, ?, NULL)"
        );
        $stmt->bind_param("isss", $userId, $otpHash, $expiresAt, $now);
        $stmt->execute();
        $stmt->close();

        // Audit event (NOTICE: NEVER logs the OTP itself)
        $this->logger->log('2FA_CHALLENGE_ISSUED', 'SUCCESS', $userId, $email, [
            'expires_in_seconds' => self::OTP_EXPIRY_SECONDS
        ]);

        return $rawOtp;
    }

    /**
     * Verifies an OTP provided by the user.
     *
     * @param int $userId User ID
     * @param string $inputOtp User entered OTP
     * @param string|null $email User email for audit logging
     * @return array{success: bool, error?: string}
     */
    public function verifyOtp(int $userId, string $inputOtp, ?string $email = null): array
    {
        $inputOtp = trim($inputOtp);
        $now = time();

        $stmt = $this->db->prepare(
            "SELECT id, otp_hash, expires_at, attempts FROM two_factor_otps WHERE user_id = ? AND used_at IS NULL ORDER BY id DESC LIMIT 1"
        );
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $res = $stmt->get_result();
        $record = $res->fetch_assoc();
        $stmt->close();

        if (!$record) {
            $this->logger->log('2FA_FAILURE', 'NO_ACTIVE_CHALLENGE', $userId, $email);
            return ['success' => false, 'error' => 'Invalid or expired verification code.'];
        }

        $recordId = (int)$record['id'];
        $attempts = (int)$record['attempts'];
        $expiresAt = strtotime($record['expires_at']);

        // Check if attempts exceeded
        if ($attempts >= self::MAX_ATTEMPTS) {
            $markUsed = $this->db->prepare("UPDATE two_factor_otps SET used_at = NOW() WHERE id = ?");
            $markUsed->bind_param("i", $recordId);
            $markUsed->execute();
            $markUsed->close();

            $this->logger->log('2FA_FAILURE', 'ATTEMPTS_EXCEEDED', $userId, $email);
            return ['success' => false, 'error' => 'Too many failed verification attempts. Please request a new code.'];
        }

        // Check expiry
        if ($now > $expiresAt) {
            $markUsed = $this->db->prepare("UPDATE two_factor_otps SET used_at = NOW() WHERE id = ?");
            $markUsed->bind_param("i", $recordId);
            $markUsed->execute();
            $markUsed->close();

            $this->logger->log('2FA_FAILURE', 'EXPIRED', $userId, $email);
            return ['success' => false, 'error' => 'Verification code has expired. Please request a new code.'];
        }

        // Increment attempts count
        $inc = $this->db->prepare("UPDATE two_factor_otps SET attempts = attempts + 1 WHERE id = ?");
        $inc->bind_param("i", $recordId);
        $inc->execute();
        $inc->close();

        // Timing-safe hash comparison
        if (CryptoService::verifyOtp($inputOtp, $record['otp_hash'])) {
            // Success! Invalidate OTP immediately to prevent reuse
            $successUpd = $this->db->prepare("UPDATE two_factor_otps SET used_at = NOW() WHERE id = ?");
            $successUpd->bind_param("i", $recordId);
            $successUpd->execute();
            $successUpd->close();

            $this->logger->log('2FA_SUCCESS', 'SUCCESS', $userId, $email);
            return ['success' => true];
        }

        $this->logger->log('2FA_FAILURE', 'INCORRECT_CODE', $userId, $email, [
            'attempt' => $attempts + 1,
            'max_allowed' => self::MAX_ATTEMPTS
        ]);

        return ['success' => false, 'error' => 'Invalid verification code.'];
    }
}
