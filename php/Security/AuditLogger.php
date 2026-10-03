<?php
namespace Daakpion\Security;

use mysqli;

/**
 * AuditLogger — Security Event Logging without secret leakage.
 * 
 * Records critical authentication events:
 * - LOGIN_SUCCESS, LOGIN_FAILURE, LOGIN_RATE_LIMITED
 * - 2FA_CHALLENGE_ISSUED, 2FA_SUCCESS, 2FA_FAILURE, 2FA_RATE_LIMITED
 * - PASSWORD_CHANGE_SUCCESS, PASSWORD_CHANGE_FAILURE
 * - TEMPORARY_PASSWORD_ASSIGNED, TEMPORARY_PASSWORD_CONSUMED
 * - PASSWORD_RESET_REQUESTED, PASSWORD_RESET_COMPLETED, PASSWORD_RESET_FAILED
 * - SESSION_INVALIDATED
 * 
 * STRICT PROHIBITIONS:
 * NEVER logs plaintext passwords, password hashes, pepper, OTPs, reset tokens, or session IDs.
 */
class AuditLogger
{
    private ?mysqli $db;
    private static ?string $logFile = null;

    public function __construct(?mysqli $db = null)
    {
        $this->db = $db;
        if (self::$logFile === null) {
            $logDir = __DIR__ . '/../../logs';
            if (!is_dir($logDir)) {
                @mkdir($logDir, 0750, true);
            }
            self::$logFile = $logDir . '/security_audit.log';
        }
    }

    /**
     * Sanitizes contextual data to ensure no sensitive secrets can ever be written to logs.
     */
    private function sanitizeContext(array $details): array
    {
        $sanitized = [];
        $forbiddenKeys = [
            'password', 'new_password', 'current_password', 'confirm_password',
            'hash', 'pepper', 'token', 'reset_token', 'otp', 'code',
            'session_id', 'secret', 'key'
        ];

        foreach ($details as $k => $v) {
            $lowK = strtolower((string)$k);
            $matched = false;
            foreach ($forbiddenKeys as $forbidden) {
                if (strpos($lowK, $forbidden) !== false) {
                    $sanitized[$k] = '[REDACTED]';
                    $matched = true;
                    break;
                }
            }
            if (!$matched) {
                if (is_array($v)) {
                    $sanitized[$k] = $this->sanitizeContext($v);
                } elseif (is_scalar($v) || $v === null) {
                    $sanitized[$k] = $v;
                } else {
                    $sanitized[$k] = '[OBJECT]';
                }
            }
        }
        return $sanitized;
    }

    /**
     * Records a security audit event.
     *
     * @param string $eventType Standardized event identifier
     * @param string $status SUCCESS, FAILURE, BLOCKED, etc.
     * @param int|null $userId User ID if known
     * @param string|null $identifier Username or email
     * @param array $details Non-sensitive contextual metadata
     */
    public function log(
        string $eventType,
        string $status,
        ?int $userId = null,
        ?string $identifier = null,
        array $details = []
    ): void {
        $ip = RateLimiter::getClientIp();
        $userAgent = substr($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown', 0, 250);
        $sanitized = $this->sanitizeContext($details);
        $detailsJson = !empty($sanitized) ? json_encode($sanitized, JSON_UNESCAPED_SLASHES) : null;
        $now = date('Y-m-d H:i:s');

        // 1. Write to database table if DB connection is active
        if ($this->db && !$this->db->connect_errno) {
            try {
                $stmt = $this->db->prepare(
                    "INSERT INTO security_audit_logs (event_type, user_id, identifier, ip_address, user_agent, status, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                );
                if ($stmt) {
                    $stmt->bind_param("sissssss", $eventType, $userId, $identifier, $ip, $userAgent, $status, $detailsJson, $now);
                    $stmt->execute();
                    $stmt->close();
                }
            } catch (\Throwable $e) {
                // Do not crash application if audit DB fails; proceed to file logging
            }
        }

        // 2. Write to secure server audit log file
        if (self::$logFile) {
            $logEntry = sprintf(
                "[%s] [%s] status=%s user_id=%s identifier=%s ip=%s ua=\"%s\" details=%s\n",
                $now,
                $eventType,
                $status,
                $userId ? (string)$userId : 'none',
                $identifier ? $identifier : 'none',
                $ip,
                $userAgent,
                $detailsJson ?? '{}'
            );
            @file_put_contents(self::$logFile, $logEntry, FILE_APPEND | LOCK_EX);
        }
    }
}
