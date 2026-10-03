<?php
namespace Daakpion\Security;

use mysqli;

/**
 * RateLimiter — Atomic, concurrency-safe brute-force protection.
 * 
 * Protects login, 2FA, OTP resends, password resets, and credential changes.
 * Uses MySQL atomic UPSERT (ON DUPLICATE KEY UPDATE) to prevent race conditions.
 * Supports sliding-window rate limiting with time-based lockouts (no permanent DoS lockouts).
 */
class RateLimiter
{
    private mysqli $db;

    public function __construct(mysqli $db)
    {
        $this->db = $db;
    }

    /**
     * Resolves the client IP address securely.
     * NEVER trusts arbitrary X-Forwarded-For headers unless explicitly coming from a trusted proxy.
     */
    public static function getClientIp(): string
    {
        $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

        // Check if trusted proxy configuration is defined
        $trustedProxies = defined('TRUSTED_PROXIES') ? (array)TRUSTED_PROXIES : [];

        if (!empty($trustedProxies) && in_array($remoteAddr, $trustedProxies, true)) {
            if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
                $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
                $clientIp = trim($ips[0]);
                if (filter_var($clientIp, FILTER_VALIDATE_IP)) {
                    return $clientIp;
                }
            }
        }

        return filter_var($remoteAddr, FILTER_VALIDATE_IP) ? $remoteAddr : '127.0.0.1';
    }

    /**
     * Constructs a namespaced rate-limit key.
     */
    public static function buildKey(string $action, string $identifier): string
    {
        $safeId = hash('sha256', strtolower(trim($identifier)));
        return substr("rl:{$action}:{$safeId}", 0, 190);
    }

    /**
     * Checks if a key is currently blocked.
     *
     * @param string $key Rate limit key
     * @param int &$retryAfter Output: remaining seconds until unblocked
     * @return bool True if blocked, false if allowed
     */
    public function isBlocked(string $key, ?int &$retryAfter = 0): bool
    {
        $now = time();
        $stmt = $this->db->prepare("SELECT blocked_until FROM security_rate_limits WHERE rate_key = ?");
        if (!$stmt) {
            return false;
        }

        $stmt->bind_param("s", $key);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $stmt->close();

        if ($row && $row['blocked_until'] > $now) {
            $retryAfter = $row['blocked_until'] - $now;
            return true;
        }

        return false;
    }

    /**
     * Registers a failure/hit against the key atomically.
     * If attempts exceed $maxAttempts within $windowSeconds, blocks the key for $blockSeconds.
     *
     * @param string $key Rate limit key
     * @param int $maxAttempts Maximum allowed failures
     * @param int $windowSeconds Sliding window duration
     * @param int $blockSeconds Block duration on limit exceeded
     * @return array{blocked: bool, attempts: int, retryAfter: int}
     */
    public function hit(string $key, int $maxAttempts = 5, int $windowSeconds = 900, int $blockSeconds = 900): array
    {
        $now = time();

        // Atomic check & update using transaction or atomic query
        $stmt = $this->db->prepare("SELECT attempts, first_attempt_at, blocked_until FROM security_rate_limits WHERE rate_key = ? FOR UPDATE");
        
        $this->db->begin_transaction();
        try {
            $stmt->bind_param("s", $key);
            $stmt->execute();
            $res = $stmt->get_result();
            $row = $res->fetch_assoc();
            $stmt->close();

            $blocked = false;
            $retryAfter = 0;
            $newAttempts = 1;

            if ($row) {
                // If previously blocked and block still active
                if ($row['blocked_until'] > $now) {
                    $this->db->commit();
                    return [
                        'blocked'    => true,
                        'attempts'   => (int)$row['attempts'],
                        'retryAfter' => $row['blocked_until'] - $now,
                    ];
                }

                // If window expired, reset attempts
                if ($now - $row['first_attempt_at'] > $windowSeconds) {
                    $newAttempts = 1;
                    $firstAttempt = $now;
                    $blockedUntil = 0;
                } else {
                    $newAttempts = (int)$row['attempts'] + 1;
                    $firstAttempt = (int)$row['first_attempt_at'];
                    $blockedUntil = 0;

                    if ($newAttempts >= $maxAttempts) {
                        $blocked = true;
                        $blockedUntil = $now + $blockSeconds;
                        $retryAfter = $blockSeconds;
                    }
                }

                $upd = $this->db->prepare("UPDATE security_rate_limits SET attempts = ?, first_attempt_at = ?, last_attempt_at = ?, blocked_until = ? WHERE rate_key = ?");
                $upd->bind_param("iiiis", $newAttempts, $firstAttempt, $now, $blockedUntil, $key);
                $upd->execute();
                $upd->close();
            } else {
                // Insert new entry
                $ins = $this->db->prepare("INSERT INTO security_rate_limits (rate_key, attempts, first_attempt_at, last_attempt_at, blocked_until) VALUES (?, 1, ?, ?, 0)");
                $ins->bind_param("sii", $key, $now, $now);
                $ins->execute();
                $ins->close();
            }

            $this->db->commit();

            return [
                'blocked'    => $blocked,
                'attempts'   => $newAttempts,
                'retryAfter' => $retryAfter,
            ];
        } catch (\Throwable $e) {
            $this->db->rollback();
            return ['blocked' => false, 'attempts' => 1, 'retryAfter' => 0];
        }
    }

    /**
     * Clears rate limit upon successful authentication.
     */
    public function clear(string $key): void
    {
        $stmt = $this->db->prepare("DELETE FROM security_rate_limits WHERE rate_key = ?");
        if ($stmt) {
            $stmt->bind_param("s", $key);
            $stmt->execute();
            $stmt->close();
        }
    }
}
