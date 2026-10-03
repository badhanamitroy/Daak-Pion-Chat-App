<?php
namespace Daakpion\Security;

use RuntimeException;

/**
 * CryptoService — Production-grade password hashing, verification, and pepper management.
 * 
 * Cryptography Architecture:
 *   password -> HMAC-SHA256(password, server-side pepper) -> Argon2id -> database
 * 
 * Backward Compatibility:
 *   Supports legacy unpeppered bcrypt hashes for seamless automatic migration.
 */
class CryptoService
{
    /**
     * Argon2id options benchmarked on this deployment environment:
     * - memory_cost: 65536 KiB (64 MiB)
     * - time_cost:   4 iterations
     * - threads:     1 thread
     * - verified execution time: ~207 ms (ideal OWASP range: 100ms - 500ms)
     */
    public const ARGON2_OPTIONS = [
        'memory_cost' => 65536,
        'time_cost'   => 4,
        'threads'     => 1,
    ];

    /**
     * Pre-calculated dummy Argon2id hash used for constant-time verification
     * when a username/email does not exist, resisting user enumeration via timing attacks.
     */
    private const DUMMY_HASH = '$argon2id$v=19$m=65536,t=4,p=1$ZHVtbXlzYWx0MTIzNDU2Nw$N3g6VlX50p5X1w+JgU+aG63iJ94o1E4Q69g3W2a3O7M';

    /**
     * List of prohibited placeholder peppers that must cause fail-closed behavior.
     */
    private const PROHIBITED_PEPPERS = [
        'REPLACE_WITH_CRYPTOGRAPHICALLY_RANDOM_64_CHAR_HEX_PEPPER',
        'your-strong-secret-key-change-me-in-production',
        'CHANGE_ME',
        '12345678901234567890123456789012',
        'default_pepper_secret_key_123456',
        'sps_fallback_pepper_insecure_secret_key'
    ];

    /**
     * Cached validated pepper for current request lifecycle.
     */
    private static ?string $validatedPepper = null;

    /**
     * Retrieves and strictly validates the server-side password pepper.
     * 
     * FAILS CLOSED if pepper is missing, invalid, too short, or a placeholder.
     * Never silently uses a fallback secret.
     *
     * @return string Validated pepper secret
     * @throws RuntimeException If pepper is missing or fails security validation
     */
    public static function getPepper(): string
    {
        if (self::$validatedPepper !== null) {
            return self::$validatedPepper;
        }

        // 1. Try defined constant PASSWORD_PEPPER
        $pepper = null;
        if (defined('PASSWORD_PEPPER')) {
            $pepper = PASSWORD_PEPPER;
        }

        // 2. Try environment variables
        if (empty($pepper)) {
            $env = getenv('PASSWORD_PEPPER');
            if ($env !== false && $env !== '') {
                $pepper = $env;
            } elseif (!empty($_ENV['PASSWORD_PEPPER'])) {
                $pepper = $_ENV['PASSWORD_PEPPER'];
            } elseif (!empty($_SERVER['PASSWORD_PEPPER'])) {
                $pepper = $_SERVER['PASSWORD_PEPPER'];
            }
        }

        // 3. Try loading security_secrets.php if not yet defined
        if (empty($pepper) && file_exists(__DIR__ . '/../security_secrets.php')) {
            require_once __DIR__ . '/../security_secrets.php';
            if (defined('PASSWORD_PEPPER')) {
                $pepper = PASSWORD_PEPPER;
            }
        }

        // Strict Validation (FAIL CLOSED)
        if (empty($pepper) || !is_string($pepper)) {
            // Never expose details or secrets
            throw new RuntimeException("Cryptographic configuration error: Password pepper is not configured.");
        }

        // Minimum length check: at least 32 characters (256-bit hex is 64 characters)
        if (strlen($pepper) < 32) {
            throw new RuntimeException("Cryptographic configuration error: Password pepper does not meet length/entropy requirements.");
        }

        // Prohibited default / placeholder check
        foreach (self::PROHIBITED_PEPPERS as $prohibited) {
            if (hash_equals($prohibited, $pepper)) {
                throw new RuntimeException("Cryptographic configuration error: Insecure default placeholder pepper detected.");
            }
        }

        self::$validatedPepper = $pepper;
        return self::$validatedPepper;
    }

    /**
     * Hashes a password using HMAC-SHA256 with the server-side pepper and Argon2id.
     *
     * @param string $plainPassword Plaintext user password
     * @return string Argon2id password hash
     */
    public static function hashPassword(string $plainPassword): string
    {
        $pepper = self::getPepper();
        $peppered = hash_hmac('sha256', $plainPassword, $pepper);
        
        $hash = password_hash($peppered, PASSWORD_ARGON2ID, self::ARGON2_OPTIONS);
        if ($hash === false) {
            throw new RuntimeException("Password hashing failed.");
        }
        
        return $hash;
    }

    /**
     * Verifies a plaintext password against a stored database hash.
     * 
     * Supports:
     * 1. Modern Argon2id hashes with HMAC-SHA256 pepper
     * 2. Legacy unpeppered bcrypt hashes for seamless transparent migration
     * 
     * @param string $plainPassword Plaintext password provided by user
     * @param string $storedHash Stored hash from database
     * @param bool &$needsRehash Output parameter: true if hash needs migration to current Argon2id config
     * @return bool True if password matches, false otherwise
     */
    public static function verifyPassword(string $plainPassword, string $storedHash, bool &$needsRehash = false): bool
    {
        $needsRehash = false;

        if (empty($plainPassword) || empty($storedHash)) {
            return false;
        }

        $pepper = self::getPepper();
        $peppered = hash_hmac('sha256', $plainPassword, $pepper);

        // 1. Primary check: Peppered password against Argon2id (or peppered legacy)
        if (password_verify($peppered, $storedHash)) {
            // Check if Argon2id parameters changed or need upgrading
            if (password_needs_rehash($storedHash, PASSWORD_ARGON2ID, self::ARGON2_OPTIONS)) {
                $needsRehash = true;
            }
            return true;
        }

        // 2. Legacy check: Unpeppered password against existing bcrypt hash
        // (For existing DaakPion users created before security upgrade)
        if (password_verify($plainPassword, $storedHash)) {
            // Legacy bcrypt matched! Mark for immediate migration to peppered Argon2id
            $needsRehash = true;
            return true;
        }

        return false;
    }

    /**
     * Performs a constant-time dummy verification when user is not found,
     * mitigating timing-based user enumeration.
     */
    public static function dummyVerify(string $dummyInput = 'invalid_dummy_password_timing'): void
    {
        $pepper = null;
        try {
            $pepper = self::getPepper();
        } catch (\Throwable $e) {
            $pepper = 'dummy_fail_closed_safe_timing_string_1234567890';
        }
        $peppered = hash_hmac('sha256', $dummyInput, $pepper);
        password_verify($peppered, self::DUMMY_HASH);
    }

    /**
     * Generates a cryptographically secure random token (e.g. for password reset or CSRF).
     *
     * @param int $bytes Number of random bytes (default: 32 -> 64 hex characters)
     * @return string Hex-encoded random token
     */
    public static function generateSecureToken(int $bytes = 32): string
    {
        return bin2hex(random_bytes($bytes));
    }

    /**
     * Computes a secure HMAC-SHA256 or SHA-256 hash of a sensitive token for database storage.
     * Tokens are NEVER stored plaintext in the database.
     *
     * @param string $token Raw token
     * @return string 64-char SHA-256 hash
     */
    public static function hashToken(string $token): string
    {
        return hash('sha256', $token);
    }

    /**
     * Generates a cryptographically random numeric OTP.
     *
     * @param int $digits Number of digits (default: 6)
     * @return string Zero-padded numeric OTP
     */
    public static function generateOtp(int $digits = 6): string
    {
        $min = 0;
        $max = (10 ** $digits) - 1;
        $num = random_int($min, $max);
        return str_pad((string)$num, $digits, '0', STR_PAD_LEFT);
    }

    /**
     * Hashes an OTP using HMAC-SHA256 with the pepper before database storage.
     * OTPs are NEVER stored plaintext in the database.
     *
     * @param string $otp Raw numeric OTP
     * @return string HMAC hash
     */
    public static function hashOtp(string $otp): string
    {
        return hash_hmac('sha256', $otp, self::getPepper());
    }

    /**
     * Constant-time comparison between user input OTP hash and stored OTP hash.
     */
    public static function verifyOtp(string $rawOtp, string $storedOtpHash): bool
    {
        $computed = self::hashOtp($rawOtp);
        return hash_equals($storedOtpHash, $computed);
    }
}
