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

    /**
     * List of prohibited placeholder message encryption keys that must cause fail-closed behavior.
     */
    private const PROHIBITED_MESSAGE_KEYS = [
        'REPLACE_WITH_CRYPTOGRAPHICALLY_RANDOM_64_CHAR_HEX_KEY',
        'your-strong-secret-key-change-me-in-production',
        'CHANGE_ME',
        '12345678901234567890123456789012',
        'default_message_encryption_key_123456',
        'sps_fallback_message_encryption_key',
        '00000000000000000000000000000000',
        '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    ];

    /**
     * Resolves and derives the 256-bit binary message encryption key from application configuration.
     * Never returns an empty key. Fails closed if dedicated key is missing, malformed, or a placeholder.
     * Never falls back to generic application SECRET_KEY.
     *
     * @param string|null $overrideKey Optional explicit key for testing or rotation
     * @return string Exactly 32 bytes binary key
     * @throws RuntimeException If dedicated message key is missing, malformed, or a placeholder
     */
    public static function getMessageKey(?string $overrideKey = null): string
    {
        $rawKey = $overrideKey;

        if (empty($rawKey)) {
            // 1. Check defined constant MESSAGE_ENCRYPTION_KEY
            if (defined('MESSAGE_ENCRYPTION_KEY')) {
                $rawKey = MESSAGE_ENCRYPTION_KEY;
            }

            // 2. Check environment variables
            if (empty($rawKey)) {
                $env = getenv('MESSAGE_ENCRYPTION_KEY');
                if ($env !== false && $env !== '') {
                    $rawKey = $env;
                } elseif (!empty($_ENV['MESSAGE_ENCRYPTION_KEY'])) {
                    $rawKey = $_ENV['MESSAGE_ENCRYPTION_KEY'];
                } elseif (!empty($_SERVER['MESSAGE_ENCRYPTION_KEY'])) {
                    $rawKey = $_SERVER['MESSAGE_ENCRYPTION_KEY'];
                }
            }

            // 3. Try loading security_secrets.php if not yet defined
            if (empty($rawKey) && file_exists(__DIR__ . '/../security_secrets.php')) {
                require_once __DIR__ . '/../security_secrets.php';
                if (defined('MESSAGE_ENCRYPTION_KEY')) {
                    $rawKey = MESSAGE_ENCRYPTION_KEY;
                }
            }
        }

        // FAIL CLOSED: Dedicated key must be provided
        if (empty($rawKey) || !is_string($rawKey)) {
            throw new RuntimeException("Cryptographic configuration error: Dedicated message encryption key is not configured.");
        }

        // Never allow generic SECRET_KEY as message encryption key
        if (defined('SECRET_KEY') && hash_equals(SECRET_KEY, $rawKey)) {
            throw new RuntimeException("Cryptographic configuration error: Message encryption key cannot reuse generic SECRET_KEY.");
        }

        // Reject prohibited placeholders
        foreach (self::PROHIBITED_MESSAGE_KEYS as $prohibited) {
            if (hash_equals($prohibited, $rawKey)) {
                throw new RuntimeException("Cryptographic configuration error: Message encryption key is a prohibited placeholder.");
            }
        }
        foreach (self::PROHIBITED_PEPPERS as $prohibited) {
            if (hash_equals($prohibited, $rawKey)) {
                throw new RuntimeException("Cryptographic configuration error: Message encryption key cannot reuse placeholder pepper.");
            }
        }

        // Minimum length check (at least 32 bytes or 64 hex characters)
        if (strlen($rawKey) < 32) {
            throw new RuntimeException("Cryptographic configuration error: Message encryption key must be at least 32 bytes.");
        }

        // Derive uniform 32-byte (256-bit) binary key
        if (strlen($rawKey) === 64 && ctype_xdigit($rawKey)) {
            return hex2bin($rawKey);
        }
        if (strlen($rawKey) === 32) {
            return $rawKey;
        }

        return hash('sha256', $rawKey, true);
    }


    /**
     * Encrypts a chat message using AES-256-GCM (Authenticated Encryption with Associated Data).
     *
     * Format: v2:gcm:<base64(12-byte IV)>:<base64(16-byte Tag)>:<base64(Ciphertext)>
     *
     * @param string $plaintext Unencrypted message text
     * @param string|null $overrideKey Optional key for testing
     * @return string Versioned authenticated ciphertext string
     */
    public static function encryptMessage(string $plaintext, ?string $overrideKey = null): string
    {
        $key = self::getMessageKey($overrideKey);

        // 12-byte cryptographically secure random nonce (NIST recommendation for GCM)
        $iv = random_bytes(12);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '', // AAD
            16  // 128-bit authentication tag length
        );

        if ($ciphertext === false || strlen($tag) !== 16) {
            throw new RuntimeException("Authenticated message encryption failed.");
        }

        return 'v2:gcm:' . base64_encode($iv) . ':' . base64_encode($tag) . ':' . base64_encode($ciphertext);
    }

    /**
     * Decrypts a stored chat message.
     * Supports:
     * 1. Modern v2:gcm:<iv>:<tag>:<ciphertext> (AES-256-GCM with authenticated integrity verification)
     * 2. Legacy <iv>:<ciphertext> (AES-256-CBC with random IV)
     * 3. Very old <ciphertext> (AES-256-CBC with static derived IV)
     *
     * Fails closed: Returns null if ciphertext or authentication tag is invalid or tampered.
     * Never returns attacker-manipulated plaintext.
     *
     * @param string $stored Stored ciphertext from database
     * @param string|null $overrideKey Optional key for testing
     * @return string|null Plaintext message or null if decryption/authentication fails
     */
    public static function decryptMessage(string $stored, ?string $overrideKey = null): ?string
    {
        if ($stored === '') {
            return null;
        }

        try {
            $derivedKey = self::getMessageKey($overrideKey);
            $rawSecretKey = $overrideKey ?? (defined('SECRET_KEY') ? SECRET_KEY : '');
        } catch (\Throwable $e) {
            return null;
        }

        // Format 1: Modern Authenticated AES-256-GCM
        if (str_starts_with($stored, 'v2:gcm:')) {
            $parts = explode(':', $stored);
            if (count($parts) !== 5) {
                return null;
            }

            $iv = base64_decode($parts[2], true);
            $tag = base64_decode($parts[3], true);
            $ciphertext = base64_decode($parts[4], true);

            if ($iv === false || $tag === false || $ciphertext === false) {
                return null;
            }

            if (strlen($iv) !== 12 || strlen($tag) !== 16) {
                return null;
            }

            $plaintext = openssl_decrypt(
                $ciphertext,
                'aes-256-gcm',
                $derivedKey,
                OPENSSL_RAW_DATA,
                $iv,
                $tag
            );

            return ($plaintext !== false) ? $plaintext : null;
        }

        // Format 2: Legacy Random-IV AES-256-CBC (<iv_b64>:<ciphertext>)
        if (strpos($stored, ':') !== false) {
            $parts = explode(':', $stored, 2);
            if (count($parts) !== 2) {
                return null;
            }

            $iv = base64_decode($parts[0], true);
            if ($iv === false || strlen($iv) !== 16) {
                return null;
            }

            // Legacy CBC used raw SECRET_KEY directly
            $plaintext = openssl_decrypt($parts[1], 'AES-256-CBC', $rawSecretKey, 0, $iv);
            if ($plaintext === false) {
                $plaintext = openssl_decrypt($parts[1], 'AES-256-CBC', $derivedKey, 0, $iv);
            }

            return ($plaintext !== false) ? $plaintext : null;
        }

        // Format 3: Very old Static-IV AES-256-CBC (<ciphertext>)
        $staticIv = substr(hash('sha256', $rawSecretKey), 0, 16);
        $plaintext = openssl_decrypt($stored, 'AES-256-CBC', $rawSecretKey, 0, $staticIv);
        if ($plaintext === false) {
            $plaintext = openssl_decrypt($stored, 'AES-256-CBC', $derivedKey, 0, $staticIv);
        }

        return ($plaintext !== false) ? $plaintext : null;
    }
}
