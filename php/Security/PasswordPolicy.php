<?php
namespace Daakpion\Security;

/**
 * PasswordPolicy — Enforces production-grade password strength and entropy rules.
 * 
 * Rules:
 * - Minimum 12 characters (recommended baseline)
 * - Maximum 1024 characters (supports long passphrases)
 * - Reject common/obvious passwords (curated common passwords dictionary)
 * - Reject passwords containing user identifier (email, username, first/last name)
 * - Reject simple repeating characters (e.g. 'aaaaaaaaaaaa')
 * - Reject sequential characters (e.g. '123456789012', 'abcdefghijkl')
 * - NEVER logs or leaks password text
 */
class PasswordPolicy
{
    public const MIN_LENGTH = 12;
    public const MAX_LENGTH = 1024;

    /**
     * Common weak passwords blacklist.
     */
    private const COMMON_PASSWORDS = [
        'password1234', 'password12345', '123456789012', '1234567890123',
        'qwertyuiopas', 'qwertyuiop12', 'administrator', 'admin1234567',
        'iloveyou1234', 'letmein12345', 'welcome12345', 'changeme1234',
        'passcode1234', 'default12345', 'daakpion1234', 'daakpion2026',
        'supersecret1', 'trustnoone12', 'masterkey123', 'dragon123456'
    ];

    /**
     * Validates a password against the policy.
     *
     * @param string $password The plaintext password to evaluate
     * @param array $userContext Optional user details to check against (e.g. ['email' => '...', 'fname' => '...', 'lname' => '...'])
     * @return array{valid: bool, errors: string[]}
     */
    public static function validate(string $password, array $userContext = []): array
    {
        $errors = [];
        $len = mb_strlen($password, '8bit');

        // 1. Length validation
        if ($len < self::MIN_LENGTH) {
            $errors[] = "Password must be at least " . self::MIN_LENGTH . " characters long.";
        }

        if ($len > self::MAX_LENGTH) {
            $errors[] = "Password must not exceed " . self::MAX_LENGTH . " characters.";
        }

        // 2. Blacklisted common passwords check
        $normalized = strtolower(trim($password));
        if (in_array($normalized, self::COMMON_PASSWORDS, true)) {
            $errors[] = "This password is too common and easily guessed. Please choose a stronger passphrase.";
        }

        // 3. Repeating character patterns (e.g. 'aaaaaaaaaaaa', '111111111111')
        if (preg_match('/^(.)\1{7,}$/u', $password)) {
            $errors[] = "Password cannot consist predominantly of a single repeated character.";
        }

        // 4. Sequential keyboard patterns (e.g. '123456789012', 'abcdefghijkl')
        $sequences = [
            '01234567890123456789',
            'abcdefghijklmnopqrstuvwxyz',
            'qwertyuiopasdfghjklzxcvbnm'
        ];
        foreach ($sequences as $seq) {
            if ($len >= 6 && stripos($seq, substr($normalized, 0, 8)) !== false) {
                $errors[] = "Password contains a simple sequential keyboard pattern. Please choose a more varied passphrase.";
                break;
            }
        }

        // 5. User identity inclusion check
        if (!empty($userContext)) {
            $identifiers = [];

            if (!empty($userContext['email'])) {
                $emailParts = explode('@', strtolower($userContext['email']));
                if (!empty($emailParts[0]) && strlen($emailParts[0]) >= 3) {
                    $identifiers[] = $emailParts[0];
                }
            }

            if (!empty($userContext['fname']) && strlen($userContext['fname']) >= 3) {
                $identifiers[] = strtolower($userContext['fname']);
            }

            if (!empty($userContext['lname']) && strlen($userContext['lname']) >= 3) {
                $identifiers[] = strtolower($userContext['lname']);
            }

            foreach ($identifiers as $id) {
                if (stripos($normalized, $id) !== false) {
                    $errors[] = "Password must not contain your name, username, or email address.";
                    break;
                }
            }
        }

        return [
            'valid'  => empty($errors),
            'errors' => $errors,
        ];
    }
}
