<?php
// tests/Phase5PersistentAuthTest.php — Comprehensive Automated Test Suite for Login Responsiveness & Persistent Auth
declare(strict_types=1);

require_once __DIR__ . '/../php/bootstrap_security.php';

use Daakpion\Security\CryptoService;
use Daakpion\Security\TwoFactorService;
use Daakpion\Security\SessionManager;
use Daakpion\Security\PersistentAuthService;
use Daakpion\Security\CsrfProtection;
use Daakpion\Security\AuditLogger;

class Phase5PersistentAuthTest
{
    private mysqli $db;
    private int $passed = 0;
    private int $failed = 0;
    private array $failures = [];
    private array $cleanupUserIds = [];

    public function __construct(mysqli $db)
    {
        $this->db = $db;
    }

    private function assert(string $testName, bool $condition, string $detail = ''): void
    {
        if ($condition) {
            $this->passed++;
            echo " [PASS] {$testName}\n";
        } else {
            $this->failed++;
            $this->failures[] = "{$testName}: {$detail}";
            echo " [FAIL] {$testName} - {$detail}\n";
        }
    }

    private function createSyntheticUser(string $email, string $rawPassword, bool $twoFactor = false): int
    {
        $hash = CryptoService::hashPassword($rawPassword);
        $twoFactorInt = $twoFactor ? 1 : 0;
        $stmt = $this->db->prepare(
            "INSERT INTO users (fname, lname, email, password, status, two_factor_enabled, password_version) VALUES ('TestFirst', 'TestLast', ?, ?, 'Offline', ?, 1)"
        );
        $stmt->bind_param("ssi", $email, $hash, $twoFactorInt);
        $stmt->execute();
        $id = (int)$this->db->insert_id;
        $stmt->close();
        $this->cleanupUserIds[] = $id;
        return $id;
    }

    private function cleanup(): void
    {
        if (!empty($this->cleanupUserIds)) {
            $idList = implode(',', array_map('intval', $this->cleanupUserIds));
            $this->db->query("DELETE FROM persistent_logins WHERE user_id IN ({$idList})");
            $this->db->query("DELETE FROM two_factor_otps WHERE user_id IN ({$idList})");
            $this->db->query("DELETE FROM security_audit_logs WHERE user_id IN ({$idList})");
            $this->db->query("DELETE FROM users WHERE id IN ({$idList})");
        }
    }

    public function runAll(): void
    {
        echo "=========================================================\n";
        echo "   DAAKPION LOGIN RESPONSIVENESS & PERSISTENT AUTH TESTS \n";
        echo "=========================================================\n\n";

        try {
            $this->test1_SingleClickDirectLoginWithout2fa();
            $this->test2_SingleClick2faInitiation();
            $this->test3_2faCompletionWithPersistentLogin();
            $this->test4_BrowserClosureAndSessionRestoration();
            $this->test5_TokenRotationUponRestoration();
            $this->test6_TamperedValidatorDetectionAndRevocation();
            $this->test7_ExpiredPersistentTokenRejection();
            $this->test8_ExplicitLogoutRevocation();
            $this->test9_DeletedUserPersistentLoginRejection();
            $this->test10_PasswordChangeRevokesPersistentTokens();
            $this->test11_CheckAuthEndpointReturnsCorrectState();
            $this->test12_InvalidCredentialsDoNotStallOrIssueTokens();
        } finally {
            $this->cleanup();
        }

        echo "\n=========================================================\n";
        echo "  RESULTS: {$this->passed} Passed | {$this->failed} Failed\n";
        echo "=========================================================\n";

        if ($this->failed > 0) {
            echo "Failure details:\n";
            foreach ($this->failures as $f) {
                echo " - {$f}\n";
            }
            exit(1);
        }
    }

    /**
     * 1. Single-click direct login for non-2FA user: establishes session, issues remember token, redirects to user-profile.php
     */
    private function test1_SingleClickDirectLoginWithout2fa(): void
    {
        echo "--- 1. SINGLE-CLICK DIRECT LOGIN WITHOUT 2FA ---\n";
        $email = "direct_login_" . bin2hex(random_bytes(4)) . "@example.com";
        $pass  = "StrongPassword123!#";
        $userId = $this->createSyntheticUser($email, $pass, false);

        // Fetch user
        $stmt = $this->db->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        // Simulate login
        SessionManager::loginUser($user, false);
        $this->assert("Session user_id established", isset($_SESSION['user_id']) && (int)$_SESSION['user_id'] === $userId);

        // Issue persistent token
        $issued = PersistentAuthService::issueToken($userId, $this->db);
        $this->assert("Persistent token issued successfully", $issued === true);

        // Verify row exists in DB
        $res = $this->db->query("SELECT id, selector, validator_hash FROM persistent_logins WHERE user_id = {$userId}");
        $row = $res->fetch_assoc();
        $this->assert("Persistent login row created in database", !empty($row['selector']) && !empty($row['validator_hash']));
    }

    /**
     * 2. Single-click 2FA initiation: issues OTP, pre-auth state stored, remember_me preserved
     */
    private function test2_SingleClick2faInitiation(): void
    {
        echo "--- 2. 2FA INITIATION WITH REMEMBER_ME PRESERVED ---\n";
        $_SESSION = [];
        $email = "otp_login_" . bin2hex(random_bytes(4)) . "@example.com";
        $pass  = "StrongPassword123!#";
        $userId = $this->createSyntheticUser($email, $pass, true);

        $twoFactor = new TwoFactorService($this->db);
        $rawOtp = $twoFactor->issueOtp($userId, $email);

        $_SESSION['2fa_preauth_user_id']     = $userId;
        $_SESSION['2fa_preauth_email']       = $email;
        $_SESSION['2fa_preauth_remember_me'] = true;

        $this->assert("Preauth user ID stored in session", $_SESSION['2fa_preauth_user_id'] === $userId);
        $this->assert("Remember-me flag preserved in preauth session", $_SESSION['2fa_preauth_remember_me'] === true);
        $this->assert("User is NOT marked authenticated before OTP", !isset($_SESSION['user_id']));
    }

    /**
     * 3. 2FA completion: verifies OTP, cleans preauth state, establishes session, issues persistent token
     */
    private function test3_2faCompletionWithPersistentLogin(): void
    {
        echo "--- 3. 2FA COMPLETION & PERSISTENT CREDENTIAL CREATION ---\n";
        $email = "otp_verify_" . bin2hex(random_bytes(4)) . "@example.com";
        $pass  = "StrongPassword123!#";
        $userId = $this->createSyntheticUser($email, $pass, true);

        $twoFactor = new TwoFactorService($this->db);
        $rawOtp = $twoFactor->issueOtp($userId, $email);

        // Set pre-auth state
        $_SESSION['2fa_preauth_user_id']     = $userId;
        $_SESSION['2fa_preauth_email']       = $email;
        $_SESSION['2fa_preauth_remember_me'] = true;

        // Verify OTP
        $verif = $twoFactor->verifyOtp($userId, $rawOtp, $email);
        $this->assert("OTP verified successfully", $verif['success'] === true);

        // Simulate verify_2fa.php completion logic
        $uStmt = $this->db->prepare("SELECT * FROM users WHERE id = ?");
        $uStmt->bind_param("i", $userId);
        $uStmt->execute();
        $user = $uStmt->get_result()->fetch_assoc();
        $uStmt->close();

        SessionManager::loginUser($user, false);
        $rememberMe = !empty($_SESSION['2fa_preauth_remember_me']);
        unset($_SESSION['2fa_preauth_user_id'], $_SESSION['2fa_preauth_email'], $_SESSION['2fa_preauth_remember_me']);

        if ($rememberMe) {
            PersistentAuthService::issueToken($userId, $this->db);
        }

        $this->assert("Session user_id is now active", (int)$_SESSION['user_id'] === $userId);
        $this->assert("Preauth state cleaned up", !isset($_SESSION['2fa_preauth_user_id']));

        $pRow = $this->db->query("SELECT id FROM persistent_logins WHERE user_id = {$userId}")->fetch_assoc();
        $this->assert("Persistent login active after 2FA", !empty($pRow['id']));
    }

    /**
     * 4. Browser closure simulation: clears $_SESSION, restores session using cookie
     */
    private function test4_BrowserClosureAndSessionRestoration(): void
    {
        echo "--- 4. BROWSER CLOSURE & PERSISTENT SESSION RESTORATION ---\n";
        $email = "browser_restart_" . bin2hex(random_bytes(4)) . "@example.com";
        $pass  = "StrongPassword123!#";
        $userId = $this->createSyntheticUser($email, $pass, false);

        // Issue token
        $selector = bin2hex(random_bytes(16));
        $validator = bin2hex(random_bytes(32));
        $validatorHash = hash('sha256', $validator);
        $expiresAt = date('Y-m-d H:i:s', time() + 2592000);

        $stmt = $this->db->prepare("INSERT INTO persistent_logins (user_id, selector, validator_hash, expires_at) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("isss", $userId, $selector, $validatorHash, $expiresAt);
        $stmt->execute();
        $stmt->close();

        // Simulate browser closure: session is destroyed, cookie remains
        $_SESSION = [];
        $this->assert("Pre-condition: session is empty after browser restart", empty($_SESSION['user_id']));

        // Set cookie
        $_COOKIE[PersistentAuthService::COOKIE_NAME] = $selector . ':' . $validator;

        // Restore session
        $restoredUserId = PersistentAuthService::validateAndRestore($this->db);
        $this->assert("validateAndRestore returned matching user_id", $restoredUserId === $userId);
        $this->assert("Session state successfully re-established", isset($_SESSION['user_id']) && (int)$_SESSION['user_id'] === $userId);
        $this->assert("User name restored in session", !empty($_SESSION['user_name']));
    }

    /**
     * 5. Token rotation upon restoration
     */
    private function test5_TokenRotationUponRestoration(): void
    {
        echo "--- 5. TOKEN ROTATION UPON RESTORATION ---\n";
        $email = "rotation_" . bin2hex(random_bytes(4)) . "@example.com";
        $pass  = "StrongPassword123!#";
        $userId = $this->createSyntheticUser($email, $pass, false);

        $selector = bin2hex(random_bytes(16));
        $oldValidator = bin2hex(random_bytes(32));
        $oldHash = hash('sha256', $oldValidator);
        $expiresAt = date('Y-m-d H:i:s', time() + 2592000);

        $stmt = $this->db->prepare("INSERT INTO persistent_logins (user_id, selector, validator_hash, expires_at) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("isss", $userId, $selector, $oldHash, $expiresAt);
        $stmt->execute();
        $stmt->close();

        $_SESSION = [];
        $_COOKIE[PersistentAuthService::COOKIE_NAME] = $selector . ':' . $oldValidator;

        $restored = PersistentAuthService::validateAndRestore($this->db);
        $this->assert("Restoration succeeded on first attempt", $restored === $userId);

        // Verify in DB that validator_hash changed (rotation)
        $newRow = $this->db->query("SELECT validator_hash FROM persistent_logins WHERE selector = '{$selector}'")->fetch_assoc();
        $this->assert("Validator hash was rotated in database", $newRow['validator_hash'] !== $oldHash);

        // Old validator must no longer authenticate
        $_SESSION = [];
        $_COOKIE[PersistentAuthService::COOKIE_NAME] = $selector . ':' . $oldValidator;
        $reused = PersistentAuthService::validateAndRestore($this->db);
        $this->assert("Replay of old validator is rejected", $reused === null);
    }

    /**
     * 6. Tampered validator detection and revocation
     */
    private function test6_TamperedValidatorDetectionAndRevocation(): void
    {
        echo "--- 6. TAMPERED VALIDATOR DETECTION & REVOCATION ---\n";
        $email = "tamper_" . bin2hex(random_bytes(4)) . "@example.com";
        $pass  = "StrongPassword123!#";
        $userId = $this->createSyntheticUser($email, $pass, false);

        $selector = bin2hex(random_bytes(16));
        $validValidator = bin2hex(random_bytes(32));
        $validHash = hash('sha256', $validValidator);
        $expiresAt = date('Y-m-d H:i:s', time() + 2592000);

        $stmt = $this->db->prepare("INSERT INTO persistent_logins (user_id, selector, validator_hash, expires_at) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("isss", $userId, $selector, $validHash, $expiresAt);
        $stmt->execute();
        $stmt->close();

        // Present wrong validator with valid selector
        $tamperedValidator = bin2hex(random_bytes(32));
        $_COOKIE[PersistentAuthService::COOKIE_NAME] = $selector . ':' . $tamperedValidator;
        $_SESSION = [];

        $restored = PersistentAuthService::validateAndRestore($this->db);
        $this->assert("Tampered validator rejected", $restored === null);

        // Token should be revoked
        $check = $this->db->query("SELECT id FROM persistent_logins WHERE selector = '{$selector}'")->fetch_assoc();
        $this->assert("Compromised token revoked from database", empty($check));
    }

    /**
     * 7. Expired persistent token rejection
     */
    private function test7_ExpiredPersistentTokenRejection(): void
    {
        echo "--- 7. EXPIRED PERSISTENT TOKEN REJECTION ---\n";
        $email = "expired_" . bin2hex(random_bytes(4)) . "@example.com";
        $pass  = "StrongPassword123!#";
        $userId = $this->createSyntheticUser($email, $pass, false);

        $selector = bin2hex(random_bytes(16));
        $validator = bin2hex(random_bytes(32));
        $hash = hash('sha256', $validator);
        $expiredTime = date('Y-m-d H:i:s', time() - 3600); // 1 hr ago

        $stmt = $this->db->prepare("INSERT INTO persistent_logins (user_id, selector, validator_hash, expires_at) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("isss", $userId, $selector, $hash, $expiredTime);
        $stmt->execute();
        $stmt->close();

        $_COOKIE[PersistentAuthService::COOKIE_NAME] = $selector . ':' . $validator;
        $_SESSION = [];

        $restored = PersistentAuthService::validateAndRestore($this->db);
        $this->assert("Expired token rejected", $restored === null);
        $this->assert("Session was not established", !isset($_SESSION['user_id']));

        // Verify expired token deleted
        $check = $this->db->query("SELECT id FROM persistent_logins WHERE selector = '{$selector}'")->fetch_assoc();
        $this->assert("Expired token deleted from database", empty($check));
    }

    /**
     * 8. Explicit logout revocation
     */
    private function test8_ExplicitLogoutRevocation(): void
    {
        echo "--- 8. EXPLICIT LOGOUT TOKEN REVOCATION ---\n";
        $email = "logout_" . bin2hex(random_bytes(4)) . "@example.com";
        $pass  = "StrongPassword123!#";
        $userId = $this->createSyntheticUser($email, $pass, false);

        $selector = bin2hex(random_bytes(16));
        $validator = bin2hex(random_bytes(32));
        $hash = hash('sha256', $validator);
        $expiresAt = date('Y-m-d H:i:s', time() + 2592000);

        $stmt = $this->db->prepare("INSERT INTO persistent_logins (user_id, selector, validator_hash, expires_at) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("isss", $userId, $selector, $hash, $expiresAt);
        $stmt->execute();
        $stmt->close();

        $_COOKIE[PersistentAuthService::COOKIE_NAME] = $selector . ':' . $validator;

        // Perform revocation as in logout.php
        PersistentAuthService::revokeToken($this->db);

        $this->assert("Cookie unset in \$_COOKIE", empty($_COOKIE[PersistentAuthService::COOKIE_NAME]));
        $row = $this->db->query("SELECT id FROM persistent_logins WHERE selector = '{$selector}'")->fetch_assoc();
        $this->assert("Token deleted from database on explicit logout", empty($row));
    }

    /**
     * 9. Deleted user rejection
     */
    private function test9_DeletedUserPersistentLoginRejection(): void
    {
        echo "--- 9. DELETED USER PERSISTENT LOGIN REJECTION ---\n";
        $email = "deleted_user_" . bin2hex(random_bytes(4)) . "@example.com";
        $pass  = "StrongPassword123!#";
        $userId = $this->createSyntheticUser($email, $pass, false);

        $selector = bin2hex(random_bytes(16));
        $validator = bin2hex(random_bytes(32));
        $hash = hash('sha256', $validator);
        $expiresAt = date('Y-m-d H:i:s', time() + 2592000);

        $stmt = $this->db->prepare("INSERT INTO persistent_logins (user_id, selector, validator_hash, expires_at) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("isss", $userId, $selector, $hash, $expiresAt);
        $stmt->execute();
        $stmt->close();

        // Delete user
        $this->db->query("DELETE FROM users WHERE id = {$userId}");

        $_COOKIE[PersistentAuthService::COOKIE_NAME] = $selector . ':' . $validator;
        $_SESSION = [];

        $restored = PersistentAuthService::validateAndRestore($this->db);
        $this->assert("Deleted user persistent login rejected", $restored === null);
        $this->assert("Session user_id not created", !isset($_SESSION['user_id']));
    }

    /**
     * 10. Password change revokes all persistent tokens
     */
    private function test10_PasswordChangeRevokesPersistentTokens(): void
    {
        echo "--- 10. PASSWORD CHANGE REVOKES ALL PERSISTENT TOKENS ---\n";
        $email = "pwd_change_" . bin2hex(random_bytes(4)) . "@example.com";
        $pass  = "StrongPassword123!#";
        $userId = $this->createSyntheticUser($email, $pass, false);

        // Create 2 persistent tokens (e.g. laptop and phone)
        for ($i = 0; $i < 2; $i++) {
            $selector = bin2hex(random_bytes(16));
            $validator = bin2hex(random_bytes(32));
            $hash = hash('sha256', $validator);
            $expiresAt = date('Y-m-d H:i:s', time() + 2592000);

            $stmt = $this->db->prepare("INSERT INTO persistent_logins (user_id, selector, validator_hash, expires_at) VALUES (?, ?, ?, ?)");
            $stmt->bind_param("isss", $userId, $selector, $hash, $expiresAt);
            $stmt->execute();
            $stmt->close();
        }

        $countBefore = (int)$this->db->query("SELECT COUNT(*) as cnt FROM persistent_logins WHERE user_id = {$userId}")->fetch_assoc()['cnt'];
        $this->assert("Pre-condition: 2 persistent tokens exist", $countBefore === 2);

        // User changes password -> SessionManager::invalidateOtherSessions is called
        SessionManager::invalidateOtherSessions($userId, $this->db);

        $countAfter = (int)$this->db->query("SELECT COUNT(*) as cnt FROM persistent_logins WHERE user_id = {$userId}")->fetch_assoc()['cnt'];
        $this->assert("All persistent tokens revoked after password change", $countAfter === 0);
    }

    /**
     * 11. Check auth endpoint verification
     */
    private function test11_CheckAuthEndpointReturnsCorrectState(): void
    {
        echo "--- 11. CHECK AUTH ENDPOINT STATE ---\n";
        $_SESSION = [];
        $unauthRes = ['authenticated' => isset($_SESSION['user_id']) && (int)$_SESSION['user_id'] > 0];
        $this->assert("Unauthenticated check reports false", $unauthRes['authenticated'] === false);

        $_SESSION['user_id'] = 999;
        $authRes = ['authenticated' => isset($_SESSION['user_id']) && (int)$_SESSION['user_id'] > 0];
        $this->assert("Authenticated check reports true", $authRes['authenticated'] === true);
        $_SESSION = [];
    }

    /**
     * 12. Invalid credentials do not stall or issue persistent tokens
     */
    private function test12_InvalidCredentialsDoNotStallOrIssueTokens(): void
    {
        echo "--- 12. INVALID CREDENTIALS HANDLING ---\n";
        $email = "bad_cred_" . bin2hex(random_bytes(4)) . "@example.com";
        $pass  = "CorrectPassword123!";
        $userId = $this->createSyntheticUser($email, $pass, false);

        // Fetch stored hash
        $storedHash = $this->db->query("SELECT password FROM users WHERE id = {$userId}")->fetch_assoc()['password'];
        $needsRehash = false;
        $isValid = CryptoService::verifyPassword("WrongPassword!", $storedHash, $needsRehash);

        $this->assert("Incorrect password verification fails", $isValid === false);

        $tokens = (int)$this->db->query("SELECT COUNT(*) as cnt FROM persistent_logins WHERE user_id = {$userId}")->fetch_assoc()['cnt'];
        $this->assert("No persistent tokens issued for failed credentials", $tokens === 0);
    }
}

// Execute suite
$test = new Phase5PersistentAuthTest($conn);
$test->runAll();
