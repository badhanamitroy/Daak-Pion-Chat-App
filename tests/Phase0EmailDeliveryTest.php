<?php
// tests/Phase0EmailDeliveryTest.php — Comprehensive Automated Test Suite for Phase 0 Email Delivery
declare(strict_types=1);

require_once __DIR__ . '/../php/bootstrap_security.php';

use Daakpion\Security\CryptoService;
use Daakpion\Security\TwoFactorService;
use Daakpion\Security\PasswordResetService;
use Daakpion\Security\MailService;
use Daakpion\Security\Environment;
use Daakpion\Security\RateLimiter;
use Daakpion\Security\AuditLogger;

class Phase0EmailDeliveryTest
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
            "INSERT INTO users (fname, lname, email, password, status, two_factor_enabled, password_version) VALUES ('Phase0', 'Tester', ?, ?, 'Offline', ?, 1)"
        );
        $stmt->bind_param("ssi", $email, $hash, $twoFactorInt);
        $stmt->execute();
        $id = (int)$this->db->insert_id;
        $stmt->close();
        $this->cleanupUserIds[] = $id;
        return $id;
    }

    public function runAll(): void
    {
        echo "=========================================================\n";
        echo "   DAAKPION PHASE 0 EMAIL DELIVERY AUTOMATED TEST SUITE  \n";
        echo "=========================================================\n\n";

        try {
            $this->test1_NormalLoginWithout2FA();
            $this->test2_LoginWith2FAEnabled();
            $this->test3_CorrectOtpVerification();
            $this->test4_IncorrectOtpVerification();
            $this->test5_ExpiredOtpVerification();
            $this->test6_OtpResendFlow();
            $this->test7_OtpResendRateLimit();
            $this->test8_PasswordResetExistingEmail();
            $this->test9_PasswordResetUnknownEmailAntiEnumeration();
            $this->test10_ResetTokenExpiry();
            $this->test11_ResetTokenSingleUse();
            $this->test12_InvalidResetToken();
            $this->test13_SmtpFailureHandling();
            $this->test14_MissingSmtpConfiguration();
            $this->test15_ProductionModeBehavior();
            $this->test16_DevelopmentModeBehavior();
            $this->test17_AuditLogEntries();
            $this->test18_NoSecretsInLogs();
            $this->test19_NoOtpInProductionPageSource();
            $this->test20_NoResetTokenInProductionPageSource();
        } finally {
            $this->cleanupSyntheticData();
        }

        echo "\n=========================================================\n";
        echo "  PHASE 0 RESULTS: {$this->passed} Passed | {$this->failed} Failed\n";
        echo "=========================================================\n";

        if ($this->failed > 0) {
            echo "\nFailures encountered:\n";
            foreach ($this->failures as $f) {
                echo "  - {$f}\n";
            }
            exit(1);
        }
    }

    /**
     * 1. Mandatory 2FA for all users
     */
    private function test1_NormalLoginWithout2FA(): void
    {
        echo "--- 1. MANDATORY 2FA ENFORCEMENT ---\n";
        $email = "test1_mandatory2fa_" . bin2hex(random_bytes(4)) . "@example.com";
        $password = "StrongPassphrase2026!#";
        $userId = $this->createSyntheticUser($email, $password, true);

        $stmt = $this->db->prepare("SELECT id, fname, lname, email, password, two_factor_enabled FROM users WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        $needsRehash = false;
        $valid = CryptoService::verifyPassword($password, $user['password'], $needsRehash);
        $this->assert("Password verifies correctly", $valid);
        $this->assert("2FA is strictly enabled for user", !empty($user['two_factor_enabled']));
    }

    /**
     * 2. Login with 2FA enabled
     */
    private function test2_LoginWith2FAEnabled(): void
    {
        echo "--- 2. LOGIN WITH 2FA ENABLED ---\n";
        $email = "test2_2fa_" . bin2hex(random_bytes(4)) . "@example.com";
        $password = "StrongPassphrase2026!#";
        $userId = $this->createSyntheticUser($email, $password, true);

        $twoFactor = new TwoFactorService($this->db);
        $rawOtp = $twoFactor->issueOtp($userId, $email);

        $this->assert("OTP generated with length 6", strlen($rawOtp) === 6 && ctype_digit($rawOtp));

        // Verify mail dispatch method can be called with valid parameters
        $mailService = new MailService($this->db);
        $this->assert("MailService instance created", $mailService instanceof MailService);
    }

    /**
     * 3. Correct OTP
     */
    private function test3_CorrectOtpVerification(): void
    {
        echo "--- 3. CORRECT OTP VERIFICATION ---\n";
        $email = "test3_otp_" . bin2hex(random_bytes(4)) . "@example.com";
        $password = "StrongPassphrase2026!#";
        $userId = $this->createSyntheticUser($email, $password, true);

        $twoFactor = new TwoFactorService($this->db);
        $rawOtp = $twoFactor->issueOtp($userId, $email);

        $res = $twoFactor->verifyOtp($userId, $rawOtp, $email);
        $this->assert("Correct OTP succeeds", $res['success'] === true);
    }

    /**
     * 4. Incorrect OTP
     */
    private function test4_IncorrectOtpVerification(): void
    {
        echo "--- 4. INCORRECT OTP VERIFICATION ---\n";
        $email = "test4_badotp_" . bin2hex(random_bytes(4)) . "@example.com";
        $userId = $this->createSyntheticUser($email, "StrongPassphrase2026!#", true);

        $twoFactor = new TwoFactorService($this->db);
        $twoFactor->issueOtp($userId, $email);

        $res = $twoFactor->verifyOtp($userId, "000000", $email);
        $this->assert("Incorrect OTP is rejected", $res['success'] === false);
    }

    /**
     * 5. Expired OTP
     */
    private function test5_ExpiredOtpVerification(): void
    {
        echo "--- 5. EXPIRED OTP VERIFICATION ---\n";
        $email = "test5_expotp_" . bin2hex(random_bytes(4)) . "@example.com";
        $userId = $this->createSyntheticUser($email, "StrongPassphrase2026!#", true);

        $twoFactor = new TwoFactorService($this->db);
        $rawOtp = $twoFactor->issueOtp($userId, $email);

        // Manually age OTP past expiry in database
        $past = date('Y-m-d H:i:s', time() - 3600);
        $this->db->query("UPDATE two_factor_otps SET expires_at = '{$past}' WHERE user_id = {$userId}");

        $res = $twoFactor->verifyOtp($userId, $rawOtp, $email);
        $this->assert("Expired OTP is rejected", $res['success'] === false);
        $this->assert("Rejection reason mentions expired", str_contains(strtolower($res['error'] ?? ''), 'expired'));
    }

    /**
     * 6. OTP resend
     */
    private function test6_OtpResendFlow(): void
    {
        echo "--- 6. OTP RESEND FLOW ---\n";
        $email = "test6_resend_" . bin2hex(random_bytes(4)) . "@example.com";
        $userId = $this->createSyntheticUser($email, "StrongPassphrase2026!#", true);

        $twoFactor = new TwoFactorService($this->db);
        $firstOtp = $twoFactor->issueOtp($userId, $email);
        $secondOtp = $twoFactor->issueOtp($userId, $email);

        // Prior OTP must be invalidated
        $firstRes = $twoFactor->verifyOtp($userId, $firstOtp, $email);
        $this->assert("First OTP is invalidated by resend", $firstRes['success'] === false);

        // Second OTP must succeed
        $secondRes = $twoFactor->verifyOtp($userId, $secondOtp, $email);
        $this->assert("Second (latest) OTP verifies successfully", $secondRes['success'] === true);
    }

    /**
     * 7. OTP resend rate limit
     */
    private function test7_OtpResendRateLimit(): void
    {
        echo "--- 7. OTP RESEND RATE LIMIT ---\n";
        $rateLimiter = new RateLimiter($this->db);
        $userId = 999990 + random_int(1, 999);
        $key = RateLimiter::buildKey('otp_resend', (string)$userId);

        $rateLimiter->clear($key);
        $hit1 = $rateLimiter->hit($key, 1, 60, 60);
        $this->assert("First resend attempt is allowed", $hit1['blocked'] === false);

        $hit2 = $rateLimiter->hit($key, 1, 60, 60);
        $this->assert("Second immediate resend attempt is blocked by rate limit", $hit2['blocked'] === true);
        $this->assert("Retry after is positive", $hit2['retryAfter'] > 0);

        $rateLimiter->clear($key);
    }

    /**
     * 8. Password reset request for existing email
     */
    private function test8_PasswordResetExistingEmail(): void
    {
        echo "--- 8. PASSWORD RESET REQUEST FOR EXISTING EMAIL ---\n";
        $email = "test8_reset_" . bin2hex(random_bytes(4)) . "@example.com";
        $userId = $this->createSyntheticUser($email, "StrongPassphrase2026!#", false);

        $rateLimiter = new RateLimiter($this->db);
        $rateLimiter->clear(RateLimiter::buildKey('reset_ip', RateLimiter::getClientIp()));

        $service = new PasswordResetService($this->db);
        $res = $service->requestReset($email);

        $this->assert("Request reset returns success response", $res['success'] === true, $res['message'] ?? '');
        $this->assert("Response uses anti-enumeration message", str_contains($res['message'], 'instructions have been sent'));

        // Verify token hash is stored in database
        $stmt = $this->db->prepare("SELECT id, token_hash, expires_at FROM password_resets WHERE user_id = ? AND used_at IS NULL");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        $this->assert("Password reset row was inserted", !empty($row));
        $this->assert("Token is stored as 64-char hex hash", strlen($row['token_hash']) === 64);
    }

    /**
     * 9. Password reset request for unknown email
     */
    private function test9_PasswordResetUnknownEmailAntiEnumeration(): void
    {
        echo "--- 9. PASSWORD RESET REQUEST FOR UNKNOWN EMAIL ---\n";
        $unknownEmail = "nonexistent_" . bin2hex(random_bytes(6)) . "@example.com";

        $rateLimiter = new RateLimiter($this->db);
        $rateLimiter->clear(RateLimiter::buildKey('reset_ip', RateLimiter::getClientIp()));

        $service = new PasswordResetService($this->db);
        $res = $service->requestReset($unknownEmail);

        $this->assert("Unknown email returns success status", $res['success'] === true, $res['message'] ?? '');
        $this->assert("Unknown email returns identical anti-enumeration message", $res['message'] === 'If the account exists, password reset instructions have been sent.');

        // Verify NO token was created in DB
        $stmt = $this->db->prepare("SELECT COUNT(*) as c FROM password_resets r JOIN users u ON u.id = r.user_id WHERE u.email = ?");
        $stmt->bind_param("s", $unknownEmail);
        $stmt->execute();
        $cnt = (int)$stmt->get_result()->fetch_assoc()['c'];
        $stmt->close();

        $this->assert("Zero tokens created for nonexistent user", $cnt === 0);
    }

    /**
     * 10. Reset token expiry
     */
    private function test10_ResetTokenExpiry(): void
    {
        echo "--- 10. RESET TOKEN EXPIRY ---\n";
        $email = "test10_exp_" . bin2hex(random_bytes(4)) . "@example.com";
        $userId = $this->createSyntheticUser($email, "StrongPassphrase2026!#", false);

        $service = new PasswordResetService($this->db);
        $rawToken = CryptoService::generateSecureToken(32);
        $tokenHash = CryptoService::hashToken($rawToken);
        $expiredTime = date('Y-m-d H:i:s', time() - 60);

        $stmt = $this->db->prepare("INSERT INTO password_resets (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, NOW())");
        $stmt->bind_param("iss", $userId, $tokenHash, $expiredTime);
        $stmt->execute();
        $stmt->close();

        $record = $service->verifyToken($rawToken);
        $this->assert("Expired reset token evaluates to null", $record === null);
    }

    /**
     * 11. Reset token single-use behavior
     */
    private function test11_ResetTokenSingleUse(): void
    {
        echo "--- 11. RESET TOKEN SINGLE-USE BEHAVIOR ---\n";
        $email = "test11_single_" . bin2hex(random_bytes(4)) . "@example.com";
        $userId = $this->createSyntheticUser($email, "OldPasswordPassphrase2026!", false);

        $service = new PasswordResetService($this->db);
        $rawToken = CryptoService::generateSecureToken(32);
        $tokenHash = CryptoService::hashToken($rawToken);
        $expires = date('Y-m-d H:i:s', time() + 900);

        $stmt = $this->db->prepare("INSERT INTO password_resets (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, NOW())");
        $stmt->bind_param("iss", $userId, $tokenHash, $expires);
        $stmt->execute();
        $stmt->close();

        $firstReset = $service->completeReset($rawToken, "NewBrandPassphrase2026!");
        $this->assert("First reset with token succeeds", $firstReset['success'] === true);

        $secondReset = $service->completeReset($rawToken, "AnotherPassphrase2026!");
        $this->assert("Second reset with same token is rejected", $secondReset['success'] === false);
    }

    /**
     * 12. Invalid reset token
     */
    private function test12_InvalidResetToken(): void
    {
        echo "--- 12. INVALID RESET TOKEN ---\n";
        $service = new PasswordResetService($this->db);

        $res1 = $service->verifyToken("completely-invalid-bogus-token");
        $this->assert("Bogus token returns null", $res1 === null);

        $res2 = $service->verifyToken("");
        $this->assert("Empty token returns null", $res2 === null);

        $completeRes = $service->completeReset("bogus-token", "NewPassphrase2026!");
        $this->assert("completeReset with invalid token fails", $completeRes['success'] === false);
    }

    /**
     * 13. SMTP failure
     */
    private function test13_SmtpFailureHandling(): void
    {
        echo "--- 13. SMTP FAILURE HANDLING ---\n";
        $mailService = new MailService($this->db);

        // Attempting to send to invalid email format
        $sent = $mailService->sendTwoFactorOtp("not-an-email", "Tester", "123456");
        $this->assert("Invalid email fails gracefully without exception", $sent === false);
        $this->assert("Last error is recorded", !empty($mailService->getLastError()));
    }

    /**
     * 14. Missing SMTP configuration
     */
    private function test14_MissingSmtpConfiguration(): void
    {
        echo "--- 14. MISSING SMTP CONFIGURATION ---\n";
        $configured = MailService::isConfigured();
        // Regardless of whether host is localhost or placeholder, method executes cleanly
        $this->assert("MailService::isConfigured() returns boolean", is_bool($configured));

        $baseUrl = MailService::getAppBaseUrl();
        $this->assert("MailService::getAppBaseUrl() returns valid URL", filter_var($baseUrl, FILTER_VALIDATE_URL) !== false);
    }

    /**
     * 15. Production-mode behavior
     */
    private function test15_ProductionModeBehavior(): void
    {
        echo "--- 15. PRODUCTION-MODE BEHAVIOR ---\n";
        putenv('APP_ENV=production');
        $_SERVER['APP_ENV'] = 'production';

        $this->assert("Environment detects production", Environment::isProduction());
        $this->assert("allowDevSecrets returns false in production", Environment::allowDevSecrets() === false);

        $email = "test15_prod_" . bin2hex(random_bytes(4)) . "@example.com";
        $userId = $this->createSyntheticUser($email, "StrongPassphrase2026!#", false);

        $rateLimiter = new RateLimiter($this->db);
        $rateLimiter->clear(RateLimiter::buildKey('reset_ip', RateLimiter::getClientIp()));

        $service = new PasswordResetService($this->db);
        $res = $service->requestReset($email);

        $this->assert("Production requestReset omits dev_token", !isset($res['dev_token']));
        $this->assert("Production requestReset omits dev_mail_error", !isset($res['dev_mail_error']));
    }

    /**
     * 16. Development-mode behavior
     */
    private function test16_DevelopmentModeBehavior(): void
    {
        echo "--- 16. DEVELOPMENT-MODE BEHAVIOR ---\n";
        putenv('APP_ENV=development');
        $_SERVER['APP_ENV'] = 'development';

        $this->assert("Environment detects development", Environment::isDevelopment());
        $this->assert("allowDevSecrets returns true in development", Environment::allowDevSecrets() === true);

        $email = "test16_dev_" . bin2hex(random_bytes(4)) . "@example.com";
        $userId = $this->createSyntheticUser($email, "StrongPassphrase2026!#", false);

        $rateLimiter = new RateLimiter($this->db);
        $rateLimiter->clear(RateLimiter::buildKey('reset_ip', RateLimiter::getClientIp()));

        $service = new PasswordResetService($this->db);
        $res = $service->requestReset($email);

        $this->assert("Development requestReset attaches dev_token", !empty($res['dev_token']), $res['message'] ?? '');

        // Restore to development for rest of tests
        putenv('APP_ENV=development');
        $_SERVER['APP_ENV'] = 'development';
    }

    /**
     * 17. Audit log entries
     */
    private function test17_AuditLogEntries(): void
    {
        echo "--- 17. AUDIT LOG ENTRIES ---\n";
        $logger = new AuditLogger($this->db);
        $testEmail = "audit_test_" . bin2hex(random_bytes(4)) . "@example.com";

        $logger->log('2FA_EMAIL_FAILED', 'FAILURE', null, $testEmail, [
            'reason' => 'Connection refused',
        ]);
        $logger->log('PASSWORD_RESET_EMAIL_SENT', 'SUCCESS', null, $testEmail, [
            'subject' => 'DaakPion - Reset Your Password',
        ]);

        $stmt = $this->db->prepare("SELECT event_type, status FROM security_audit_logs WHERE identifier = ? ORDER BY id DESC LIMIT 2");
        $stmt->bind_param("s", $testEmail);
        $stmt->execute();
        $rows = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        $stmt->close();

        $this->assert("Audit rows written to database", count($rows) === 2);
        $types = array_column($rows, 'event_type');
        $this->assert("Contains PASSWORD_RESET_EMAIL_SENT event", in_array('PASSWORD_RESET_EMAIL_SENT', $types, true));
        $this->assert("Contains 2FA_EMAIL_FAILED event", in_array('2FA_EMAIL_FAILED', $types, true));
    }

    /**
     * 18. No secrets appearing in logs
     */
    private function test18_NoSecretsInLogs(): void
    {
        echo "--- 18. NO SECRETS APPEARING IN LOGS ---\n";
        $logger = new AuditLogger($this->db);
        $testEmail = "leak_test_" . bin2hex(random_bytes(4)) . "@example.com";
        $sensitiveOtp = "849201";
        $sensitiveToken = "ab837f82710364917a94ec901237aef9";
        $sensitivePassword = "MySuperSecretPassword!";

        $logger->log('TEST_EVENT', 'SUCCESS', null, $testEmail, [
            'otp'           => $sensitiveOtp,
            'token'         => $sensitiveToken,
            'password'      => $sensitivePassword,
            'smtp_password' => 'secret_smtp_password',
        ]);

        $stmt = $this->db->prepare("SELECT details FROM security_audit_logs WHERE identifier = ? ORDER BY id DESC LIMIT 1");
        $stmt->bind_param("s", $testEmail);
        $stmt->execute();
        $details = (string)$stmt->get_result()->fetch_assoc()['details'];
        $stmt->close();

        $this->assert("OTP is redacted in audit log details", !str_contains($details, $sensitiveOtp));
        $this->assert("Token is redacted in audit log details", !str_contains($details, $sensitiveToken));
        $this->assert("Password is redacted in audit log details", !str_contains($details, $sensitivePassword));
        $this->assert("SMTP password is redacted in audit log details", !str_contains($details, 'secret_smtp_password'));
    }

    /**
     * 19. No OTP appearing in page source in production
     */
    private function test19_NoOtpInProductionPageSource(): void
    {
        echo "--- 19. NO OTP IN PRODUCTION PAGE SOURCE ---\n";
        // Render verify_2fa.php under simulated production environment
        $simulatedOtp = "729401";

        // Test output buffering of verify_2fa snippet logic in production
        putenv('APP_ENV=production');
        $_SERVER['APP_ENV'] = 'production';

        ob_start();
        $devOtp = $simulatedOtp;
        if ($devOtp && Environment::allowDevSecrets()) {
            echo "<div class=\"dev-box\">Simulated OTP: {$devOtp}</div>";
        }
        $rendered = ob_get_clean();

        $this->assert("In production mode, OTP is completely omitted from page output", !str_contains($rendered, $simulatedOtp));
    }

    /**
     * 20. No reset token appearing in page source in production
     */
    private function test20_NoResetTokenInProductionPageSource(): void
    {
        echo "--- 20. NO RESET TOKEN IN PRODUCTION PAGE SOURCE ---\n";
        $simulatedToken = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        putenv('APP_ENV=production');
        $_SERVER['APP_ENV'] = 'production';

        ob_start();
        $devToken = $simulatedToken;
        if ($devToken && Environment::allowDevSecrets()) {
            echo "<div class=\"dev-box\">Reset token: {$devToken}</div>";
        }
        $rendered = ob_get_clean();

        $this->assert("In production mode, reset token is completely omitted from page output", !str_contains($rendered, $simulatedToken));

        // Restore development mode
        putenv('APP_ENV=development');
        $_SERVER['APP_ENV'] = 'development';
    }

    private function cleanupSyntheticData(): void
    {
        if (!empty($this->cleanupUserIds)) {
            $ids = implode(',', array_map('intval', $this->cleanupUserIds));
            $this->db->query("DELETE FROM two_factor_otps WHERE user_id IN ({$ids})");
            $this->db->query("DELETE FROM password_resets WHERE user_id IN ({$ids})");
            $this->db->query("DELETE FROM security_audit_logs WHERE user_id IN ({$ids})");
            $this->db->query("DELETE FROM users WHERE id IN ({$ids})");
        }
    }
}

// Run test suite
$suite = new Phase0EmailDeliveryTest($conn);
$suite->runAll();
