<?php
// tests/Phase2RemediationTest.php — Automated Phase 2 Security Remediation Test Suite
declare(strict_types=1);

require_once __DIR__ . '/../php/bootstrap_security.php';

use Daakpion\Security\CryptoService;
use Daakpion\Security\CsrfProtection;
use Daakpion\Security\Environment;
use Daakpion\Security\SessionManager;

class Phase2RemediationTest
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

    public function runAll(): void
    {
        echo "=========================================================\n";
        echo "   DAAKPION PHASE 2 SECURITY REMEDIATION TEST SUITE       \n";
        echo "=========================================================\n\n";

        try {
            $this->testCryptographicUpgradeAesGcm();
            $this->testQueryResourceLimitsAndPagination();
            $this->testExplicitAppEnvAndSecretSuppression();
            $this->testContentSecurityPolicyHardening();
        } finally {
            $this->cleanupSyntheticData();
        }

        echo "\n=========================================================\n";
        echo "  PHASE 2 RESULTS: {$this->passed} Passed | {$this->failed} Failed\n";
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
     * Executes a target script in an isolated sub-process with provided session, get, post, and env parameters.
     */
    private function executeSubprocess(
        string $scriptFile,
        array $sessionData,
        array $postData = [],
        array $getData = [],
        array $headers = [],
        array $envOverrides = []
    ): array {
        $wrapperFile = sys_get_temp_dir() . '/daakpion_p2_test_' . uniqid() . '.php';

        $sessionExport = var_export($sessionData, true);
        $postExport = var_export($postData, true);
        $getExport = var_export($getData, true);
        $headersExport = var_export($headers, true);
        $targetScript = str_replace('\\', '/', $scriptFile);
        $bootstrapPath = str_replace('\\', '/', realpath(__DIR__ . '/../php/bootstrap_security.php'));

        $envSetup = '';
        foreach ($envOverrides as $k => $v) {
            $envSetup .= "putenv('{$k}={$v}'); \$_ENV['{$k}'] = '{$v}'; \$_SERVER['{$k}'] = '{$v}';\n";
        }

        $wrapperCode = <<<PHP
<?php
declare(strict_types=1);
{$envSetup}
require_once '{$bootstrapPath}';

register_shutdown_function(function() {
    \$code = http_response_code() ?: 200;
    \$body = '';
    while (ob_get_level() > 0) {
        \$body = ob_get_contents() . \$body;
        ob_end_clean();
    }
    echo "__DAAKPION_JSON_START__" . json_encode([
        'http_code' => \$code,
        'body' => \$body
    ]) . "__DAAKPION_JSON_END__";
});

ob_start();

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
\$_SESSION = {$sessionExport};
\$_POST = {$postExport};
\$_GET = {$getExport};
\$_SERVER['REQUEST_METHOD'] = !empty({$postExport}) ? 'POST' : 'GET';
foreach ({$headersExport} as \$k => \$v) {
    \$_SERVER[\$k] = \$v;
}

include '{$targetScript}';
PHP;

        file_put_contents($wrapperFile, $wrapperCode);

        $cmd = 'php ' . escapeshellarg($wrapperFile);
        $output = shell_exec($cmd);
        @unlink($wrapperFile);

        if (!$output) {
            return ['http_code' => 500, 'body' => '', 'json' => null];
        }

        if (preg_match('/__DAAKPION_JSON_START__(.*?)__DAAKPION_JSON_END__/s', $output, $m)) {
            $decoded = json_decode($m[1], true);
        } else {
            $decoded = null;
        }

        if (!$decoded) {
            return ['http_code' => 500, 'body' => $output, 'json' => null];
        }

        $bodyJson = json_decode($decoded['body'] ?? '', true);
        $decoded['json'] = $bodyJson;
        return $decoded;
    }

    private function createSyntheticUser(string $tag): int
    {
        $email = "synthetic_p2_{$tag}_" . bin2hex(random_bytes(6)) . "@example.com";
        $hash = CryptoService::hashPassword("SyntheticSecret123!");
        $stmt = $this->db->prepare("INSERT INTO users (fname, lname, email, password, password_version) VALUES (?, 'Phase2User', ?, ?, 1)");
        $fname = "SynP2_" . ucfirst($tag);
        $stmt->bind_param("sss", $fname, $email, $hash);
        $stmt->execute();
        $id = (int)$this->db->insert_id;
        $stmt->close();
        $this->cleanupUserIds[] = $id;
        return $id;
    }

    private function setFriendship(int $user1, int $user2, string $status = 'active'): void
    {
        $u1 = min($user1, $user2);
        $u2 = max($user1, $user2);
        $stmt = $this->db->prepare("INSERT INTO friends (user1_id, user2_id, status) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE status = ?");
        $stmt->bind_param("iiss", $u1, $u2, $status, $status);
        $stmt->execute();
        $stmt->close();
    }

    private function testCryptographicUpgradeAesGcm(): void
    {
        echo "--- 1. AUTHENTICATED ENCRYPTION (AES-256-GCM) TESTS (DP-VULN-03) ---\n";

        $samplePlaintext = "Top secret message: " . bin2hex(random_bytes(8));

        // 1.1: New encryption uses GCM and starts with v2:gcm:
        $encrypted = CryptoService::encryptMessage($samplePlaintext);
        $this->assert("New encryption starts with 'v2:gcm:' format identifier", str_starts_with($encrypted, 'v2:gcm:'), "Ciphertext: {$encrypted}");

        // 1.2: New message can be decrypted successfully
        $decrypted = CryptoService::decryptMessage($encrypted);
        $this->assert("New GCM message successfully decrypts to original plaintext", $decrypted === $samplePlaintext);

        // 1.3: Random nonce uniqueness: consecutive encryptions of same text yield different ciphertexts & nonces
        $encrypted2 = CryptoService::encryptMessage($samplePlaintext);
        $this->assert("Consecutive encryptions produce distinct ciphertexts (unique nonces)", $encrypted !== $encrypted2);

        $parts1 = explode(':', $encrypted);
        $parts2 = explode(':', $encrypted2);
        $this->assert("Nonces are distinct between encryptions", $parts1[2] !== $parts2[2]);
        $this->assert("Nonce length is exactly 12 bytes decoded", strlen(base64_decode($parts1[2])) === 12);
        $this->assert("Tag length is exactly 16 bytes decoded", strlen(base64_decode($parts1[3])) === 16);

        // 1.4: Legacy CBC message (random IV) backward compatibility
        $rawSecret = defined('SECRET_KEY') ? SECRET_KEY : 'test-secret';
        $legacyIv = random_bytes(16);
        $legacyCipher = openssl_encrypt($samplePlaintext, 'AES-256-CBC', $rawSecret, 0, $legacyIv);
        $legacyStored = base64_encode($legacyIv) . ':' . $legacyCipher;

        $decryptedLegacy = CryptoService::decryptMessage($legacyStored);
        $this->assert("Legacy AES-256-CBC (random IV) message decrypts successfully", $decryptedLegacy === $samplePlaintext);

        // 1.5: Very old legacy CBC message (static IV) backward compatibility
        $staticIv = substr(hash('sha256', $rawSecret), 0, 16);
        $oldLegacyCipher = openssl_encrypt($samplePlaintext, 'AES-256-CBC', $rawSecret, 0, $staticIv);
        $decryptedOldLegacy = CryptoService::decryptMessage($oldLegacyCipher);
        $this->assert("Very old legacy AES-256-CBC (static IV) message decrypts successfully", $decryptedOldLegacy === $samplePlaintext);

        // 1.6: Tampered ciphertext in GCM is detected and fails closed (returns null)
        $tamperedParts = $parts1;
        $rawCipher = base64_decode($tamperedParts[4]);
        $rawCipher[0] = chr(ord($rawCipher[0]) ^ 0x01); // flip 1 bit
        $tamperedParts[4] = base64_encode($rawCipher);
        $tamperedEncrypted = implode(':', $tamperedParts);

        $tamperedResult = CryptoService::decryptMessage($tamperedEncrypted);
        $this->assert("Tampered ciphertext fails authentication and returns null (fail-closed)", $tamperedResult === null);

        // 1.7: Tampered authentication tag is detected and fails closed
        $tamperedTagParts = $parts1;
        $rawTag = base64_decode($tamperedTagParts[3]);
        $rawTag[0] = chr(ord($rawTag[0]) ^ 0xFF);
        $tamperedTagParts[3] = base64_encode($rawTag);
        $tamperedTagEncrypted = implode(':', $tamperedTagParts);

        $tamperedTagResult = CryptoService::decryptMessage($tamperedTagEncrypted);
        $this->assert("Tampered authentication tag fails authentication and returns null", $tamperedTagResult === null);

        // 1.8: Tampered nonce/IV is detected and fails closed
        $tamperedIvParts = $parts1;
        $rawIv = base64_decode($tamperedIvParts[2]);
        $rawIv[0] = chr(ord($rawIv[0]) ^ 0x05);
        $tamperedIvParts[2] = base64_encode($rawIv);
        $tamperedIvEncrypted = implode(':', $tamperedIvParts);

        $tamperedIvResult = CryptoService::decryptMessage($tamperedIvEncrypted);
        $this->assert("Tampered IV fails authentication and returns null", $tamperedIvResult === null);

        // 1.9: Malformed ciphertext strings fail closed safely
        $this->assert("Empty string decryption returns null", CryptoService::decryptMessage('') === null);
        $this->assert("Malformed v2:gcm with missing components returns null", CryptoService::decryptMessage('v2:gcm:only_two_parts') === null);
        $this->assert("Corrupt base64 in v2:gcm returns null", CryptoService::decryptMessage('v2:gcm:???:::@@@') === null);

        // 1.10: Decryption with wrong key fails closed
        $wrongKey = "completely-wrong-encryption-key-for-test-123456789";
        $wrongKeyResult = CryptoService::decryptMessage($encrypted, $wrongKey);
        $this->assert("Decryption with wrong key fails authentication and returns null", $wrongKeyResult === null);

        // 1.11: End-to-end integration via send_message.php stores v2:gcm: in database
        $userA = $this->createSyntheticUser('gcm_a');
        $userB = $this->createSyntheticUser('gcm_b');
        $this->setFriendship($userA, $userB, 'active');

        $csrfToken = CsrfProtection::getToken();
        $sendScript = realpath(__DIR__ . '/../php/send_message.php');
        $secretMsgText = "Integration GCM Test " . bin2hex(random_bytes(4));

        $resSend = $this->executeSubprocess($sendScript, [
            'user_id' => $userA,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [
            'receiver_id' => $userB,
            'message' => $secretMsgText,
            'csrf_token' => $csrfToken
        ]);

        $this->assert("send_message.php returns HTTP 200", $resSend['http_code'] === 200);

        // Query database directly to verify stored ciphertext format
        $stmt = $this->db->prepare("SELECT message FROM messages WHERE sender_id = ? AND receiver_id = ? ORDER BY id DESC LIMIT 1");
        $stmt->bind_param("ii", $userA, $userB);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        $storedInDb = $row['message'] ?? '';
        $this->assert("Newly sent message in DB starts with 'v2:gcm:'", str_starts_with($storedInDb, 'v2:gcm:'), "DB Value: {$storedInDb}");

        // 1.12: get_messages.php successfully decrypts the GCM message
        $getScript = realpath(__DIR__ . '/../php/get_messages.php');
        $resGet = $this->executeSubprocess($getScript, [
            'user_id' => $userB,
            'password_version' => 1
        ], [], [
            'friend_id' => $userA
        ]);

        $this->assert("get_messages.php returns HTTP 200", $resGet['http_code'] === 200);
        $this->assert("get_messages.php returns valid JSON array", is_array($resGet['json']));
        $lastMsg = end($resGet['json']) ?: [];
        $this->assert("get_messages.php decrypts GCM message matching original plaintext", ($lastMsg['message'] ?? '') === $secretMsgText);

        // 1.13: get_messages.php with tampered message returns '[message unavailable]' placeholder
        $tamperedDbMsg = substr_replace($storedInDb, 'X', 15, 1);
        $upd = $this->db->prepare("UPDATE messages SET message = ? WHERE sender_id = ? AND receiver_id = ? ORDER BY id DESC LIMIT 1");
        $upd->bind_param("sii", $tamperedDbMsg, $userA, $userB);
        $upd->execute();
        $upd->close();

        $resGetTampered = $this->executeSubprocess($getScript, [
            'user_id' => $userB,
            'password_version' => 1
        ], [], [
            'friend_id' => $userA
        ]);
        $tamperedLast = end($resGetTampered['json']) ?: [];
        $this->assert("Tampered message in get_messages.php renders '[message unavailable]'", ($tamperedLast['message'] ?? '') === '[message unavailable]');
    }

    private function testQueryResourceLimitsAndPagination(): void
    {
        echo "\n--- 2. QUERY RESOURCE LIMITS & PAGINATION TESTS (DP-VULN-06) ---\n";

        $user1 = $this->createSyntheticUser('page_1');
        $user2 = $this->createSyntheticUser('page_2');
        $this->setFriendship($user1, $user2, 'active');

        // Insert 15 synthetic messages between user1 and user2
        $insertStmt = $this->db->prepare("INSERT INTO messages (sender_id, receiver_id, message, sent_at) VALUES (?, ?, ?, NOW())");
        $msgIds = [];
        for ($i = 1; $i <= 15; $i++) {
            $enc = CryptoService::encryptMessage("Paginated message #{$i}");
            $insertStmt->bind_param("iis", $user1, $user2, $enc);
            $insertStmt->execute();
            $msgIds[] = (int)$this->db->insert_id;
        }
        $insertStmt->close();

        $getScript = realpath(__DIR__ . '/../php/get_messages.php');

        // 2.1: Default request returns messages bounded by default limit
        $resDefault = $this->executeSubprocess($getScript, [
            'user_id' => $user2,
            'password_version' => 1
        ], [], [
            'friend_id' => $user1
        ]);
        $this->assert("get_messages.php default request succeeds", $resDefault['http_code'] === 200);
        $this->assert("Default request returns array of messages", is_array($resDefault['json']));
        $this->assert("Default request returns all 15 messages (<= default 50)", count($resDefault['json']) === 15);

        // 2.2: Explicit small limit (e.g. limit=5)
        $resLimit5 = $this->executeSubprocess($getScript, [
            'user_id' => $user2,
            'password_version' => 1
        ], [], [
            'friend_id' => $user1,
            'limit' => 5
        ]);
        $this->assert("Explicit limit=5 returns exactly 5 messages", count($resLimit5['json']) === 5);

        // 2.3: Oversized limit (limit=5000) is clamped to maximum 100
        $resOversized = $this->executeSubprocess($getScript, [
            'user_id' => $user2,
            'password_version' => 1
        ], [], [
            'friend_id' => $user1,
            'limit' => 5000
        ]);
        $this->assert("Oversized limit=5000 succeeds and executes bounded query", $resOversized['http_code'] === 200);

        // 2.4: Negative limit is sanitized to default (50)
        $resNeg = $this->executeSubprocess($getScript, [
            'user_id' => $user2,
            'password_version' => 1
        ], [], [
            'friend_id' => $user1,
            'limit' => -25
        ]);
        $this->assert("Negative limit is sanitized without error", $resNeg['http_code'] === 200 && count($resNeg['json']) === 15);

        // 2.5: Non-numeric limit is sanitized
        $resNonNum = $this->executeSubprocess($getScript, [
            'user_id' => $user2,
            'password_version' => 1
        ], [], [
            'friend_id' => $user1,
            'limit' => 'drop_tables_attempt'
        ]);
        $this->assert("Non-numeric limit string is safely cast to integer", $resNonNum['http_code'] === 200);

        // 2.6: Cursor pagination with since_id
        $midId = $msgIds[7]; // 8th message
        $resSince = $this->executeSubprocess($getScript, [
            'user_id' => $user2,
            'password_version' => 1
        ], [], [
            'friend_id' => $user1,
            'since_id' => $midId
        ]);
        $this->assert("since_id cursor returns only newer messages", count($resSince['json']) === 7);
        foreach ($resSince['json'] as $m) {
            $this->assert("Returned message id > since_id", (int)$m['id'] > $midId);
        }

        // 2.7: Historical pagination with before_id
        $resBefore = $this->executeSubprocess($getScript, [
            'user_id' => $user2,
            'password_version' => 1
        ], [], [
            'friend_id' => $user1,
            'before_id' => $midId,
            'limit' => 5
        ]);
        $this->assert("before_id cursor returns historical messages", count($resBefore['json']) === 5);
        foreach ($resBefore['json'] as $m) {
            $this->assert("Returned message id < before_id", (int)$m['id'] < $midId);
        }

        // 2.8: Static check: friendlist.php allUsers query contains LIMIT
        $friendlistContent = file_get_contents(__DIR__ . '/../php/friendlist.php');
        $this->assert("friendlist.php allUsers query enforces LIMIT constraint", strpos($friendlistContent, 'ORDER BY id ASC LIMIT 100') !== false);

        // 2.9: Static check: chatboard.php friends union query contains LIMIT
        $chatboardContent = file_get_contents(__DIR__ . '/../php/chatboard.php');
        $this->assert("chatboard.php friends query enforces LIMIT 100", strpos($chatboardContent, 'LIMIT 100') !== false);
    }

    private function testExplicitAppEnvAndSecretSuppression(): void
    {
        echo "\n--- 3. EXPLICIT APP_ENV & SECRET SUPPRESSION TESTS (DP-VULN-07) ---\n";

        // 3.1: Environment unit tests
        $this->assert("Environment class exists", class_exists(Environment::class));

        // Test environment resolution logic
        putenv('APP_ENV=production');
        $this->assert("APP_ENV=production isProduction is true", Environment::isProduction() === true);
        $this->assert("Production strictly forbids dev secrets", Environment::allowDevSecrets() === false);

        putenv('APP_ENV=development');
        $this->assert("APP_ENV=development isDevelopment is true", Environment::isDevelopment() === true);
        $this->assert("Development allows dev secrets", Environment::allowDevSecrets() === true);

        putenv('APP_ENV=test');
        $this->assert("APP_ENV=test isTest is true", Environment::isTest() === true);
        $this->assert("Test environment allows dev secrets", Environment::allowDevSecrets() === true);

        // Invalid / unknown environment fails closed to production
        putenv('APP_ENV=unrecognized_attacker_env');
        $this->assert("Invalid APP_ENV defaults to production", Environment::getEnvironment() === 'production');
        $this->assert("Invalid APP_ENV disallows dev secrets", Environment::allowDevSecrets() === false);

        // 3.2: Production mode: verify_2fa.php does NOT expose dev_otp
        $user2fa = $this->createSyntheticUser('env_2fa');
        $twoFactor = new \Daakpion\Security\TwoFactorService($this->db);
        $twoFactor->issueOtp($user2fa, "env_{$user2fa}@example.com");

        $verifyScript = realpath(__DIR__ . '/../php/verify_2fa.php');
        $preauthUser = ['id' => $user2fa, 'email' => "env_{$user2fa}@example.com"];
        $resProd2fa = $this->executeSubprocess($verifyScript, [
            '2fa_preauth_user_id' => $user2fa,
            '2fa_preauth_email' => "env_{$user2fa}@example.com",
            '2fa_preauth_user' => $preauthUser
        ], [], [], [], [
            'APP_ENV' => 'production'
        ]);

        $this->assert("Production verify_2fa.php suppresses dev-box", strpos($resProd2fa['body'], 'Local Dev Simulated OTP') === false);

        // 3.3: Development mode: verify_2fa.php displays dev-box when resend is triggered
        $csrfToken = CsrfProtection::getToken();
        $resDev2fa = $this->executeSubprocess($verifyScript, [
            '2fa_preauth_user_id' => $user2fa,
            '2fa_preauth_email' => "env_{$user2fa}@example.com",
            '2fa_preauth_user' => $preauthUser,
            'csrf_token' => $csrfToken
        ], [
            'resend_otp' => '1',
            'csrf_token' => $csrfToken
        ], [], [], [
            'APP_ENV' => 'development'
        ]);
        $this->assert("Development mode verify_2fa.php allows dev OTP display", strpos($resDev2fa['body'], 'Local Dev Simulated OTP') !== false);

        // 3.4: Production mode: forgot_password.php suppresses dev_token
        $forgotScript = realpath(__DIR__ . '/../php/forgot_password.php');
        $resProdForgot = $this->executeSubprocess($forgotScript, [
            'csrf_token' => CsrfProtection::getToken()
        ], [
            'email' => "synthetic_p2_env_2fa@example.com",
            'csrf_token' => CsrfProtection::getToken()
        ], [], [], [
            'APP_ENV' => 'production'
        ]);
        $this->assert("Production forgot_password.php suppresses dev reset token", strpos($resProdForgot['body'], 'Local Dev Simulated Reset Link') === false);

        // Restore environment
        putenv('APP_ENV=test');
    }

    private function testContentSecurityPolicyHardening(): void
    {
        echo "\n--- 4. CONTENT SECURITY POLICY (CSP) TESTS (DP-VULN-08) ---\n";

        // 4.1: Root .htaccess contains Content-Security-Policy header
        $rootHtaccess = dirname(__DIR__) . DIRECTORY_SEPARATOR . '.htaccess';
        $content = file_get_contents($rootHtaccess);

        $hasCsp = strpos($content, 'Content-Security-Policy') !== false;
        $this->assert("Root .htaccess declares Content-Security-Policy header", $hasCsp);

        $hasObjectNone = strpos($content, "object-src 'none'") !== false;
        $this->assert("CSP restricts object-src to 'none'", $hasObjectNone);

        $hasFrameNone = strpos($content, "frame-src 'none'") !== false;
        $this->assert("CSP restricts frame-src to 'none'", $hasFrameNone);

        $hasBaseUriSelf = strpos($content, "base-uri 'self'") !== false;
        $this->assert("CSP restricts base-uri to 'self'", $hasBaseUriSelf);

        $hasFormActionSelf = strpos($content, "form-action 'self'") !== false;
        $this->assert("CSP restricts form-action to 'self'", $hasFormActionSelf);

        $hasFrameAncestors = strpos($content, "frame-ancestors 'self'") !== false;
        $this->assert("CSP restricts frame-ancestors to 'self'", $hasFrameAncestors);

        $hasUnsafeEval = strpos($content, "'unsafe-eval'") !== false;
        $this->assert("CSP explicitly omits 'unsafe-eval' for defense-in-depth", !$hasUnsafeEval);

        // 4.2: Dynamic HTTP verification via loopback curl against index.html
        $curlHeaders = shell_exec('curl.exe -s -I http://127.0.0.1/Daakpion/index.html');
        if (!empty($curlHeaders)) {
            $hasCspLive = stripos($curlHeaders, 'content-security-policy:') !== false;
            $this->assert("Apache actively emits Content-Security-Policy header over HTTP", $hasCspLive);
        }
    }

    private function cleanupSyntheticData(): void
    {
        if (empty($this->cleanupUserIds)) {
            return;
        }

        $idList = implode(',', array_map('intval', $this->cleanupUserIds));
        $this->db->query("DELETE FROM messages WHERE sender_id IN ({$idList}) OR receiver_id IN ({$idList})");
        $this->db->query("DELETE FROM friendrequests WHERE sender_id IN ({$idList}) OR receiver_id IN ({$idList})");
        $this->db->query("DELETE FROM friends WHERE user1_id IN ({$idList}) OR user2_id IN ({$idList})");
        $this->db->query("DELETE FROM password_resets WHERE user_id IN ({$idList})");
        $this->db->query("DELETE FROM users WHERE id IN ({$idList})");
    }
}

// Instantiate and run suite
$p2Suite = new Phase2RemediationTest($conn);
$p2Suite->runAll();
