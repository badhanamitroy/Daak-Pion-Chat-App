<?php
// tests/Phase4RemediationTest.php — Automated Phase 4 Security Remediation Test Suite
declare(strict_types=1);

require_once __DIR__ . '/../php/bootstrap_security.php';

use Daakpion\Security\CryptoService;
use Daakpion\Security\CsrfProtection;
use Daakpion\Security\SessionManager;

class Phase4RemediationTest
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
        echo "   DAAKPION PHASE 4 SECURITY REMEDIATION TEST SUITE       \n";
        echo "=========================================================\n\n";

        try {
            $this->testCryptographicKeyHardening_DP_P3_002();
            $this->testBlockedRelationshipEnforcement_DP_P3_001();
            $this->testFriendRequestDeclineAndResend_DP_P3_003();
            $this->testLogoutCsrf_DP_P3_004();
            $this->testLegacyConfigExposureAndHeaders_DP_P3_005();
            $this->testQueryBounds_DP_P3_006();
            $this->testRegistrationAntiEnumeration_DP_P3_008();
            $this->testCspHardening_DP_P3_007();
            $this->testOnlinePresenceAndHeartbeat_DP_P4_009();
        } finally {
            $this->cleanupSyntheticData();
        }

        echo "\n=========================================================\n";
        echo "  PHASE 4 RESULTS: {$this->passed} Passed | {$this->failed} Failed\n";
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
        $wrapperFile = sys_get_temp_dir() . '/daakpion_p4_test_' . uniqid() . '.php';

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

        $body = $decoded['body'] ?? $output;
        $httpCode = (int)($decoded['http_code'] ?? 200);

        return [
            'http_code' => $httpCode,
            'body'      => $body,
            'json'      => json_decode($body, true)
        ];
    }

    private function createSyntheticUser(string $prefix, string $status = 'Offline'): int
    {
        $unique = bin2hex(random_bytes(6));
        $fname = "Test_{$prefix}";
        $lname = $unique;
        $email = "test_{$prefix}_{$unique}@daakpion.local";
        $hash = '$argon2id$v=19$m=65536,t=4,p=1$ZHVtbXlzYWx0MTIzNDU2Nw$N3g6VlX50p5X1w+JgU+aG63iJ94o1E4Q69g3W2a3O7M';

        $stmt = $this->db->prepare("INSERT INTO users (fname, lname, email, password, status, password_version) VALUES (?, ?, ?, ?, ?, 1)");
        $stmt->bind_param("sssss", $fname, $lname, $email, $hash, $status);
        $stmt->execute();
        $id = (int)$this->db->insert_id;
        $stmt->close();

        $this->cleanupUserIds[] = $id;
        return $id;
    }

    private function setRelationship(int $u1, int $u2, string $status): void
    {
        $this->db->query("DELETE FROM friends WHERE (user1_id = {$u1} AND user2_id = {$u2}) OR (user1_id = {$u2} AND user2_id = {$u1})");
        $stmt = $this->db->prepare("INSERT INTO friends (user1_id, user2_id, friends_since, status) VALUES (?, ?, NOW(), ?)");
        $stmt->bind_param("iis", $u1, $u2, $status);
        $stmt->execute();
        $stmt->close();
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 1. DP-P4-001 (DP-P3-002) — Cryptographic Key Hardening
    // ─────────────────────────────────────────────────────────────────────────────
    private function testCryptographicKeyHardening_DP_P3_002(): void
    {
        echo "--- 1. CRYPTOGRAPHIC KEY HARDENING TESTS (DP-P3-002 -> DP-P4-001) ---\n";

        // 1.1: Dedicated message key resolves to exactly 32 bytes binary
        $key = CryptoService::getMessageKey();
        $this->assert("Dedicated MESSAGE_ENCRYPTION_KEY resolves to exactly 32 bytes binary", strlen($key) === 32);

        // 1.2: Prohibited placeholder key is rejected (fails closed)
        $placeholderRejected = false;
        try {
            CryptoService::getMessageKey('your-strong-secret-key-change-me-in-production');
        } catch (\RuntimeException $e) {
            $placeholderRejected = true;
        }
        $this->assert("Generic app_config SECRET_KEY placeholder is strictly rejected", $placeholderRejected);

        // 1.3: Example template placeholder key is rejected
        $templateRejected = false;
        try {
            CryptoService::getMessageKey('REPLACE_WITH_CRYPTOGRAPHICALLY_RANDOM_64_CHAR_HEX_KEY');
        } catch (\RuntimeException $e) {
            $templateRejected = true;
        }
        $this->assert("Example template placeholder key is strictly rejected", $templateRejected);

        // 1.4: Key shorter than 32 characters is rejected
        $shortRejected = false;
        try {
            CryptoService::getMessageKey('short_key_12345');
        } catch (\RuntimeException $e) {
            $shortRejected = true;
        }
        $this->assert("Malformed key (< 32 bytes) fails closed", $shortRejected);

        // 1.5: Valid 64-char hex key works cleanly
        $validHex = bin2hex(random_bytes(32));
        $derived = CryptoService::getMessageKey($validHex);
        $this->assert("Valid 64-character hex key derives 32-byte binary key", strlen($derived) === 32 && $derived === hex2bin($validHex));

        // 1.6: AES-256-GCM encryption and decryption works with dedicated key
        $plaintext = "Phase 4 Confidential Message: " . bin2hex(random_bytes(8));
        $encrypted = CryptoService::encryptMessage($plaintext);
        $this->assert("GCM ciphertext format identifier starts with 'v2:gcm:'", str_starts_with($encrypted, 'v2:gcm:'));
        $decrypted = CryptoService::decryptMessage($encrypted);
        $this->assert("Message successfully decrypts to original plaintext using dedicated key", $decrypted === $plaintext);

        // 1.7: Tampered ciphertext fails authentication (returns null)
        $parts = explode(':', $encrypted);
        $rawCipher = base64_decode($parts[4]);
        $rawCipher[0] = chr(ord($rawCipher[0]) ^ 0x01);
        $parts[4] = base64_encode($rawCipher);
        $tamperedCipher = implode(':', $parts);
        $this->assert("Tampered GCM ciphertext fails authentication (returns null)", CryptoService::decryptMessage($tamperedCipher) === null);

        // 1.8: Legacy CBC ciphertext backward compatibility
        $rawSecret = defined('SECRET_KEY') ? SECRET_KEY : 'test-secret';
        $legacyIv = random_bytes(16);
        $legacyCipher = openssl_encrypt($plaintext, 'AES-256-CBC', $rawSecret, 0, $legacyIv);
        $legacyStored = base64_encode($legacyIv) . ':' . $legacyCipher;
        $this->assert("Legacy AES-256-CBC ciphertext remains backward compatible", CryptoService::decryptMessage($legacyStored) === $plaintext);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 2. DP-P4-002 (DP-P3-001) — Blocked Relationship Enforcement
    // ─────────────────────────────────────────────────────────────────────────────
    private function testBlockedRelationshipEnforcement_DP_P3_001(): void
    {
        echo "\n--- 2. BLOCKED RELATIONSHIP ENFORCEMENT TESTS (DP-P3-001 -> DP-P4-002) ---\n";

        $blocker = $this->createSyntheticUser('blocker');
        $blocked = $this->createSyntheticUser('blocked');

        // Establish blocked status: blocker blocked the blocked user
        $this->setRelationship($blocker, $blocked, 'blocked');

        $csrfToken = CsrfProtection::getToken();
        $sendRequestScript = realpath(__DIR__ . '/../php/send_request.php');

        // 2.1: Blocked user attempts to send friend request to blocker -> HTTP 403 Forbidden
        $res1 = $this->executeSubprocess($sendRequestScript, [
            'user_id' => $blocked,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [
            'receiver_id' => $blocker,
            'csrf_token' => $csrfToken
        ]);
        $this->assert("Blocked user -> Blocker friend request rejected with HTTP 403", $res1['http_code'] === 403);
        $this->assert("Blocked user response does not reveal detailed block state", str_contains($res1['body'], "Action not allowed."));

        // 2.2: Blocker attempts to send friend request to blocked user -> HTTP 403 Forbidden
        $res2 = $this->executeSubprocess($sendRequestScript, [
            'user_id' => $blocker,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [
            'receiver_id' => $blocked,
            'csrf_token' => $csrfToken
        ]);
        $this->assert("Blocker -> Blocked user friend request rejected with HTTP 403", $res2['http_code'] === 403);

        // 2.3: Verify zero friend requests created in database
        $stmt = $this->db->prepare("SELECT COUNT(*) AS cnt FROM friendrequests WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)");
        $stmt->bind_param("iiii", $blocker, $blocked, $blocked, $blocker);
        $stmt->execute();
        $cnt = (int)$stmt->get_result()->fetch_assoc()['cnt'];
        $stmt->close();
        $this->assert("Zero friend requests created between blocked parties", $cnt === 0);

        // 2.4: Verify block in friends table was NOT overwritten
        $stmt = $this->db->prepare("SELECT status FROM friends WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)");
        $stmt->bind_param("iiii", $blocker, $blocked, $blocked, $blocker);
        $stmt->execute();
        $status = $stmt->get_result()->fetch_assoc()['status'] ?? '';
        $stmt->close();
        $this->assert("Blocked status in friends table remains intact", $status === 'blocked');

        // 2.5: Normal non-blocked request succeeds
        $userC = $this->createSyntheticUser('normal_user');
        $res3 = $this->executeSubprocess($sendRequestScript, [
            'user_id' => $blocker,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [
            'receiver_id' => $userC,
            'csrf_token' => $csrfToken
        ]);
        $this->assert("Normal non-blocked friend request succeeds with HTTP 200", $res3['http_code'] === 200 && str_contains($res3['body'], "Friend request sent!"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 3. DP-P4-003 (DP-P3-003) — Friend Request Decline & Re-Send Logic
    // ─────────────────────────────────────────────────────────────────────────────
    private function testFriendRequestDeclineAndResend_DP_P3_003(): void
    {
        echo "\n--- 3. FRIEND REQUEST DECLINE & RE-SEND TESTS (DP-P3-003 -> DP-P4-003) ---\n";

        $sender = $this->createSyntheticUser('req_sender');
        $receiver = $this->createSyntheticUser('req_receiver');

        $csrfToken = CsrfProtection::getToken();
        $sendScript = realpath(__DIR__ . '/../php/send_request.php');
        $respondScript = realpath(__DIR__ . '/../php/respond_request.php');

        // 3.1: Sender sends friend request
        $sendRes = $this->executeSubprocess($sendScript, [
            'user_id' => $sender,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [
            'receiver_id' => $receiver,
            'csrf_token' => $csrfToken
        ]);
        $this->assert("Initial friend request sent successfully", $sendRes['http_code'] === 200);

        // Fetch request ID
        $stmt = $this->db->prepare("SELECT id, status FROM friendrequests WHERE sender_id = ? AND receiver_id = ?");
        $stmt->bind_param("ii", $sender, $receiver);
        $stmt->execute();
        $reqRow = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        $reqId = (int)($reqRow['id'] ?? 0);
        $this->assert("Friend request created with pending status", ($reqRow['status'] ?? '') === 'pending');

        // 3.2: Receiver declines request
        $declineRes = $this->executeSubprocess($respondScript, [
            'user_id' => $receiver,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [
            'request_id' => $reqId,
            'action' => 'decline',
            'csrf_token' => $csrfToken
        ]);
        $this->assert("Decline request succeeds with HTTP 200", $declineRes['http_code'] === 200 && str_contains($declineRes['body'], "Friend request declined!"));

        // 3.3: Verify DB status is 'rejected' (NOT invalid 'declined' or empty string)
        $stmt = $this->db->prepare("SELECT status FROM friendrequests WHERE id = ?");
        $stmt->bind_param("i", $reqId);
        $stmt->execute();
        $updatedStatus = $stmt->get_result()->fetch_assoc()['status'] ?? '';
        $stmt->close();
        $this->assert("Friend request status in DB updated to canonical enum 'rejected'", $updatedStatus === 'rejected');

        // 3.4: Sender re-sends request after decline -> succeeds without duplicate key error
        $reSendRes = $this->executeSubprocess($sendScript, [
            'user_id' => $sender,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [
            'receiver_id' => $receiver,
            'csrf_token' => $csrfToken
        ]);
        $this->assert("Re-sending friend request after rejection succeeds with HTTP 200", $reSendRes['http_code'] === 200 && str_contains($reSendRes['body'], "Friend request sent!"));

        // Verify request row status is reset to 'pending'
        $stmt = $this->db->prepare("SELECT status, responded_at FROM friendrequests WHERE id = ?");
        $stmt->bind_param("i", $reqId);
        $stmt->execute();
        $resetRow = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        $this->assert("Re-sent request row status is reset to 'pending'", ($resetRow['status'] ?? '') === 'pending');
        $this->assert("Re-sent request responded_at timestamp is cleared (NULL)", $resetRow['responded_at'] === null);

        // 3.5: Duplicate pending request while pending is rejected
        $dupRes = $this->executeSubprocess($sendScript, [
            'user_id' => $sender,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [
            'receiver_id' => $receiver,
            'csrf_token' => $csrfToken
        ]);
        $this->assert("Duplicate pending request is rejected safely", str_contains($dupRes['body'], "You already sent a request to this person"));

        // 3.6: Receiver accepts request
        $acceptRes = $this->executeSubprocess($respondScript, [
            'user_id' => $receiver,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [
            'request_id' => $reqId,
            'action' => 'accept',
            'csrf_token' => $csrfToken
        ]);
        $this->assert("Accepting friend request succeeds", str_contains($acceptRes['body'], "Friend request accepted!"));

        // 3.7: Attempting to send request to active friend is rejected
        $alreadyFriendRes = $this->executeSubprocess($sendScript, [
            'user_id' => $sender,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [
            'receiver_id' => $receiver,
            'csrf_token' => $csrfToken
        ]);
        $this->assert("Sending request to active friend returns already friends", str_contains($alreadyFriendRes['body'], "You are already friends"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 4. DP-P4-004 (DP-P3-004) — Logout CSRF Protection
    // ─────────────────────────────────────────────────────────────────────────────
    private function testLogoutCsrf_DP_P3_004(): void
    {
        echo "\n--- 4. LOGOUT CSRF PROTECTION TESTS (DP-P3-004 -> DP-P4-004) ---\n";

        $user = $this->createSyntheticUser('logout_user', 'Active now');
        $csrfToken = CsrfProtection::getToken();
        $logoutScript = realpath(__DIR__ . '/../php/logout.php');

        // 4.1: GET request to logout.php is rejected with HTTP 405 Method Not Allowed
        $getRes = $this->executeSubprocess($logoutScript, [
            'user_id' => $user,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], []); // Empty post => GET request
        $this->assert("GET logout is rejected with HTTP 405 Method Not Allowed", $getRes['http_code'] === 405);
        $this->assert("GET logout error specifies POST required", str_contains($getRes['body'], "Method Not Allowed"));

        // Verify session was NOT destroyed
        $stmt = $this->db->prepare("SELECT status FROM users WHERE id = ?");
        $stmt->bind_param("i", $user);
        $stmt->execute();
        $statusAfterGet = $stmt->get_result()->fetch_assoc()['status'] ?? '';
        $stmt->close();
        $this->assert("User status remains active after rejected GET logout attempt", $statusAfterGet === 'Active now');

        // 4.2: POST request without CSRF token is rejected with HTTP 403 Forbidden
        $postNoCsrf = $this->executeSubprocess($logoutScript, [
            'user_id' => $user,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [
            'action' => 'logout'
        ]);
        $this->assert("POST logout without CSRF token is rejected with HTTP 403 Forbidden", $postNoCsrf['http_code'] === 403);

        // 4.3: POST request with invalid CSRF token is rejected with HTTP 403 Forbidden
        $postInvalidCsrf = $this->executeSubprocess($logoutScript, [
            'user_id' => $user,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [
            'csrf_token' => 'invalid_csrf_token_12345'
        ]);
        $this->assert("POST logout with invalid CSRF token is rejected with HTTP 403 Forbidden", $postInvalidCsrf['http_code'] === 403);

        // 4.4: POST request with valid CSRF token succeeds
        $postValid = $this->executeSubprocess($logoutScript, [
            'user_id' => $user,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [
            'csrf_token' => $csrfToken
        ]);
        $this->assert("POST logout with valid CSRF token succeeds with HTTP 302/200", in_array($postValid['http_code'], [200, 302], true));

        // Verify user status is set to Offline in DB
        $stmt = $this->db->prepare("SELECT status FROM users WHERE id = ?");
        $stmt->bind_param("i", $user);
        $stmt->execute();
        $statusAfterLogout = $stmt->get_result()->fetch_assoc()['status'] ?? '';
        $stmt->close();
        $this->assert("User status transitioned to 'Offline' on valid POST logout", $statusAfterLogout === 'Offline');
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 5. DP-P4-005 (DP-P3-005) — Legacy Config Exposure & Verbose Headers
    // ─────────────────────────────────────────────────────────────────────────────
    private function testLegacyConfigExposureAndHeaders_DP_P3_005(): void
    {
        echo "\n--- 5. LEGACY CONFIG EXPOSURE & VERBOSE HEADERS TESTS (DP-P3-005 -> DP-P4-005) ---\n";

        // 5.1: HTTP access to /php/config.php returns HTTP 403 Forbidden
        $curlConfig = shell_exec('curl.exe -i -s http://127.0.0.1/Daakpion/php/config.php');
        $this->assert("Direct HTTP access to /php/config.php is denied with HTTP 403", str_contains($curlConfig, '403 Forbidden'));

        // 5.2: HTTP access to /php/db_connect.php returns HTTP 403 Forbidden
        $curlDb = shell_exec('curl.exe -i -s http://127.0.0.1/Daakpion/php/db_connect.php');
        $this->assert("Direct HTTP access to /php/db_connect.php is denied with HTTP 403", str_contains($curlDb, '403 Forbidden'));

        // 5.3: HTTP access to /php/app_config.php returns HTTP 403 Forbidden
        $curlAppConfig = shell_exec('curl.exe -i -s http://127.0.0.1/Daakpion/php/app_config.php');
        $this->assert("Direct HTTP access to /php/app_config.php is denied with HTTP 403", str_contains($curlAppConfig, '403 Forbidden'));

        // 5.4: X-Powered-By header is suppressed
        $curlHeaders = shell_exec('curl.exe -i -s http://127.0.0.1/Daakpion/index.html');
        $hasPoweredBy = stripos($curlHeaders, 'x-powered-by:') !== false;
        $this->assert("X-Powered-By header is actively suppressed from HTTP responses", !$hasPoweredBy);

        // 5.5: .htaccess configuration contains denial for config and database scripts
        $htaccessContent = file_get_contents(dirname(__DIR__) . DIRECTORY_SEPARATOR . '.htaccess');
        $hasShielding = (bool)preg_match('/FilesMatch\s+"[^"]*config[^"]*db_connect/i', $htaccessContent);
        $this->assert(".htaccess contains explicit FilesMatch denial for internal scripts", $hasShielding);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 6. DP-P4-006 (DP-P3-006) — Query Bounds
    // ─────────────────────────────────────────────────────────────────────────────
    private function testQueryBounds_DP_P3_006(): void
    {
        echo "\n--- 6. QUERY BOUNDS TESTS (DP-P3-006 -> DP-P4-006) ---\n";

        $friendlistContent = file_get_contents(realpath(__DIR__ . '/../php/friendlist.php'));

        // 6.1: friendlist.php friends query enforces LIMIT 100
        $friendsHasLimit = (bool)preg_match('/WHERE\s+f\.user2_id\s*=\s*\?\s*AND\s*f\.status\s*=\s*\'active\'\)\s*LIMIT\s+100/i', $friendlistContent);
        $this->assert("friendlist.php active friends query enforces LIMIT 100", $friendsHasLimit);

        // 6.2: friendlist.php pending query enforces LIMIT 100
        $pendingHasLimit = (bool)preg_match('/ORDER\s+BY\s+fr\.sent_at\s+DESC\s+LIMIT\s+100/i', $friendlistContent);
        $this->assert("friendlist.php pending requests query enforces LIMIT 100", $pendingHasLimit);

        // 6.3: chatboard.php friends query enforces LIMIT 100
        $chatboardContent = file_get_contents(realpath(__DIR__ . '/../php/chatboard.php'));
        $chatboardHasLimit = (bool)preg_match('/WHERE\s+f\.user2_id=\?\s*AND\s*f\.status=\'active\'\)\s*LIMIT\s+100/i', $chatboardContent);
        $this->assert("chatboard.php friends query enforces LIMIT 100", $chatboardHasLimit);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 7. DP-P4-007 (DP-P3-008) — Registration Anti-Enumeration Defense
    // ─────────────────────────────────────────────────────────────────────────────
    private function testRegistrationAntiEnumeration_DP_P3_008(): void
    {
        echo "\n--- 7. REGISTRATION ACCOUNT ENUMERATION TESTS (DP-P3-008 -> DP-P4-007) ---\n";

        $unique = bin2hex(random_bytes(6));
        $existingEmail = "enum_target_{$unique}@daakpion.local";

        // Create existing account
        $stmt = $this->db->prepare("INSERT INTO users (fname, lname, email, password, status, password_version) VALUES ('Target', 'User', ?, 'hash', 'Offline', 1)");
        $stmt->bind_param("s", $existingEmail);
        $stmt->execute();
        $this->cleanupUserIds[] = (int)$this->db->insert_id;
        $stmt->close();

        $regScript = realpath(__DIR__ . '/../php/registration.php');

        // Clear existing rate limits for test IP space
        $this->db->query("DELETE FROM security_rate_limits WHERE rate_key LIKE 'rl:register_ip:%'");

        // 7.1: Registering with existing email returns generic error without revealing existence
        $ip1 = '198.51.100.' . mt_rand(1, 200);
        $resExisting = $this->executeSubprocess($regScript, [], [
            'fname' => 'Attacker',
            'lname' => 'Probe',
            'email' => $existingEmail,
            'password' => 'StrongPassword123#Valid'
        ], [], ['REMOTE_ADDR' => $ip1]);

        $this->assert("Registration with existing email does not disclose account existence", !str_contains($resExisting['body'], "already registered"));
        $this->assert("Registration returns safe generic message for existing account", str_contains($resExisting['body'], "Unable to complete registration with the provided details"));

        // 7.2: Registering with invalid email format returns appropriate format validation error
        $ip2 = '198.51.100.' . mt_rand(1, 200);
        $resInvalidEmail = $this->executeSubprocess($regScript, [], [
            'fname' => 'Attacker',
            'lname' => 'Probe',
            'email' => 'invalid-not-an-email',
            'password' => 'StrongPassword123#Valid'
        ], [], ['REMOTE_ADDR' => $ip2]);
        $this->assert("Invalid email format returns field validation error", str_contains($resInvalidEmail['body'], "not a valid email address"));

        // 7.3: Registering with weak password returns password policy error
        $ip3 = '198.51.100.' . mt_rand(1, 200);
        $resWeakPass = $this->executeSubprocess($regScript, [], [
            'fname' => 'Attacker',
            'lname' => 'Probe',
            'email' => "brand_new_{$unique}@daakpion.local",
            'password' => 'short'
        ], [], ['REMOTE_ADDR' => $ip3]);
        $this->assert("Weak password returns password policy requirement error", str_contains($resWeakPass['body'], "at least 12 characters"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 8. DP-P4-008 (DP-P3-007) — Content Security Policy Hardening
    // ─────────────────────────────────────────────────────────────────────────────
    private function testCspHardening_DP_P3_007(): void
    {
        echo "\n--- 8. CONTENT SECURITY POLICY HARDENING TESTS (DP-P3-007 -> DP-P4-008) ---\n";

        $rootHtaccess = file_get_contents(dirname(__DIR__) . DIRECTORY_SEPARATOR . '.htaccess');
        $bootstrapContent = file_get_contents(realpath(__DIR__ . '/../php/bootstrap_security.php'));

        // 8.1: .htaccess script-src does not allow arbitrary CDN scripts (cdnjs removed from script-src)
        $hasCdnjsInScriptSrcHtaccess = (bool)preg_match("/script-src[^;]*cdnjs\.cloudflare\.com/i", $rootHtaccess);
        $this->assert(".htaccess script-src omits open cdnjs CDN script execution gadget source", !$hasCdnjsInScriptSrcHtaccess);

        // 8.2: bootstrap_security.php script-src does not allow cdnjs
        $hasCdnjsInScriptSrcBootstrap = (bool)preg_match("/script-src[^;]*cdnjs\.cloudflare\.com/i", $bootstrapContent);
        $this->assert("bootstrap_security.php script-src omits open cdnjs CDN script source", !$hasCdnjsInScriptSrcBootstrap);

        // 8.3: Live Apache emission contains hardened script-src
        $liveHeaders = shell_exec('curl.exe -s -I http://127.0.0.1/Daakpion/index.html');
        $hasHardenedCsp = str_contains($liveHeaders, "script-src 'self' 'unsafe-inline'");
        $this->assert("Live HTTP response serves hardened script-src directive", $hasHardenedCsp);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 9. DP-P4-009 — Online Presence & Heartbeat Architecture
    // ─────────────────────────────────────────────────────────────────────────────
    private function testOnlinePresenceAndHeartbeat_DP_P4_009(): void
    {
        echo "\n--- 9. ONLINE PRESENCE & HEARTBEAT TESTS (DP-P4-009) ---\n";

        $userA = $this->createSyntheticUser('pres_a', 'Offline');
        $userB = $this->createSyntheticUser('pres_b', 'Offline');
        $userC = $this->createSyntheticUser('pres_c', 'Offline'); // Not friends with A

        // Establish confirmed friendship between A and B
        $this->setRelationship($userA, $userB, 'active');

        $csrfToken = CsrfProtection::getToken();
        $heartbeatScript = realpath(__DIR__ . '/../php/heartbeat.php');
        $presenceScript = realpath(__DIR__ . '/../php/get_presence.php');

        // 9.1: Unauthenticated heartbeat request rejected with HTTP 401
        $unauthHeartbeat = $this->executeSubprocess($heartbeatScript, [], [
            'csrf_token' => $csrfToken
        ]);
        $this->assert("Unauthenticated heartbeat rejected with HTTP 401", $unauthHeartbeat['http_code'] === 401);

        // 9.2: GET heartbeat rejected with HTTP 405 Method Not Allowed
        $getHeartbeat = $this->executeSubprocess($heartbeatScript, [
            'user_id' => $userA,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], []);
        $this->assert("GET heartbeat rejected with HTTP 405 Method Not Allowed", $getHeartbeat['http_code'] === 405);

        // 9.3: Heartbeat without valid CSRF rejected with HTTP 403
        $badCsrfHeartbeat = $this->executeSubprocess($heartbeatScript, [
            'user_id' => $userA,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [
            'csrf_token' => 'invalid_csrf'
        ]);
        $this->assert("Heartbeat with invalid CSRF token rejected with HTTP 403", $badCsrfHeartbeat['http_code'] === 403);

        // 9.4: Authenticated heartbeat succeeds and updates user's own last_activity_at
        $validHeartbeat = $this->executeSubprocess($heartbeatScript, [
            'user_id' => $userA,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [
            'csrf_token' => $csrfToken
        ]);
        $this->assert("Valid authenticated heartbeat succeeds with HTTP 200", $validHeartbeat['http_code'] === 200);

        // Verify last_activity_at updated in DB for User A
        $stmt = $this->db->prepare("SELECT status, last_activity_at, TIMESTAMPDIFF(SECOND, last_activity_at, NOW()) AS age FROM users WHERE id = ?");
        $stmt->bind_param("i", $userA);
        $stmt->execute();
        $userARow = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        $this->assert("Heartbeat transitions user status to 'Active now'", $userARow['status'] === 'Active now');
        $this->assert("Heartbeat sets recent last_activity_at timestamp", (int)$userARow['age'] <= 5);

        // 9.5: Unauthenticated presence query rejected with HTTP 401
        $unauthPres = $this->executeSubprocess($presenceScript, [], [], ['friend_id' => (string)$userB]);
        $this->assert("Unauthenticated presence query rejected with HTTP 401", $unauthPres['http_code'] === 401);

        // 9.6: Non-friend presence inquiry rejected with HTTP 403
        $nonFriendPres = $this->executeSubprocess($presenceScript, [
            'user_id' => $userA,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [], ['friend_id' => (string)$userC]);
        $this->assert("Presence inquiry for non-friend user rejected with HTTP 403", $nonFriendPres['http_code'] === 403);

        // 9.7: Blocked relationship presence inquiry rejected with HTTP 403
        $this->setRelationship($userA, $userB, 'blocked');
        $blockedPres = $this->executeSubprocess($presenceScript, [
            'user_id' => $userA,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [], ['friend_id' => (string)$userB]);
        $this->assert("Presence inquiry for blocked user rejected with HTTP 403", $blockedPres['http_code'] === 403);

        // Restore active friendship between A and B
        $this->setRelationship($userA, $userB, 'active');

        // 9.8: Friend B queries presence of active Friend A (recent activity <= 120s) -> Online
        $activePres = $this->executeSubprocess($presenceScript, [
            'user_id' => $userB,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [], ['friend_id' => (string)$userA]);
        $this->assert("Presence API returns HTTP 200 for confirmed friend", $activePres['http_code'] === 200);
        $this->assert("Recently active user correctly reported as is_online = true", ($activePres['json']['is_online'] ?? false) === true);
        $this->assert("Recently active user status_text is 'Active now'", ($activePres['json']['status_text'] ?? '') === 'Active now');

        // 9.9: Stale activity (> 120s) -> User A becomes Offline automatically
        $this->db->query("UPDATE users SET last_activity_at = NOW() - INTERVAL 150 SECOND WHERE id = {$userA}");
        $expiredPres = $this->executeSubprocess($presenceScript, [
            'user_id' => $userB,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [], ['friend_id' => (string)$userA]);
        $this->assert("Stale activity (> 120s) automatically evaluates to is_online = false (Offline)", ($expiredPres['json']['is_online'] ?? true) === false);
        $this->assert("Stale activity status_text reports 'Offline'", ($expiredPres['json']['status_text'] ?? '') === 'Offline');

        // 9.10: User logout sets status = 'Offline' and clears last_activity_at -> Offline
        $this->db->query("UPDATE users SET status = 'Offline', last_activity_at = NULL WHERE id = {$userA}");
        $loggedOutPres = $this->executeSubprocess($presenceScript, [
            'user_id' => $userB,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [], ['friend_id' => (string)$userA]);
        $this->assert("Logged out user evaluates to is_online = false (Offline)", ($loggedOutPres['json']['is_online'] ?? true) === false);

        // 9.11: Batch active friends presence inquiry
        $batchPres = $this->executeSubprocess($presenceScript, [
            'user_id' => $userB,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], []);
        $this->assert("Batch presence inquiry returns HTTP 200", $batchPres['http_code'] === 200);
        $this->assert("Batch presence includes active friend A", isset($batchPres['json']['presence'][$userA]));
        $this->assert("Batch presence excludes non-friend C", !isset($batchPres['json']['presence'][$userC]));
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
$p4Suite = new Phase4RemediationTest($conn);
$p4Suite->runAll();
