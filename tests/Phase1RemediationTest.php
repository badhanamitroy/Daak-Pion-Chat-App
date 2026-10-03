<?php
// tests/Phase1RemediationTest.php — Automated Phase 1 Security Remediation Test Suite
declare(strict_types=1);

require_once __DIR__ . '/../php/bootstrap_security.php';

use Daakpion\Security\CryptoService;
use Daakpion\Security\CsrfProtection;
use Daakpion\Security\SessionManager;

class Phase1RemediationTest
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
        echo "   DAAKPION PHASE 1 SECURITY REMEDIATION TEST SUITE       \n";
        echo "=========================================================\n\n";

        try {
            $this->testActiveFriendshipAuthorization();
            $this->testCsrfProtectionEndpoints();
            $this->testSafeErrorHandlingAndSqlSuppression();
            $this->testCliAndHttpAccessRestrictions();
        } finally {
            $this->cleanupSyntheticData();
        }

        echo "\n=========================================================\n";
        echo "  PHASE 1 RESULTS: {$this->passed} Passed | {$this->failed} Failed\n";
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
     * Executes a target script in an isolated sub-process with provided session and post parameters.
     */
    private function executeSubprocess(string $scriptFile, array $sessionData, array $postData, array $headers = []): array
    {
        $wrapperFile = sys_get_temp_dir() . '/daakpion_test_' . uniqid() . '.php';
        
        $sessionExport = var_export($sessionData, true);
        $postExport = var_export($postData, true);
        $headersExport = var_export($headers, true);
        $targetScript = str_replace('\\', '/', $scriptFile);
        $bootstrapPath = str_replace('\\', '/', realpath(__DIR__ . '/../php/bootstrap_security.php'));

        $wrapperCode = <<<PHP
<?php
declare(strict_types=1);
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
\$_SERVER['REQUEST_METHOD'] = 'POST';
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
        $email = "synthetic_{$tag}_" . bin2hex(random_bytes(6)) . "@example.com";
        $hash = CryptoService::hashPassword("SyntheticSecret123!");
        $stmt = $this->db->prepare("INSERT INTO users (fname, lname, email, password, password_version) VALUES (?, 'TestUser', ?, ?, 1)");
        $fname = "Syn_" . ucfirst($tag);
        $stmt->bind_param("sss", $fname, $email, $hash);
        $stmt->execute();
        $id = (int)$this->db->insert_id;
        $stmt->close();
        $this->cleanupUserIds[] = $id;
        return $id;
    }

    private function setFriendship(int $user1, int $user2, string $status): void
    {
        $u1 = min($user1, $user2);
        $u2 = max($user1, $user2);
        $stmt = $this->db->prepare("INSERT INTO friends (user1_id, user2_id, status) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE status = ?");
        $stmt->bind_param("iiss", $u1, $u2, $status, $status);
        $stmt->execute();
        $stmt->close();
    }

    private function countMessagesBetween(int $u1, int $u2): int
    {
        $stmt = $this->db->prepare("SELECT COUNT(*) FROM messages WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)");
        $stmt->bind_param("iiii", $u1, $u2, $u2, $u1);
        $stmt->execute();
        $res = $stmt->get_result()->fetch_row();
        $stmt->close();
        return (int)($res[0] ?? 0);
    }

    private function createFriendRequest(int $senderId, int $receiverId): int
    {
        $stmt = $this->db->prepare("INSERT INTO friendrequests (sender_id, receiver_id, status, sent_at) VALUES (?, ?, 'pending', NOW())");
        $stmt->bind_param("ii", $senderId, $receiverId);
        $stmt->execute();
        $id = (int)$this->db->insert_id;
        $stmt->close();
        return $id;
    }

    private function testActiveFriendshipAuthorization(): void
    {
        echo "--- 1. ACTIVE FRIENDSHIP AUTHORIZATION (DP-VULN-01) ---\n";

        $userA = $this->createSyntheticUser('sender');
        $userB = $this->createSyntheticUser('friend');
        $userC = $this->createSyntheticUser('stranger');
        $userD = $this->createSyntheticUser('pending');
        $userE = $this->createSyntheticUser('blocked');

        // Relationships
        $this->setFriendship($userA, $userB, 'active');
        $this->setFriendship($userA, $userD, 'pending');
        $this->setFriendship($userA, $userE, 'blocked');
        // userC has no record in friends with userA

        $csrfToken = CsrfProtection::getToken();
        $scriptPath = realpath(__DIR__ . '/../php/send_message.php');

        // Test 1.1: Active friend messaging succeeds
        $resAB = $this->executeSubprocess($scriptPath, [
            'user_id' => $userA,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [
            'receiver_id' => $userB,
            'message' => 'Hello active friend!',
            'csrf_token' => $csrfToken
        ]);

        $this->assert("Active friends messaging returns HTTP 200", $resAB['http_code'] === 200, "Received {$resAB['http_code']}: {$resAB['body']}");
        $this->assert("Active friends messaging inserts message in database", $this->countMessagesBetween($userA, $userB) === 1);

        // Test 1.2: Non-friend messaging rejected with HTTP 403
        $initialStrangerMsgs = $this->countMessagesBetween($userA, $userC);
        $resAC = $this->executeSubprocess($scriptPath, [
            'user_id' => $userA,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [
            'receiver_id' => $userC,
            'message' => 'Unsolicited message to stranger',
            'csrf_token' => $csrfToken
        ]);

        $this->assert("Non-friend messaging rejected with HTTP 403", $resAC['http_code'] === 403, "Received {$resAC['http_code']}: {$resAC['body']}");
        $this->assert("Non-friend error message mentions confirmed friends", strpos($resAC['body'], 'confirmed friends') !== false);
        $this->assert("Zero message records created for non-friend", $this->countMessagesBetween($userA, $userC) === $initialStrangerMsgs);

        // Test 1.3: Pending friend request messaging rejected with HTTP 403
        $resAD = $this->executeSubprocess($scriptPath, [
            'user_id' => $userA,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [
            'receiver_id' => $userD,
            'message' => 'Trying to message pending friend',
            'csrf_token' => $csrfToken
        ]);

        $this->assert("Pending friend request messaging rejected with HTTP 403", $resAD['http_code'] === 403);
        $this->assert("Zero message records created for pending friend", $this->countMessagesBetween($userA, $userD) === 0);

        // Test 1.4: Blocked relationship messaging rejected with HTTP 403
        $resAE = $this->executeSubprocess($scriptPath, [
            'user_id' => $userA,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [
            'receiver_id' => $userE,
            'message' => 'Trying to message blocked user',
            'csrf_token' => $csrfToken
        ]);

        $this->assert("Blocked user messaging rejected with HTTP 403", $resAE['http_code'] === 403);
        $this->assert("Zero message records created for blocked user", $this->countMessagesBetween($userA, $userE) === 0);

        // Test 1.5: Nonexistent receiver ID rejected with HTTP 403
        $resANonExistent = $this->executeSubprocess($scriptPath, [
            'user_id' => $userA,
            'password_version' => 1,
            'csrf_token' => $csrfToken
        ], [
            'receiver_id' => 99999999,
            'message' => 'Ghost recipient test',
            'csrf_token' => $csrfToken
        ]);

        $this->assert("Nonexistent receiver ID rejected with HTTP 403", $resANonExistent['http_code'] === 403);
    }

    private function testCsrfProtectionEndpoints(): void
    {
        echo "\n--- 2. CSRF PROTECTION ON SOCIAL ENDPOINTS (DP-VULN-02) ---\n";

        $user1 = $this->createSyntheticUser('csrf1');
        $user2 = $this->createSyntheticUser('csrf2');
        $this->setFriendship($user1, $user2, 'active');

        $validToken = CsrfProtection::getToken();
        $invalidToken = 'invalid_csrf_token_value_0123456789abcdef';

        // 2.1: send_message.php CSRF tests
        $sendMsgScript = realpath(__DIR__ . '/../php/send_message.php');

        $resNoToken = $this->executeSubprocess($sendMsgScript, [
            'user_id' => $user1,
            'password_version' => 1,
            'csrf_token' => $validToken
        ], [
            'receiver_id' => $user2,
            'message' => 'Test without token'
        ]);
        $this->assert("send_message.php rejects missing CSRF token with HTTP 403", $resNoToken['http_code'] === 403);
        $this->assert("send_message.php missing CSRF error message matches expected", strpos($resNoToken['body'], 'CSRF') !== false);

        $resInvalidToken = $this->executeSubprocess($sendMsgScript, [
            'user_id' => $user1,
            'password_version' => 1,
            'csrf_token' => $validToken
        ], [
            'receiver_id' => $user2,
            'message' => 'Test with invalid token',
            'csrf_token' => $invalidToken
        ]);
        $this->assert("send_message.php rejects invalid CSRF token with HTTP 403", $resInvalidToken['http_code'] === 403);

        $resValidHeader = $this->executeSubprocess($sendMsgScript, [
            'user_id' => $user1,
            'password_version' => 1,
            'csrf_token' => $validToken
        ], [
            'receiver_id' => $user2,
            'message' => 'Test with header token'
        ], [
            'HTTP_X_CSRF_TOKEN' => $validToken
        ]);
        $this->assert("send_message.php accepts valid CSRF token in X-CSRF-Token header", $resValidHeader['http_code'] === 200);

        // 2.2: send_request.php CSRF tests
        $user3 = $this->createSyntheticUser('req_target');
        $sendReqScript = realpath(__DIR__ . '/../php/send_request.php');

        $resReqNoToken = $this->executeSubprocess($sendReqScript, [
            'user_id' => $user1,
            'password_version' => 1,
            'csrf_token' => $validToken
        ], [
            'receiver_id' => $user3
        ]);
        $this->assert("send_request.php rejects missing CSRF token with HTTP 403", $resReqNoToken['http_code'] === 403);

        $resReqInvalidToken = $this->executeSubprocess($sendReqScript, [
            'user_id' => $user1,
            'password_version' => 1,
            'csrf_token' => $validToken
        ], [
            'receiver_id' => $user3,
            'csrf_token' => $invalidToken
        ]);
        $this->assert("send_request.php rejects invalid CSRF token with HTTP 403", $resReqInvalidToken['http_code'] === 403);

        $resReqValid = $this->executeSubprocess($sendReqScript, [
            'user_id' => $user1,
            'password_version' => 1,
            'csrf_token' => $validToken
        ], [
            'receiver_id' => $user3,
            'csrf_token' => $validToken
        ]);
        $this->assert("send_request.php accepts valid CSRF token with HTTP 200", $resReqValid['http_code'] === 200);

        // 2.3: respond_request.php CSRF tests
        // Insert pending friend requests from user3 to user1
        $reqNoToken = $this->createFriendRequest($user3, $user1);
        $reqInvalidToken = $this->createFriendRequest($user3, $user1);
        $reqValid = $this->createFriendRequest($user3, $user1);
        $respondReqScript = realpath(__DIR__ . '/../php/respond_request.php');

        $resRespNoToken = $this->executeSubprocess($respondReqScript, [
            'user_id' => $user1,
            'password_version' => 1,
            'csrf_token' => $validToken
        ], [
            'request_id' => $reqNoToken,
            'action' => 'accept'
        ]);
        $this->assert("respond_request.php rejects missing CSRF token with HTTP 403", $resRespNoToken['http_code'] === 403);

        $resRespInvalidToken = $this->executeSubprocess($respondReqScript, [
            'user_id' => $user1,
            'password_version' => 1,
            'csrf_token' => $validToken
        ], [
            'request_id' => $reqInvalidToken,
            'action' => 'accept',
            'csrf_token' => $invalidToken
        ]);
        $this->assert("respond_request.php rejects invalid CSRF token with HTTP 403", $resRespInvalidToken['http_code'] === 403);

        $resRespValid = $this->executeSubprocess($respondReqScript, [
            'user_id' => $user1,
            'password_version' => 1,
            'csrf_token' => $validToken
        ], [
            'request_id' => $reqValid,
            'action' => 'accept',
            'csrf_token' => $validToken
        ]);
        $this->assert("respond_request.php accepts valid CSRF token with HTTP 200", $resRespValid['http_code'] === 200);
    }

    private function testSafeErrorHandlingAndSqlSuppression(): void
    {
        echo "\n--- 3. SAFE ERROR HANDLING & SQL SUPPRESSION (DP-VULN-04) ---\n";

        // Test static analysis of remediated files to ensure raw $conn->error and $e->getMessage() are eliminated from outputs
        $filesToCheck = [
            'php/friendlist.php',
            'php/respond_request.php',
            'php/edit-profile.php',
            'php/db_connect.php',
            'php/send_message.php',
            'php/send_request.php'
        ];

        foreach ($filesToCheck as $relPath) {
            $fullPath = realpath(__DIR__ . '/../' . $relPath);
            $content = file_get_contents($fullPath);

            // Ensure no raw echo/die containing $conn->error
            $hasRawConnErrorEcho = (bool)preg_match('/(echo|die|print)\s*\(?.*\$conn->error/i', $content);
            $this->assert("{$relPath} suppresses raw \$conn->error disclosure", !$hasRawConnErrorEcho, "Found direct \$conn->error echo/die");

            // Ensure no raw echo/die containing $e->getMessage() directly to client
            $hasRawExceptionEcho = (bool)preg_match('/(echo|die|print)\s*\(?.*\$e->getMessage\(\)/i', $content);
            $this->assert("{$relPath} suppresses raw \$e->getMessage() disclosure", !$hasRawExceptionEcho, "Found direct \$e->getMessage() echo/die");

            // Ensure error_log is used for diagnostics
            $hasErrorLog = (bool)strpos($content, 'error_log');
            $this->assert("{$relPath} logs technical diagnostics via error_log", $hasErrorLog, "Missing error_log invocation");
        }

        // Functional check: respond_request.php error handling returns generic error on DB failure
        $respondReqScript = realpath(__DIR__ . '/../php/respond_request.php');
        $validToken = CsrfProtection::getToken();
        // Invoke with invalid action to trigger invalid action branch or fail cleanly
        $resInvalidAction = $this->executeSubprocess($respondReqScript, [
            'user_id' => 9999999,
            'password_version' => 1,
            'csrf_token' => $validToken
        ], [
            'sender_id' => 8888888,
            'action' => 'invalid_action_xyz',
            'csrf_token' => $validToken
        ]);
        $this->assert("respond_request.php handles unexpected action without SQL error", strpos($resInvalidAction['body'], 'syntax error') === false);
    }

    private function testCliAndHttpAccessRestrictions(): void
    {
        echo "\n--- 4. CLI RESTRICTIONS & DIRECTORY ACCESS CONTROLS (DP-VULN-05) ---\n";

        // 4.1: migrate_security.php rejects non-CLI execution
        $migrateScript = realpath(__DIR__ . '/../php/migrate_security.php');
        $content = file_get_contents($migrateScript);
        $hasCliGuard = strpos($content, "php_sapi_name() !== 'cli'") !== false;
        $this->assert("migrate_security.php contains php_sapi_name() !== 'cli' guard", $hasCliGuard);

        // 4.2: tests/.htaccess exists and contains 'Require all denied'
        $testsHtaccess = realpath(__DIR__ . '/.htaccess');
        $this->assert("tests/.htaccess exists", $testsHtaccess !== false);
        $testsHtaccessContent = file_get_contents($testsHtaccess);
        $hasRequireAllDenied = strpos($testsHtaccessContent, 'Require all denied') !== false;
        $this->assert("tests/.htaccess enforces 'Require all denied'", $hasRequireAllDenied);

        // 4.3: root .htaccess protects migrate_security.php
        $rootHtaccess = dirname(__DIR__) . DIRECTORY_SEPARATOR . '.htaccess';
        $this->assert("Root .htaccess exists", file_exists($rootHtaccess));
        $rootHtaccessContent = file_exists($rootHtaccess) ? file_get_contents($rootHtaccess) : '';
        $hasMigrateInHtaccess = strpos($rootHtaccessContent, 'migrate_security') !== false;
        $this->assert("Root .htaccess denies direct access to migrate_security.php", $hasMigrateInHtaccess);

        // 4.4: Dynamic Apache HTTP access verification via curl (if web server reachable)
        $curlTestOutput = shell_exec('curl.exe -s -o NUL -w "%{http_code}" http://127.0.0.1/Daakpion/tests/SecurityTestSuite.php');
        $httpCode = trim((string)$curlTestOutput);
        if ($httpCode !== '') {
            $this->assert("Apache actively denies HTTP request to /tests/ with HTTP 403", $httpCode === '403', "Received HTTP {$httpCode}");
        }

        $curlMigrateOutput = shell_exec('curl.exe -s -o NUL -w "%{http_code}" http://127.0.0.1/Daakpion/php/migrate_security.php');
        $httpCodeMigrate = trim((string)$curlMigrateOutput);
        if ($httpCodeMigrate !== '') {
            $this->assert("Apache actively denies HTTP request to migrate_security.php with HTTP 403", $httpCodeMigrate === '403', "Received HTTP {$httpCodeMigrate}");
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
        $this->db->query("DELETE FROM users WHERE id IN ({$idList})");
    }
}

// Instantiate and execute
$phase1Suite = new Phase1RemediationTest($conn);
$phase1Suite->runAll();
