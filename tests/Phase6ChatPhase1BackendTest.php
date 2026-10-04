<?php
// tests/Phase6ChatPhase1BackendTest.php — Automated test suite for Phase 1 chat enhancements
declare(strict_types=1);

require_once __DIR__ . '/../php/bootstrap_security.php';

use Daakpion\Security\CsrfProtection;
use Daakpion\Security\CryptoService;

class Phase6ChatPhase1BackendTest
{
    private mysqli $conn;
    private int $userAId;
    private int $userBId;
    private int $userCId; // Unrelated user (not friend)
    private string $csrfToken;
    private int $passed = 0;
    private int $failed = 0;

    public function __construct(mysqli $conn)
    {
        $this->conn = $conn;
    }

    private function getSessionData(int $userId): array
    {
        return [
            'user_id'          => $userId,
            'password_version' => 1,
            'csrf_token'       => $this->csrfToken,
            'name'             => 'Tester'
        ];
    }

    private function executeSubprocess(
        string $scriptFile,
        array $sessionData,
        array $postData = [],
        array $getData = [],
        array $headers = []
    ): array {
        $wrapperFile = sys_get_temp_dir() . '/daakpion_p1_test_' . uniqid() . '.php';

        $sessionExport = var_export($sessionData, true);
        $postExport = var_export($postData, true);
        $getExport = var_export($getData, true);
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

    public function run(): void
    {
        echo "=========================================================\n";
        echo "   DAAKPION CHAT PHASE 1 BACKEND VERIFICATION SUITE     \n";
        echo "=========================================================\n\n";

        $this->setUp();

        $this->testSendMessageAndEncryption();
        $this->testIdempotentMessageRetry();
        $this->testReplyToMessage();
        $this->testInvalidReplyToMessage();
        $this->testMarkMessagesRead();
        $this->testTypingIndicatorLifecycle();
        $this->testPresenceAndUnreadCounts();
        $this->testDeleteForMe();
        $this->testDeleteForEveryone();
        $this->testUnauthorizedOperations();

        $this->tearDown();

        echo "\n=========================================================\n";
        echo "  PHASE 1 RESULTS: {$this->passed} Passed | {$this->failed} Failed\n";
        echo "=========================================================\n";

        if ($this->failed > 0) {
            exit(1);
        }
    }

    private function assert(bool $condition, string $desc): void
    {
        if ($condition) {
            $this->passed++;
            echo " [PASS] $desc\n";
        } else {
            $this->failed++;
            echo " [FAIL] $desc\n";
        }
    }

    private function setUp(): void
    {
        // Fetch or create test users
        $resA = $this->conn->query("SELECT id FROM users WHERE email = 'test_direct@example.com'");
        if ($rA = $resA->fetch_assoc()) {
            $this->userAId = (int)$rA['id'];
        } else {
            $hash = CryptoService::hashPassword('TestPassword123!');
            $this->conn->query("INSERT INTO users (fname, lname, email, password, status, two_factor_enabled, password_version) VALUES ('Alice', 'Tester', 'test_direct@example.com', '$hash', 'Active now', 0, 1)");
            $this->userAId = (int)$this->conn->insert_id;
        }

        $resB = $this->conn->query("SELECT id FROM users WHERE email = 'test_login@example.com'");
        if ($rB = $resB->fetch_assoc()) {
            $this->userBId = (int)$rB['id'];
        } else {
            $hash = CryptoService::hashPassword('TestPassword123!');
            $this->conn->query("INSERT INTO users (fname, lname, email, password, status, two_factor_enabled, password_version) VALUES ('Bob', 'Tester', 'test_login@example.com', '$hash', 'Active now', 1, 1)");
            $this->userBId = (int)$this->conn->insert_id;
        }

        $resC = $this->conn->query("SELECT id FROM users WHERE email = 'user_c_unrelated@example.com'");
        if ($rC = $resC->fetch_assoc()) {
            $this->userCId = (int)$rC['id'];
        } else {
            $hash = CryptoService::hashPassword('TestPassword123!');
            $this->conn->query("INSERT INTO users (fname, lname, email, password, status, two_factor_enabled, password_version) VALUES ('Charlie', 'Stranger', 'user_c_unrelated@example.com', '$hash', 'Offline', 0, 1)");
            $this->userCId = (int)$this->conn->insert_id;
        }

        // Ensure active friendship between A and B
        $this->conn->query("DELETE FROM friends WHERE (user1_id = {$this->userAId} AND user2_id = {$this->userBId}) OR (user1_id = {$this->userBId} AND user2_id = {$this->userAId})");
        $this->conn->query("INSERT INTO friends (user1_id, user2_id, status) VALUES ({$this->userAId}, {$this->userBId}, 'active')");

        // Ensure NO friendship between A and C
        $this->conn->query("DELETE FROM friends WHERE (user1_id = {$this->userAId} AND user2_id = {$this->userCId}) OR (user1_id = {$this->userCId} AND user2_id = {$this->userAId})");

        // Clean up test messages between A and B
        $this->conn->query("DELETE FROM messages WHERE (sender_id = {$this->userAId} AND receiver_id = {$this->userBId}) OR (sender_id = {$this->userBId} AND receiver_id = {$this->userAId})");
        $this->conn->query("DELETE FROM typing_indicators WHERE user_id IN ({$this->userAId}, {$this->userBId})");

        $this->csrfToken = 'test_valid_csrf_token_' . bin2hex(random_bytes(16));
    }

    private function tearDown(): void
    {
        // Cleanup if needed
    }

    private function testSendMessageAndEncryption(): void
    {
        echo "--- 1. SEND MESSAGE & AUTHENTICATED ENCRYPTION ---\n";

        $res = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/send_message.php'),
            $this->getSessionData($this->userAId),
            [
                'receiver_id'       => (string)$this->userBId,
                'message'           => 'Hello Bob! This is an encrypted test.',
                'client_message_id' => 'msg-client-' . bin2hex(random_bytes(8)),
                'csrf_token'        => $this->csrfToken,
            ]
        );

        $this->assert($res['http_code'] === 200, "Send message returns HTTP 200");
        $data = $res['json'];
        $this->assert(is_array($data) && ($data['success'] ?? false) === true, "Send message output reports success");
        $msgId = (int)($data['id'] ?? 0);
        $this->assert($msgId > 0, "Valid message ID returned ($msgId)");

        // Verify database storage has AES-256-GCM format
        $stmt = $this->conn->prepare("SELECT message, is_read, is_delivered FROM messages WHERE id = ?");
        $stmt->bind_param("i", $msgId);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        $this->assert(str_starts_with($row['message'], 'v2:gcm:'), "Stored ciphertext uses versioned AES-256-GCM format");
        $decrypted = CryptoService::decryptMessage($row['message']);
        $this->assert($decrypted === 'Hello Bob! This is an encrypted test.', "Ciphertext decrypts to exact original plaintext");
    }

    private function testIdempotentMessageRetry(): void
    {
        echo "--- 2. IDEMPOTENT MESSAGE RETRY & DUPLICATE PREVENTION ---\n";

        $clientMsgId = 'msg-idem-' . bin2hex(random_bytes(8));

        // First attempt
        $res1 = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/send_message.php'),
            $this->getSessionData($this->userAId),
            [
                'receiver_id'       => (string)$this->userBId,
                'message'           => 'Idempotent test message',
                'client_message_id' => $clientMsgId,
                'csrf_token'        => $this->csrfToken,
            ]
        );
        $firstId = (int)($res1['json']['id'] ?? 0);

        // Immediate retry with SAME client_message_id
        $res2 = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/send_message.php'),
            $this->getSessionData($this->userAId),
            [
                'receiver_id'       => (string)$this->userBId,
                'message'           => 'Idempotent test message',
                'client_message_id' => $clientMsgId,
                'csrf_token'        => $this->csrfToken,
            ]
        );
        $secondId = (int)($res2['json']['id'] ?? 0);

        $this->assert($firstId === $secondId, "Retry returned original message ID ($firstId) without creating duplicate");
        $this->assert(($res2['json']['duplicate'] ?? false) === true, "Idempotency flag indicated duplicate handled safely");

        // Verify count in DB
        $stmt = $this->conn->prepare("SELECT COUNT(*) AS c FROM messages WHERE client_message_id = ?");
        $stmt->bind_param("s", $clientMsgId);
        $stmt->execute();
        $count = (int)$stmt->get_result()->fetch_assoc()['c'];
        $stmt->close();
        $this->assert($count === 1, "Exactly one row exists in database for this client_message_id");
    }

    private function testReplyToMessage(): void
    {
        echo "--- 3. MESSAGE REPLYING & PREVIEW RESOLUTION ---\n";

        // Create original message from Bob to Alice
        $origCipher = CryptoService::encryptMessage("Bob's initial question?");
        $this->conn->query("INSERT INTO messages (sender_id, receiver_id, message, sent_at, is_read, is_delivered) VALUES ({$this->userBId}, {$this->userAId}, '{$origCipher}', NOW(), 0, 1)");
        $origMsgId = (int)$this->conn->insert_id;

        // Alice replies to Bob's message
        $replyRes = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/send_message.php'),
            $this->getSessionData($this->userAId),
            [
                'receiver_id'       => (string)$this->userBId,
                'message'           => "Yes, I have the answer!",
                'reply_to_id'       => (string)$origMsgId,
                'client_message_id' => 'reply-' . bin2hex(random_bytes(8)),
                'csrf_token'        => $this->csrfToken,
            ]
        );
        $replyMsgId = (int)($replyRes['json']['id'] ?? 0);
        $this->assert($replyMsgId > 0, "Reply message created successfully ($replyMsgId)");

        // Test get_messages.php resolves the reply preview
        $getRes = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/get_messages.php'),
            $this->getSessionData($this->userAId),
            [],
            ['friend_id' => (string)$this->userBId, 'since_id' => '0']
        );
        $msgs = $getRes['json'] ?? [];

        $replyFound = false;
        foreach ($msgs as $m) {
            if ($m['id'] === $replyMsgId) {
                $replyFound = true;
                $this->assert(isset($m['reply_to']) && is_array($m['reply_to']), "Reply metadata present on message");
                $this->assert(($m['reply_to']['id'] ?? 0) === $origMsgId, "Referenced message ID matches original");
                $this->assert(str_contains($m['reply_to']['snippet'], "Bob's initial question"), "Reply snippet contains decrypted original text");
            }
        }
        $this->assert($replyFound, "Reply message successfully fetched from get_messages.php");
    }

    private function testInvalidReplyToMessage(): void
    {
        echo "--- 4. INVALID REPLY TARGET REJECTION ---\n";

        $res = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/send_message.php'),
            $this->getSessionData($this->userAId),
            [
                'receiver_id'       => (string)$this->userBId,
                'message'           => "Malicious reply target",
                'reply_to_id'       => '999999',
                'client_message_id' => 'bad-reply-' . bin2hex(random_bytes(8)),
                'csrf_token'        => $this->csrfToken,
            ]
        );

        $this->assert($res['http_code'] === 400, "Replying to non-existent message rejected with HTTP 400");
    }

    private function testMarkMessagesRead(): void
    {
        echo "--- 5. READ RECEIPTS & MARK MESSAGES READ ---\n";

        // Create an unread message from Bob to Alice
        $cipher = CryptoService::encryptMessage("Unread message from Bob");
        $this->conn->query("INSERT INTO messages (sender_id, receiver_id, message, sent_at, is_read, is_delivered) VALUES ({$this->userBId}, {$this->userAId}, '{$cipher}', NOW(), 0, 1)");
        $unreadId = (int)$this->conn->insert_id;

        // Alice marks messages from Bob as read
        $res = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/mark_messages_read.php'),
            $this->getSessionData($this->userAId),
            [
                'friend_id'  => (string)$this->userBId,
                'max_id'     => (string)$unreadId,
                'csrf_token' => $this->csrfToken,
            ]
        );

        $this->assert($res['http_code'] === 200, "mark_messages_read.php returns HTTP 200");
        $data = $res['json'];
        $this->assert(($data['success'] ?? false) === true, "mark_messages_read.php reported success");
        $this->assert(($data['marked_count'] ?? 0) >= 1, "At least 1 message marked as read");

        // Verify in DB
        $dbRes = $this->conn->query("SELECT is_read FROM messages WHERE id = {$unreadId}");
        $this->assert((int)$dbRes->fetch_assoc()['is_read'] === 1, "Database column is_read updated to 1");
    }

    private function testTypingIndicatorLifecycle(): void
    {
        echo "--- 6. TYPING INDICATOR LIFECYCLE ---\n";

        // Alice starts typing to Bob
        $resStart = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/update_typing.php'),
            $this->getSessionData($this->userAId),
            [
                'friend_id'  => (string)$this->userBId,
                'is_typing'  => '1',
                'csrf_token' => $this->csrfToken,
            ]
        );
        $this->assert(($resStart['json']['is_typing'] ?? false) === true, "Typing indicator set to active");

        // Bob queries presence of Alice
        $pRes = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/get_presence.php'),
            $this->getSessionData($this->userBId),
            [],
            ['friend_id' => (string)$this->userAId]
        );
        $this->assert(($pRes['json']['is_typing'] ?? false) === true, "Bob observes Alice is_typing = true");

        // Alice stops typing
        $this->executeSubprocess(
            realpath(__DIR__ . '/../php/update_typing.php'),
            $this->getSessionData($this->userAId),
            [
                'friend_id'  => (string)$this->userBId,
                'is_typing'  => '0',
                'csrf_token' => $this->csrfToken,
            ]
        );

        // Bob queries presence again
        $pRes2 = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/get_presence.php'),
            $this->getSessionData($this->userBId),
            [],
            ['friend_id' => (string)$this->userAId]
        );
        $this->assert(($pRes2['json']['is_typing'] ?? true) === false, "Bob observes Alice is_typing = false after stop");
    }

    private function testPresenceAndUnreadCounts(): void
    {
        echo "--- 7. PRESENCE & UNREAD COUNTS AGGREGATION ---\n";

        // Create 2 unread messages from Bob to Alice
        $c1 = CryptoService::encryptMessage("Unread 1");
        $c2 = CryptoService::encryptMessage("Unread 2");
        $this->conn->query("INSERT INTO messages (sender_id, receiver_id, message, sent_at, is_read, is_delivered) VALUES ({$this->userBId}, {$this->userAId}, '{$c1}', NOW(), 0, 1)");
        $this->conn->query("INSERT INTO messages (sender_id, receiver_id, message, sent_at, is_read, is_delivered) VALUES ({$this->userBId}, {$this->userAId}, '{$c2}', NOW(), 0, 1)");

        // Alice fetches batch presence
        $batchRes = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/get_presence.php'),
            $this->getSessionData($this->userAId)
        );
        $data = $batchRes['json'];

        $this->assert(isset($data['unread_counts'][$this->userBId]), "Unread counts contains entry for Bob");
        $this->assert($data['unread_counts'][$this->userBId] >= 2, "Unread count for Bob reflects at least 2 unread messages");
    }

    private function testDeleteForMe(): void
    {
        echo "--- 8. DELETE MESSAGE FOR ME ---\n";

        $cipher = CryptoService::encryptMessage("Message to delete for me");
        $this->conn->query("INSERT INTO messages (sender_id, receiver_id, message, sent_at, is_read, is_delivered) VALUES ({$this->userAId}, {$this->userBId}, '{$cipher}', NOW(), 0, 1)");
        $msgId = (int)$this->conn->insert_id;

        // Alice deletes for me
        $delRes = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/delete_message.php'),
            $this->getSessionData($this->userAId),
            [
                'message_id'  => (string)$msgId,
                'delete_type' => 'for_me',
                'csrf_token'  => $this->csrfToken,
            ]
        );
        $this->assert(($delRes['json']['success'] ?? false) === true, "Delete for me succeeds");

        // Alice should NOT see it anymore
        $aliceRes = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/get_messages.php'),
            $this->getSessionData($this->userAId),
            [],
            ['friend_id' => (string)$this->userBId, 'since_id' => '0']
        );
        $aliceMsgs = $aliceRes['json'] ?? [];
        $foundForAlice = false;
        foreach ($aliceMsgs as $m) {
            if ($m['id'] === $msgId) $foundForAlice = true;
        }
        $this->assert(!$foundForAlice, "Message is hidden from Alice's conversation view");

        // Bob SHOULD still see it
        $bobRes = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/get_messages.php'),
            $this->getSessionData($this->userBId),
            [],
            ['friend_id' => (string)$this->userAId, 'since_id' => '0']
        );
        $bobMsgs = $bobRes['json'] ?? [];
        $foundForBob = false;
        foreach ($bobMsgs as $m) {
            if ($m['id'] === $msgId) $foundForBob = true;
        }
        $this->assert($foundForBob, "Message remains visible to Bob");
    }

    private function testDeleteForEveryone(): void
    {
        echo "--- 9. DELETE MESSAGE FOR EVERYONE ---\n";

        $cipher = CryptoService::encryptMessage("Secret to delete for everyone");
        $this->conn->query("INSERT INTO messages (sender_id, receiver_id, message, sent_at, is_read, is_delivered) VALUES ({$this->userAId}, {$this->userBId}, '{$cipher}', NOW(), 0, 1)");
        $msgId = (int)$this->conn->insert_id;

        // Alice deletes for everyone
        $delRes = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/delete_message.php'),
            $this->getSessionData($this->userAId),
            [
                'message_id'  => (string)$msgId,
                'delete_type' => 'for_everyone',
                'csrf_token'  => $this->csrfToken,
            ]
        );
        $this->assert(($delRes['json']['success'] ?? false) === true, "Delete for everyone succeeds");

        // When fetched, message text should be 'This message was deleted'
        $aliceRes = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/get_messages.php'),
            $this->getSessionData($this->userAId),
            [],
            ['friend_id' => (string)$this->userBId, 'since_id' => '0']
        );
        $aliceMsgs = $aliceRes['json'] ?? [];
        $tombstoneFound = false;
        foreach ($aliceMsgs as $m) {
            if ($m['id'] === $msgId) {
                $tombstoneFound = true;
                $this->assert($m['message'] === 'This message was deleted', "Message body rendered as tombstone text");
                $this->assert(($m['is_deleted'] ?? false) === true, "is_deleted flag is true");
            }
        }
        $this->assert($tombstoneFound, "Tombstone message found in conversation");
    }

    private function testUnauthorizedOperations(): void
    {
        echo "--- 10. UNAUTHORIZED ACTIONS & CSRF FAILURES ---\n";

        // Alice tries to message Charlie (not a friend)
        $resNotFriend = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/send_message.php'),
            $this->getSessionData($this->userAId),
            [
                'receiver_id' => (string)$this->userCId,
                'message'     => 'Unauthorized message',
                'csrf_token'  => $this->csrfToken,
            ]
        );
        $this->assert($resNotFriend['http_code'] === 403, "Messaging non-friend Charlie rejected with HTTP 403");

        // Alice tries to delete with invalid CSRF
        $resBadCsrf = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/delete_message.php'),
            $this->getSessionData($this->userAId),
            [
                'message_id'  => '1',
                'delete_type' => 'for_me',
                'csrf_token'  => 'invalid_token_12345',
            ]
        );
        $this->assert($resBadCsrf['http_code'] === 403, "Delete with bad CSRF rejected with HTTP 403");
    }
}

$test = new Phase6ChatPhase1BackendTest($conn);
$test->run();
