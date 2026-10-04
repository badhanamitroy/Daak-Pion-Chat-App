<?php
// tests/Phase7MediaMessagingBackendTest.php — Comprehensive test suite for Phase 2 media messaging
declare(strict_types=1);

require_once __DIR__ . '/../php/bootstrap_security.php';

use Daakpion\Security\CsrfProtection;
use Daakpion\Security\CryptoService;
use Daakpion\Security\MediaUploadService;

class Phase7MediaMessagingBackendTest
{
    private mysqli $conn;
    private int $userAId;
    private int $userBId;
    private int $userCId; // Unrelated user (not friend)
    private string $csrfToken;
    private int $passed = 0;
    private int $failed = 0;
    private array $createdTempFiles = [];

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
        array $filesData = []
    ): array {
        $wrapperFile = sys_get_temp_dir() . '/daakpion_p2_test_' . uniqid() . '.php';

        $sessionExport = var_export($sessionData, true);
        $postExport = var_export($postData, true);
        $getExport = var_export($getData, true);
        $filesExport = var_export($filesData, true);
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
\$_FILES = {$filesExport};
\$_SERVER['REQUEST_METHOD'] = (!empty({$postExport}) || !empty({$filesExport})) ? 'POST' : 'GET';

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
        echo "   DAAKPION MEDIA MESSAGING (PHASE 2) BACKEND TEST SUITE \n";
        echo "=========================================================\n\n";

        $this->setUp();

        $this->testImageUploadAndStorage();
        $this->testDownloadSecurityAndStreaming();
        $this->testVideoUploadAndPlaybackMetadata();
        $this->testDocumentUploadAndDownloadHeader();
        $this->testVoiceAudioMessageUpload();
        $this->testProhibitedExecutableUploadBlocked();
        $this->testMimeSpoofingBlocked();
        $this->testUnauthorizedAttachmentAccessBlocked();
        $this->testDeleteMessageCleansUpAttachment();

        $this->tearDown();

        echo "\n=========================================================\n";
        echo "  PHASE 2 RESULTS: {$this->passed} Passed | {$this->failed} Failed\n";
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
        $resA = $this->conn->query("SELECT id FROM users WHERE email = 'test_direct@example.com'");
        $this->userAId = (int)$resA->fetch_assoc()['id'];

        $resB = $this->conn->query("SELECT id FROM users WHERE email = 'test_login@example.com'");
        $this->userBId = (int)$resB->fetch_assoc()['id'];

        $resC = $this->conn->query("SELECT id FROM users WHERE email = 'user_c_unrelated@example.com'");
        $this->userCId = (int)$resC->fetch_assoc()['id'];

        $this->csrfToken = 'media_test_token_' . bin2hex(random_bytes(16));
    }

    private function tearDown(): void
    {
        foreach ($this->createdTempFiles as $f) {
            if (file_exists($f)) @unlink($f);
        }
    }

    private function createFakeFile(string $name, string $content): string
    {
        $path = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'tmp_' . uniqid() . '_' . $name;
        file_put_contents($path, $content);
        $this->createdTempFiles[] = $path;
        return $path;
    }

    private function testImageUploadAndStorage(): void
    {
        echo "--- 1. IMAGE UPLOAD & METADATA STORAGE ---\n";

        // Minimal valid 1x1 transparent PNG binary
        $pngBinary = base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==');
        $tmp = $this->createFakeFile('photo.png', $pngBinary);

        $res = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/upload_media.php'),
            $this->getSessionData($this->userAId),
            [
                'receiver_id' => (string)$this->userBId,
                'caption'     => 'Check out this screenshot!',
                'csrf_token'  => $this->csrfToken,
            ],
            [],
            [
                'file' => [
                    'name'     => 'photo.png',
                    'type'     => 'image/png',
                    'tmp_name' => $tmp,
                    'error'    => UPLOAD_ERR_OK,
                    'size'     => strlen($pngBinary)
                ]
            ]
        );

        $this->assert($res['http_code'] === 200, "Image upload returned HTTP 200");
        $data = $res['json'] ?? [];
        $this->assert(($data['success'] ?? false) === true, "Upload returned success=true");
        $this->assert(($data['message_type'] ?? '') === 'image', "Message type classified as 'image'");
        $attach = $data['attachment'] ?? [];
        $attachId = (int)($attach['id'] ?? 0);
        $this->assert($attachId > 0, "Attachment ID created in database ($attachId)");

        // Verify attachment row in DB
        $stmt = $this->conn->prepare("SELECT storage_path, mime_type, media_type FROM message_attachments WHERE id = ?");
        $stmt->bind_param("i", $attachId);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        $this->assert($row && $row['mime_type'] === 'image/png', "MIME type stored as image/png");
        $rootDir = realpath(__DIR__ . '/..');
        $storedFile = $rootDir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $row['storage_path']);
        $this->assert(file_exists($storedFile), "Physical image file exists on disk");
    }

    private function testDownloadSecurityAndStreaming(): void
    {
        echo "--- 2. CONTROLLED ATTACHMENT STREAMING & AUTHORIZATION ---\n";

        // Fetch latest attachment
        $res = $this->conn->query("SELECT id FROM message_attachments ORDER BY id DESC LIMIT 1");
        $attachId = (int)$res->fetch_assoc()['id'];

        // User B (receiver) accesses the attachment
        $downRes = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/download_attachment.php'),
            $this->getSessionData($this->userBId),
            [],
            ['id' => (string)$attachId]
        );

        $this->assert($downRes['http_code'] === 200, "Receiver can stream attachment (HTTP 200)");
        $this->assert(!empty($downRes['body']), "Streamed file content is non-empty");

        // User C (unrelated third party) tries to access User A & B's attachment
        $unauthDown = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/download_attachment.php'),
            $this->getSessionData($this->userCId),
            [],
            ['id' => (string)$attachId]
        );

        $this->assert($unauthDown['http_code'] === 403, "Unrelated user accessing attachment rejected with HTTP 403");
    }

    private function testVideoUploadAndPlaybackMetadata(): void
    {
        echo "--- 3. VIDEO UPLOAD & PLAYBACK METADATA ---\n";

        // Minimal fake MP4 container header (ftypisom)
        $mp4Binary = "\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00isommp42\x00\x00\x00\x08free";
        $tmp = $this->createFakeFile('clip.mp4', $mp4Binary);

        $res = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/upload_media.php'),
            $this->getSessionData($this->userAId),
            [
                'receiver_id' => (string)$this->userBId,
                'caption'     => 'Sample video clip',
                'csrf_token'  => $this->csrfToken,
            ],
            [],
            [
                'file' => [
                    'name'     => 'clip.mp4',
                    'type'     => 'video/mp4',
                    'tmp_name' => $tmp,
                    'error'    => UPLOAD_ERR_OK,
                    'size'     => strlen($mp4Binary)
                ]
            ]
        );

        $this->assert($res['http_code'] === 200, "Video upload returned HTTP 200");
        $data = $res['json'] ?? [];
        $this->assert(($data['message_type'] ?? '') === 'video', "Message type classified as 'video'");
    }

    private function testDocumentUploadAndDownloadHeader(): void
    {
        echo "--- 4. DOCUMENT UPLOAD & ATTACHMENT DISPOSITION ---\n";

        // Minimal valid PDF header
        $pdfContent = "%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF";
        $tmp = $this->createFakeFile('report.pdf', $pdfContent);

        $res = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/upload_media.php'),
            $this->getSessionData($this->userAId),
            [
                'receiver_id' => (string)$this->userBId,
                'caption'     => 'Project specs PDF',
                'csrf_token'  => $this->csrfToken,
            ],
            [],
            [
                'file' => [
                    'name'     => 'report.pdf',
                    'type'     => 'application/pdf',
                    'tmp_name' => $tmp,
                    'error'    => UPLOAD_ERR_OK,
                    'size'     => strlen($pdfContent)
                ]
            ]
        );

        $this->assert($res['http_code'] === 200, "PDF upload returned HTTP 200");
        $attachId = (int)($res['json']['attachment']['id'] ?? 0);
        $this->assert($attachId > 0, "PDF attachment ID valid");

        // Download as attachment
        $downRes = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/download_attachment.php'),
            $this->getSessionData($this->userBId),
            [],
            ['id' => (string)$attachId, 'download' => '1']
        );

        $this->assert($downRes['http_code'] === 200, "Download endpoint returned HTTP 200");
        if (!str_starts_with($downRes['body'], "%PDF-1.4")) {
            echo "DEBUG TEST 4 BODY: " . var_export(substr($downRes['body'], 0, 100), true) . "\n";
        }
        $this->assert(str_starts_with($downRes['body'], "%PDF-1.4"), "Downloaded content matches original PDF payload");
    }

    private function testVoiceAudioMessageUpload(): void
    {
        echo "--- 5. VOICE AUDIO MESSAGE UPLOAD ---\n";

        // Minimal valid 44-byte canonical PCM WAV header
        $wavContent = "RIFF" . pack('V', 36) . "WAVEfmt " . pack('V', 16) . pack('v', 1) . pack('v', 1) . pack('V', 8000) . pack('V', 16000) . pack('v', 2) . pack('v', 16) . "data" . pack('V', 0);
        $tmp = $this->createFakeFile('voice.wav', $wavContent);

        $res = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/upload_media.php'),
            $this->getSessionData($this->userAId),
            [
                'receiver_id' => (string)$this->userBId,
                'caption'     => '',
                'csrf_token'  => $this->csrfToken,
            ],
            [],
            [
                'file' => [
                    'name'     => 'voice_note.wav',
                    'type'     => 'audio/wav',
                    'tmp_name' => $tmp,
                    'error'    => UPLOAD_ERR_OK,
                    'size'     => strlen($wavContent)
                ]
            ]
        );

        if ($res['http_code'] !== 200) {
            echo "DEBUG TEST 5 RES: " . var_export($res, true) . "\n";
        }
        $this->assert($res['http_code'] === 200, "Voice message upload returned HTTP 200");
        $this->assert(($res['json']['message_type'] ?? '') === 'audio', "Message type classified as 'audio'");
    }

    private function testProhibitedExecutableUploadBlocked(): void
    {
        echo "--- 6. PROHIBITED EXECUTABLE UPLOADS BLOCKED ---\n";

        $phpContent = "<?php phpinfo(); ?>";
        $tmp = $this->createFakeFile('shell.php', $phpContent);

        $res = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/upload_media.php'),
            $this->getSessionData($this->userAId),
            [
                'receiver_id' => (string)$this->userBId,
                'caption'     => 'Malicious file',
                'csrf_token'  => $this->csrfToken,
            ],
            [],
            [
                'file' => [
                    'name'     => 'shell.php',
                    'type'     => 'application/x-php',
                    'tmp_name' => $tmp,
                    'error'    => UPLOAD_ERR_OK,
                    'size'     => strlen($phpContent)
                ]
            ]
        );

        $this->assert($res['http_code'] === 400, "Direct .php upload rejected with HTTP 400");
    }

    private function testMimeSpoofingBlocked(): void
    {
        echo "--- 7. MIME SPOOFING & DOUBLE EXTENSION BLOCKED ---\n";

        // Double extension attack: "exploit.php.jpg"
        $phpContent = "<?php system(\$_GET['cmd']); ?>";
        $tmp = $this->createFakeFile('exploit.php.jpg', $phpContent);

        $res = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/upload_media.php'),
            $this->getSessionData($this->userAId),
            [
                'receiver_id' => (string)$this->userBId,
                'caption'     => 'Double ext',
                'csrf_token'  => $this->csrfToken,
            ],
            [],
            [
                'file' => [
                    'name'     => 'exploit.php.jpg',
                    'type'     => 'image/jpeg',
                    'tmp_name' => $tmp,
                    'error'    => UPLOAD_ERR_OK,
                    'size'     => strlen($phpContent)
                ]
            ]
        );

        $this->assert($res['http_code'] === 400, "Double-extension .php.jpg upload rejected with HTTP 400");
    }

    private function testUnauthorizedAttachmentAccessBlocked(): void
    {
        echo "--- 8. UNAUTHORIZED USER UPLOAD RESTRICTION ---\n";

        // User C (not friend with B) tries to upload to User B
        $pngBinary = base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==');
        $tmp = $this->createFakeFile('c_to_b.png', $pngBinary);

        $res = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/upload_media.php'),
            $this->getSessionData($this->userCId),
            [
                'receiver_id' => (string)$this->userBId,
                'caption'     => 'Illegal friend upload',
                'csrf_token'  => $this->csrfToken,
            ],
            [],
            [
                'file' => [
                    'name'     => 'photo.png',
                    'type'     => 'image/png',
                    'tmp_name' => $tmp,
                    'error'    => UPLOAD_ERR_OK,
                    'size'     => strlen($pngBinary)
                ]
            ]
        );

        $this->assert($res['http_code'] === 403, "Uploading to non-friend rejected with HTTP 403");
    }

    private function testDeleteMessageCleansUpAttachment(): void
    {
        echo "--- 9. DELETE MESSAGE CLEANS UP ATTACHMENTS ---\n";

        // Create an attachment from A to B
        $txtContent = "Temporary sensitive notes to delete";
        $tmp = $this->createFakeFile('notes.txt', $txtContent);

        $uploadRes = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/upload_media.php'),
            $this->getSessionData($this->userAId),
            [
                'receiver_id' => (string)$this->userBId,
                'caption'     => 'Sensitive notes',
                'csrf_token'  => $this->csrfToken,
            ],
            [],
            [
                'file' => [
                    'name'     => 'notes.txt',
                    'type'     => 'text/plain',
                    'tmp_name' => $tmp,
                    'error'    => UPLOAD_ERR_OK,
                    'size'     => strlen($txtContent)
                ]
            ]
        );

        $msgId = (int)($uploadRes['json']['id'] ?? 0);
        $attachId = (int)($uploadRes['json']['attachment']['id'] ?? 0);

        // Fetch physical storage path
        $stmt = $this->conn->prepare("SELECT storage_path FROM message_attachments WHERE id = ?");
        $stmt->bind_param("i", $attachId);
        $stmt->execute();
        $relPath = $stmt->get_result()->fetch_assoc()['storage_path'];
        $stmt->close();

        $rootDir = realpath(__DIR__ . '/..');
        $storedPhysicalFile = $rootDir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relPath);
        $this->assert(file_exists($storedPhysicalFile), "File exists before deletion");

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

        $this->assert(($delRes['json']['success'] ?? false) === true, "Delete for everyone succeeded");

        // Verify physical file is unlinked
        $this->assert(!file_exists($storedPhysicalFile), "Physical attachment file safely unlinked after delete");

        // Verify download endpoint now returns 404
        $downRes = $this->executeSubprocess(
            realpath(__DIR__ . '/../php/download_attachment.php'),
            $this->getSessionData($this->userBId),
            [],
            ['id' => (string)$attachId]
        );
        $this->assert($downRes['http_code'] === 404, "Attempting to download deleted attachment returns HTTP 404");
    }
}

$test = new Phase7MediaMessagingBackendTest($conn);
$test->run();
