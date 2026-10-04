<?php
// migrate_chat_phase2.php — Database migration for Phase 2 media messaging
declare(strict_types=1);

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    exit("Access Denied: Migration scripts can only be executed via CLI.\n");
}

require_once __DIR__ . '/db_connect.php';

echo "Running DaakPion Chat Phase 2 Migration...\n";

// 1. Create message_attachments table
$attachSql = "CREATE TABLE IF NOT EXISTS message_attachments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    message_id INT NOT NULL,
    uploader_id INT NOT NULL,
    original_name VARCHAR(255) NOT NULL,
    stored_name VARCHAR(255) NOT NULL UNIQUE,
    mime_type VARCHAR(100) NOT NULL,
    extension VARCHAR(16) NOT NULL,
    size_bytes BIGINT NOT NULL,
    media_type ENUM('image', 'video', 'audio', 'document') NOT NULL,
    storage_path VARCHAR(255) NOT NULL,
    thumbnail_path VARCHAR(255) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at DATETIME NULL,
    INDEX idx_attach_message (message_id),
    INDEX idx_attach_uploader (uploader_id),
    INDEX idx_attach_media_type (media_type),
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
    FOREIGN KEY (uploader_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

if ($conn->query($attachSql)) {
    echo " [OK] Table message_attachments verified.\n";
} else {
    echo " [ERR] Error creating message_attachments: " . $conn->error . "\n";
}

// 2. Create physical storage directories
$baseUploadDir = realpath(__DIR__ . '/..') . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . 'message_media';
$subDirs = ['images', 'videos', 'documents', 'audio', 'thumbnails'];

if (!is_dir($baseUploadDir)) {
    @mkdir($baseUploadDir, 0750, true);
}

foreach ($subDirs as $sd) {
    $path = $baseUploadDir . DIRECTORY_SEPARATOR . $sd;
    if (!is_dir($path)) {
        @mkdir($path, 0750, true);
        echo " [OK] Created directory: uploads/message_media/{$sd}\n";
    }
}

// 3. Create protective .htaccess in uploads directory
$uploadHtaccess = realpath(__DIR__ . '/..') . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . '.htaccess';
$htaccessContent = <<<HTACCESS
# DaakPion — Strict Uploads Directory Protection
# Prevents execution of any server-side code or scripts
Options -Indexes -ExecCGI

<FilesMatch "\.(php.*|phtml|phar|cgi|pl|sh|py|asp|aspx)$">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order deny,allow
        Deny from all
    </IfModule>
</FilesMatch>

<IfModule mod_mime.c>
    RemoveHandler .php .phtml .phar .cgi .pl
    RemoveType .php .phtml .phar .cgi .pl
</IfModule>
HTACCESS;

file_put_contents($uploadHtaccess, $htaccessContent);
echo " [OK] Protective .htaccess written in uploads/\n";

echo "Phase 2 Migration completed successfully!\n";
