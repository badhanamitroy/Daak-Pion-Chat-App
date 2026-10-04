<?php
// migrate_chat_phase1.php — Idempotent migration for Phase 1 chat enhancements
declare(strict_types=1);

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    exit("Access Denied: Migration scripts can only be executed via CLI.\n");
}

require_once __DIR__ . '/db_connect.php';

echo "Running DaakPion Chat Phase 1 Migration...\n";

// 1. Inspect existing columns in messages table
$msgCols = [];
$res = $conn->query("SHOW COLUMNS FROM messages");
while ($r = $res->fetch_assoc()) {
    $msgCols[] = strtolower($r['Field']);
}

$queries = [];

if (!in_array('reply_to_id', $msgCols)) {
    $queries[] = "ALTER TABLE messages ADD COLUMN reply_to_id INT(11) NULL DEFAULT NULL AFTER message, ADD INDEX idx_reply_to (reply_to_id)";
}

if (!in_array('client_message_id', $msgCols)) {
    $queries[] = "ALTER TABLE messages ADD COLUMN client_message_id VARCHAR(64) NULL DEFAULT NULL AFTER reply_to_id, ADD UNIQUE INDEX uq_client_msg_id (client_message_id)";
}

if (!in_array('is_delivered', $msgCols)) {
    $queries[] = "ALTER TABLE messages ADD COLUMN is_delivered TINYINT(1) NOT NULL DEFAULT 0 AFTER is_read, ADD INDEX idx_is_delivered (is_delivered)";
}

if (!in_array('deleted_by_sender', $msgCols)) {
    $queries[] = "ALTER TABLE messages ADD COLUMN deleted_by_sender TINYINT(1) NOT NULL DEFAULT 0 AFTER is_delivered";
}

if (!in_array('deleted_by_receiver', $msgCols)) {
    $queries[] = "ALTER TABLE messages ADD COLUMN deleted_by_receiver TINYINT(1) NOT NULL DEFAULT 0 AFTER deleted_by_sender";
}

if (!in_array('is_deleted_all', $msgCols)) {
    $queries[] = "ALTER TABLE messages ADD COLUMN is_deleted_all TINYINT(1) NOT NULL DEFAULT 0 AFTER deleted_by_receiver";
}

if (!in_array('message_type', $msgCols)) {
    $queries[] = "ALTER TABLE messages ADD COLUMN message_type ENUM('text', 'image', 'video', 'audio', 'document') NOT NULL DEFAULT 'text' AFTER is_deleted_all";
}

// Add composite index for unread counts if not present
$indexRes = $conn->query("SHOW INDEX FROM messages WHERE Key_name = 'idx_receiver_unread_sender'");
if ($indexRes->num_rows === 0) {
    $queries[] = "ALTER TABLE messages ADD INDEX idx_receiver_unread_sender (receiver_id, is_read, sender_id)";
}

foreach ($queries as $q) {
    if ($conn->query($q)) {
        echo " [OK] Executed: $q\n";
    } else {
        echo " [ERR] Error executing ($q): " . $conn->error . "\n";
    }
}

// 2. Create typing_indicators table
$typingSql = "CREATE TABLE IF NOT EXISTS typing_indicators (
    user_id INT NOT NULL,
    friend_id INT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, friend_id),
    INDEX idx_typing_updated (updated_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (friend_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

if ($conn->query($typingSql)) {
    echo " [OK] Table typing_indicators verified.\n";
} else {
    echo " [ERR] Error with typing_indicators: " . $conn->error . "\n";
}

echo "Phase 1 Migration completed successfully!\n";
