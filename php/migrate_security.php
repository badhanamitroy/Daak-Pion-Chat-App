<?php
// migrate_security.php — Idempotent security database migration for DaakPion
// Resolves DP-VULN-05: Restrict execution strictly to CLI environment.
if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    header('Content-Type: text/plain');
    exit("Access Denied: Migration scripts can only be executed via the command-line interface (CLI).\n");
}

require_once __DIR__ . '/db_connect.php';


echo "Running DaakPion Security Schema Migration...\n";

// 1. Add columns to users table if they don't exist
$userCols = [];
$res = $conn->query("SHOW COLUMNS FROM users");
while ($r = $res->fetch_assoc()) {
    $userCols[] = strtolower($r['Field']);
}

$queries = [];

if (!in_array('password_version', $userCols)) {
    $queries[] = "ALTER TABLE users ADD COLUMN password_version INT NOT NULL DEFAULT 1";
}
if (!in_array('is_temporary_password', $userCols)) {
    $queries[] = "ALTER TABLE users ADD COLUMN is_temporary_password TINYINT(1) NOT NULL DEFAULT 0";
}
if (!in_array('temp_password_expires_at', $userCols)) {
    $queries[] = "ALTER TABLE users ADD COLUMN temp_password_expires_at DATETIME NULL";
}
if (!in_array('two_factor_enabled', $userCols)) {
    $queries[] = "ALTER TABLE users ADD COLUMN two_factor_enabled TINYINT(1) NOT NULL DEFAULT 1";
} else {
    $queries[] = "ALTER TABLE users MODIFY COLUMN two_factor_enabled TINYINT(1) NOT NULL DEFAULT 1";
}
if (!in_array('last_activity_at', $userCols)) {
    $queries[] = "ALTER TABLE users ADD COLUMN last_activity_at DATETIME NULL, ADD INDEX idx_last_activity (last_activity_at)";
}

$queries[] = "UPDATE users SET two_factor_enabled = 1 WHERE two_factor_enabled = 0 OR two_factor_enabled IS NULL";

foreach ($queries as $q) {
    if ($conn->query($q)) {
        echo " Executed: $q\n";
    } else {
        echo " Error executing ($q): " . $conn->error . "\n";
    }
}

// 2. Create security_rate_limits table
$rateLimitTable = "CREATE TABLE IF NOT EXISTS security_rate_limits (
    rate_key VARCHAR(191) PRIMARY KEY,
    attempts INT NOT NULL DEFAULT 1,
    first_attempt_at INT NOT NULL,
    last_attempt_at INT NOT NULL,
    blocked_until INT NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

if ($conn->query($rateLimitTable)) {
    echo " Table security_rate_limits verified.\n";
} else {
    echo " Error with security_rate_limits: " . $conn->error . "\n";
}

// 3. Create security_audit_logs table
$auditTable = "CREATE TABLE IF NOT EXISTS security_audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,
    user_id INT NULL,
    identifier VARCHAR(191) NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent VARCHAR(255) NULL,
    status VARCHAR(20) NOT NULL,
    details TEXT NULL,
    created_at DATETIME NOT NULL,
    INDEX idx_audit_event (event_type),
    INDEX idx_audit_user (user_id),
    INDEX idx_audit_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

if ($conn->query($auditTable)) {
    echo " Table security_audit_logs verified.\n";
} else {
    echo " Error with security_audit_logs: " . $conn->error . "\n";
}

// 4. Create password_resets table
$resetTable = "CREATE TABLE IF NOT EXISTS password_resets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    INDEX idx_reset_token (token_hash),
    INDEX idx_reset_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

if ($conn->query($resetTable)) {
    echo " Table password_resets verified.\n";
} else {
    echo " Error with password_resets: " . $conn->error . "\n";
}

// 5. Create two_factor_otps table
$twoFactorTable = "CREATE TABLE IF NOT EXISTS two_factor_otps (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    otp_hash VARCHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    INDEX idx_otp_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

if ($conn->query($twoFactorTable)) {
    echo " Table two_factor_otps verified.\n";
} else {
    echo " Error with two_factor_otps: " . $conn->error . "\n";
}

// 6. Create persistent_logins table (Resolves Issue 2: Persistent Authentication)
$persistentTable = "CREATE TABLE IF NOT EXISTS persistent_logins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    selector VARCHAR(32) NOT NULL UNIQUE,
    validator_hash VARCHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME NULL,
    ip_address VARCHAR(45) NULL,
    user_agent VARCHAR(255) NULL,
    INDEX idx_persistent_selector (selector),
    INDEX idx_persistent_user (user_id),
    INDEX idx_persistent_expires (expires_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

if ($conn->query($persistentTable)) {
    echo " Table persistent_logins verified.\n";
} else {
    echo " Error with persistent_logins: " . $conn->error . "\n";
}

echo "Migration completed successfully!\n";

