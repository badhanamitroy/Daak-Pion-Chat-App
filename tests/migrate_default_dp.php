<?php
require __DIR__ . '/../php/db_connect.php';

// 1. Update column default to 'dp.png'
$alterSql = "ALTER TABLE users MODIFY COLUMN Dp varchar(256) NOT NULL DEFAULT 'dp.png'";
if ($conn->query($alterSql)) {
    echo "[SUCCESS] Altered users table Dp column default to 'dp.png'\n";
} else {
    echo "[ERROR] Failed to alter Dp column: " . $conn->error . "\n";
}

// 2. Update existing records without a dp
$updateSql = "UPDATE users SET Dp = 'dp.png' WHERE Dp = '' OR Dp IS NULL OR Dp = 'ProfilePics/default.jpg'";
if ($conn->query($updateSql)) {
    echo "[SUCCESS] Updated existing empty Dp rows to 'dp.png' (Affected: " . $conn->affected_rows . ")\n";
} else {
    echo "[ERROR] Failed to update empty Dp rows: " . $conn->error . "\n";
}

// 3. Verify all records in users table
$res = $conn->query("SELECT id, fname, lname, Dp FROM users");
echo "\n--- Current Users Table State ---\n";
while ($row = $res->fetch_assoc()) {
    echo "ID {$row['id']}: {$row['fname']} {$row['lname']} -> Dp: '{$row['Dp']}'\n";
}
