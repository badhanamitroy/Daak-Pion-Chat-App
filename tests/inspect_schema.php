<?php
require_once __DIR__ . '/../php/db_connect.php';

echo "=== TABLES ===\n";
$res = $conn->query("SHOW TABLES");
while ($row = $res->fetch_row()) {
    echo $row[0] . "\n";
}

echo "\n=== MESSAGES SCHEMA ===\n";
$res = $conn->query("DESCRIBE messages");
while ($row = $res->fetch_assoc()) {
    echo "{$row['Field']} | {$row['Type']} | Null:{$row['Null']} | Key:{$row['Key']} | Default:{$row['Default']}\n";
}

echo "\n=== MESSAGES INDEXES ===\n";
$res = $conn->query("SHOW INDEX FROM messages");
while ($row = $res->fetch_assoc()) {
    echo "{$row['Key_name']} | {$row['Column_name']} | Seq:{$row['Seq_in_index']}\n";
}

echo "\n=== SAMPLE MESSAGES COUNT ===\n";
$res = $conn->query("SELECT COUNT(*) FROM messages");
echo "Count: " . $res->fetch_row()[0] . "\n";
