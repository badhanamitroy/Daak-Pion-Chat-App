<?php
require_once __DIR__ . '/../php/db_connect.php';

// Add friendship between 445 and 443
$conn->query("INSERT INTO friends (user1_id, user2_id, friends_since, status) VALUES (445, 443, NOW(), 'active') ON DUPLICATE KEY UPDATE status='active'");
$conn->query("INSERT INTO friends (user1_id, user2_id, friends_since, status) VALUES (443, 445, NOW(), 'active') ON DUPLICATE KEY UPDATE status='active'");
echo "Friendship active between 445 and 443\n";
