<?php
require_once __DIR__ . '/../php/bootstrap_security.php';

$res = $conn->query("SELECT id, sender_id, receiver_id, message, sent_at FROM messages");
echo "Total messages: " . $res->num_rows . "\n";
while ($r = $res->fetch_assoc()) {
    $decrypted = \Daakpion\Security\CryptoService::decryptMessage($r['message']);
    echo "Message #{$r['id']}: " . ($decrypted !== null ? "DECRYPT_SUCCESS: " . substr($decrypted, 0, 30) : "DECRYPT_FAIL") . "\n";
}
