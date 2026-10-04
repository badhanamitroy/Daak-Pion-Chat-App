<?php
require_once __DIR__ . '/../php/bootstrap_security.php';

use Daakpion\Security\CryptoService;

$otp = "123456";
$otpHash = CryptoService::hashOtp($otp);
$now = date('Y-m-d H:i:s');
$expiresAt = date('Y-m-d H:i:s', time() + 3600);

$stmt = $conn->prepare("UPDATE two_factor_otps SET otp_hash = ?, expires_at = ?, attempts = 0, used_at = NULL WHERE user_id = 445 ORDER BY id DESC LIMIT 1");
$stmt->bind_param("ss", $otpHash, $expiresAt);
$stmt->execute();
echo "Updated OTP for user 445 to 123456 (affected rows: " . $stmt->affected_rows . ")\n";
$stmt->close();
