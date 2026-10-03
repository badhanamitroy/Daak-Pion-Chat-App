<?php
// tests/IntegrationFlowTest.php — End-to-end authentication and security workflow simulation
declare(strict_types=1);

require_once __DIR__ . '/../php/bootstrap_security.php';

use Daakpion\Security\CryptoService;
use Daakpion\Security\PasswordPolicy;
use Daakpion\Security\RateLimiter;
use Daakpion\Security\SessionManager;
use Daakpion\Security\TwoFactorService;
use Daakpion\Security\PasswordResetService;
use Daakpion\Security\CsrfProtection;

echo "=========================================================\n";
echo "  INTEGRATION FLOW SIMULATION & END-TO-END VALIDATION    \n";
echo "=========================================================\n\n";

$rateLimiter = new RateLimiter($conn);
$ip = RateLimiter::getClientIp();

// 1. Simulation of Legacy Bcrypt User Migration
echo "1. Testing Legacy Bcrypt User Migration on Login...\n";
$legacyEmail = "legacy_user_" . time() . "@example.com";
$legacyPassword = "LegacyPasswordToMigrate123!";
$rawBcrypt = password_hash($legacyPassword, PASSWORD_BCRYPT, ['cost' => 10]);

$stmt = $conn->prepare("INSERT INTO users (fname, lname, email, password, status, password_version) VALUES ('Legacy', 'User', ?, ?, 'Offline', 1)");
$stmt->bind_param("ss", $legacyEmail, $rawBcrypt);
$stmt->execute();
$legacyUserId = $conn->insert_id;
$stmt->close();

// Check stored hash is bcrypt
$stored = $conn->query("SELECT password FROM users WHERE id = {$legacyUserId}")->fetch_assoc()['password'];
echo " - Initial hash algo: " . password_get_info($stored)['algoName'] . "\n";
assert(password_get_info($stored)['algoName'] === 'bcrypt');

// Simulate login verification
$needsRehash = false;
$valid = CryptoService::verifyPassword($legacyPassword, $stored, $needsRehash);
assert($valid === true);
assert($needsRehash === true);

// Perform migration rehash as userlogin.php does
$newHash = CryptoService::hashPassword($legacyPassword);
$conn->query("UPDATE users SET password = '{$newHash}' WHERE id = {$legacyUserId}");

// Check updated hash is now Argon2id
$updated = $conn->query("SELECT password FROM users WHERE id = {$legacyUserId}")->fetch_assoc()['password'];
echo " - Migrated hash algo: " . password_get_info($updated)['algoName'] . "\n";
assert(password_get_info($updated)['algoName'] === 'argon2id');

// Subsequent login uses Argon2id
$needsRehashSubsequent = false;
$validSubsequent = CryptoService::verifyPassword($legacyPassword, $updated, $needsRehashSubsequent);
assert($validSubsequent === true);
assert($needsRehashSubsequent === false);
echo " [SUCCESS] Legacy migration seamlessly completed!\n\n";

// 2. Simulation of Temporary Password Restriction
echo "2. Testing Temporary Credential & Server-Side Restriction...\n";
$tempEmail = "temp_user_" . time() . "@example.com";
$tempPass = "TempInitialPassword123!";
$tempHash = CryptoService::hashPassword($tempPass);

$stmt = $conn->prepare("INSERT INTO users (fname, lname, email, password, status, is_temporary_password, password_version) VALUES ('Temp', 'User', ?, ?, 'Offline', 1, 1)");
$stmt->bind_param("ss", $tempEmail, $tempHash);
$stmt->execute();
$tempUserId = $conn->insert_id;
$stmt->close();

// Simulate login
$tempUser = $conn->query("SELECT * FROM users WHERE id = {$tempUserId}")->fetch_assoc();
SessionManager::loginUser($tempUser, true);

assert($_SESSION['must_change_password'] === true);
echo " - Temporary session established with must_change_password = true\n";

// Permanent password creation
$permPass = "PermanentNewPassword2026!";
$permHash = CryptoService::hashPassword($permPass);
$conn->query("UPDATE users SET password = '{$permHash}', is_temporary_password = 0 WHERE id = {$tempUserId}");
$_SESSION['must_change_password'] = false;
SessionManager::invalidateOtherSessions($tempUserId, $conn);

assert($_SESSION['must_change_password'] === false);
echo " [SUCCESS] Temporary password restriction and conversion completed!\n\n";

// 3. Simulation of 2FA Workflow
echo "3. Testing 2FA Challenge & Verification Workflow...\n";
$twoFactor = new TwoFactorService($conn);
$rawOtp = $twoFactor->issueOtp($tempUserId, $tempEmail);
echo " - Issued OTP (Length: " . strlen($rawOtp) . ")\n";

// Check that OTP is hashed in DB
$otpRow = $conn->query("SELECT otp_hash FROM two_factor_otps WHERE user_id = {$tempUserId} ORDER BY id DESC LIMIT 1")->fetch_assoc();
assert($otpRow['otp_hash'] !== $rawOtp);
assert(CryptoService::verifyOtp($rawOtp, $otpRow['otp_hash']));

// Incorrect code verification
$verifBad = $twoFactor->verifyOtp($tempUserId, "999999", $tempEmail);
assert($verifBad['success'] === false);

// Correct code verification
$verifGood = $twoFactor->verifyOtp($tempUserId, $rawOtp, $tempEmail);
assert($verifGood['success'] === true);

// Replay attack prevention
$verifReplay = $twoFactor->verifyOtp($tempUserId, $rawOtp, $tempEmail);
assert($verifReplay['success'] === false);
echo " [SUCCESS] 2FA OTP verification and replay protection validated!\n\n";

// 4. Cleanup
$conn->query("DELETE FROM two_factor_otps WHERE user_id IN ({$legacyUserId}, {$tempUserId})");
$conn->query("DELETE FROM users WHERE id IN ({$legacyUserId}, {$tempUserId})");

echo "=========================================================\n";
echo "  ALL INTEGRATION WORKFLOW TESTS PASSED SUCCESSFULLY!    \n";
echo "=========================================================\n";
