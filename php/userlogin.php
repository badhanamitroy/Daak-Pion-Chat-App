<?php
// userlogin.php — Hardened authentication endpoint
declare(strict_types=1);

require_once __DIR__ . '/bootstrap_security.php';

use Daakpion\Security\CryptoService;
use Daakpion\Security\SessionManager;
use Daakpion\Security\RateLimiter;
use Daakpion\Security\AuditLogger;
use Daakpion\Security\TwoFactorService;
use Daakpion\Security\PersistentAuthService;

header('X-Content-Type-Options: nosniff');

$isAjax = (!empty($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false)
       || (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest');

function respond(bool $success, string $message, ?string $redirect = null, array $extra = []): void {
    global $isAjax;
    if ($isAjax) {
        header('Content-Type: application/json');
        if (!$success) {
            http_response_code(401);
        }
        echo json_encode(array_merge([
            'success'  => $success,
            'message'  => $message,
            'redirect' => $redirect
        ], $extra));
        exit;
    }

    if ($success && $redirect) {
        header("Location: {$redirect}");
        exit;
    }

    // Direct POST fallback: redirect back to index.html with generic error parameter
    header("Location: ../index.html?error=" . urlencode($message));
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond(false, "Invalid request method.");
}

$email      = trim($_POST['email'] ?? '');
$password   = (string)($_POST['password'] ?? '');
$rememberMe = !empty($_POST['remember_me']) && ($_POST['remember_me'] === '1' || $_POST['remember_me'] === 'on' || $_POST['remember_me'] === true);


$clientIp    = RateLimiter::getClientIp();
$rateLimiter = new RateLimiter($conn);
$logger      = new AuditLogger($conn);

// ── 1. Brute-Force Rate Limiting (IP & Email dimensions) ──────────────────────
$ipKey    = RateLimiter::buildKey('login_ip', $clientIp);
$emailKey = RateLimiter::buildKey('login_email', $email !== '' ? $email : 'unknown');

$ipBlocked    = $rateLimiter->isBlocked($ipKey, $retryAfterIp);
$emailBlocked = $rateLimiter->isBlocked($emailKey, $retryAfterEmail);

if ($ipBlocked || $emailBlocked) {
    $retryAfter = max($retryAfterIp, $retryAfterEmail);
    $logger->log('LOGIN_RATE_LIMITED', 'BLOCKED', null, $email, [
        'retry_after' => $retryAfter,
        'ip'          => $clientIp
    ]);
    respond(false, "Too many failed attempts. Please wait {$retryAfter} seconds before trying again.");
}

// ── 2. Input Validation ───────────────────────────────────────────────────────
if (empty($email) || empty($password)) {
    respond(false, "Invalid email or password.");
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    CryptoService::dummyVerify();
    $rateLimiter->hit($ipKey, 10, 900, 900);
    $logger->log('LOGIN_FAILURE', 'INVALID_EMAIL_FORMAT', null, $email);
    respond(false, "Invalid email or password.");
}

// ── 3. User Lookup (Prepared Statement) ───────────────────────────────────────
$stmt = $conn->prepare("SELECT id, fname, lname, email, password, password_version, is_temporary_password, temp_password_expires_at, two_factor_enabled FROM users WHERE email = ?");
if (!$stmt) {
    respond(false, "Authentication service temporarily unavailable.");
}

$stmt->bind_param("s", $email);
$stmt->execute();
$result = $stmt->get_result();
$user   = $result->fetch_assoc();
$stmt->close();

// ── 4. Nonexistent Account Defense (Constant-Time Dummy Verification) ─────────
if (!$user) {
    // Constant-time execution prevents timing attacks & enumeration
    CryptoService::dummyVerify();
    $rateLimiter->hit($ipKey, 10, 900, 900);
    $rateLimiter->hit($emailKey, 5, 900, 900);
    $logger->log('LOGIN_FAILURE', 'USER_NOT_FOUND', null, $email);
    respond(false, "Invalid email or password.");
}

$userId = (int)$user['id'];

// ── 5. Password Verification & Migration ──────────────────────────────────────
$needsRehash = false;
$isValid = CryptoService::verifyPassword($password, $user['password'], $needsRehash);

if (!$isValid) {
    $rateLimiter->hit($ipKey, 10, 900, 900);
    $rateLimiter->hit($emailKey, 5, 900, 900);
    $logger->log('LOGIN_FAILURE', 'BAD_CREDENTIALS', $userId, $email);
    respond(false, "Invalid email or password.");
}

// ── 6. Check Temporary Password Expiration ───────────────────────────────────
if (!empty($user['is_temporary_password']) && !empty($user['temp_password_expires_at'])) {
    if (strtotime($user['temp_password_expires_at']) < time()) {
        $logger->log('LOGIN_FAILURE', 'TEMP_PASSWORD_EXPIRED', $userId, $email);
        respond(false, "This temporary password has expired. Please reset your password.");
    }
}

// ── 7. Password Rehashing / Legacy Bcrypt Migration ───────────────────────────
// If user has a legacy bcrypt hash or Argon2id parameters need updating, rehash now!
if ($needsRehash) {
    $newHash = CryptoService::hashPassword($password);
    $updHash = $conn->prepare("UPDATE users SET password = ? WHERE id = ?");
    if ($updHash) {
        $updHash->bind_param("si", $newHash, $userId);
        $updHash->execute();
        $updHash->close();
        $logger->log('PASSWORD_REHASHED', 'MIGRATED_TO_ARGON2ID', $userId, $email);
    }
}

// Clear rate limits on successful password verification
$rateLimiter->clear($ipKey);
$rateLimiter->clear($emailKey);

// ── 8. 2FA / OTP Verification Flow ───────────────────────────────────────────
if (!empty($user['two_factor_enabled'])) {
    $twoFactor = new TwoFactorService($conn, $logger);
    $rawOtp = $twoFactor->issueOtp($userId, $email);

    // Store pre-auth state in session (user is NOT authenticated yet)
    $_SESSION['2fa_preauth_user_id']     = $userId;
    $_SESSION['2fa_preauth_email']       = $email;
    $_SESSION['2fa_preauth_user']        = $user;
    $_SESSION['2fa_preauth_remember_me'] = $rememberMe;

    // Dispatch OTP email via centralized MailService using real Gmail SMTP
    $mailService = new \Daakpion\Security\MailService($conn, $logger);
    $userName = trim(($user['fname'] ?? '') . ' ' . ($user['lname'] ?? ''));
    $emailSent = $mailService->sendTwoFactorOtp($email, $userName, $rawOtp, $userId);

    if (!$emailSent) {
        $_SESSION['2fa_mail_delivery_failed'] = true;
    }

    // In development mode, allow dev secrets if enabled
    $extra = [];
    if (\Daakpion\Security\Environment::allowDevSecrets()) {
        $extra['dev_otp'] = $rawOtp;
    }

    // Redirect to 2FA challenge. Browser/client NEVER receives the raw OTP in production.
    respond(true, "Two-factor verification required.", "verify_2fa.php", $extra);
}

// ── 9. Finalize Authenticated Session (When 2FA is not enabled) ───────────────
$isTemp = !empty($user['is_temporary_password']);

// Update user status and activity timestamp (Resolves DP-P4-009)
$updStatus = $conn->prepare("UPDATE users SET status = 'Active now', last_activity_at = NOW() WHERE id = ?");
if ($updStatus) {
    $updStatus->bind_param("i", $userId);
    $updStatus->execute();
    $updStatus->close();
}

SessionManager::loginUser($user, $isTemp);

// Establish persistent login credential if requested
if ($rememberMe) {
    PersistentAuthService::issueToken($userId, $conn);
}

$logger->log('LOGIN_SUCCESS', 'SUCCESS', $userId, $email, [
    'is_temporary' => $isTemp
]);

if ($isTemp) {
    $logger->log('TEMPORARY_PASSWORD_CONSUMED', 'RESTRICTED_SESSION_STARTED', $userId, $email);
    respond(true, "Temporary login. Password change required.", "force_change_password.php");
}

respond(true, "Login successful.", "user-profile.php");

