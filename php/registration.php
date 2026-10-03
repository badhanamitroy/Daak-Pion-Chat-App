<?php
// registration.php — Hardened user registration endpoint
declare(strict_types=1);

require_once __DIR__ . '/bootstrap_security.php';

use Daakpion\Security\CryptoService;
use Daakpion\Security\PasswordPolicy;
use Daakpion\Security\RateLimiter;
use Daakpion\Security\AuditLogger;

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit(json_encode(['error' => 'Invalid request method']));
}

$fname    = trim($_POST['fname'] ?? '');
$lname    = trim($_POST['lname'] ?? '');
$email    = trim($_POST['email'] ?? '');
$password = (string)($_POST['password'] ?? '');

$clientIp    = RateLimiter::getClientIp();
$rateLimiter = new RateLimiter($conn);
$logger      = new AuditLogger($conn);

// ── 1. Rate Limiting: Max 5 registration attempts per IP per hour ─────────────
$regKey = RateLimiter::buildKey('register_ip', $clientIp);
$hit = $rateLimiter->hit($regKey, 5, 3600, 3600);
if ($hit['blocked']) {
    $logger->log('REGISTRATION_RATE_LIMITED', 'BLOCKED', null, $email, ['ip' => $clientIp]);
    http_response_code(429);
    exit(json_encode(['error' => 'Too many accounts created from this IP. Please try again later.']));
}

// ── 2. Basic Field Validation ────────────────────────────────────────────────
if (empty($fname) || empty($lname) || empty($email) || empty($password)) {
    exit(json_encode(['error' => 'All input fields are required!']));
}

if (strlen($fname) > 80 || strlen($lname) > 80) {
    exit(json_encode(['error' => 'Name must be 80 characters or fewer.']));
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    exit(json_encode(['error' => 'This is not a valid email address.']));
}

// ── 3. Strict Password Policy Enforcement ────────────────────────────────────
$userContext = [
    'email' => $email,
    'fname' => $fname,
    'lname' => $lname,
];
$policy = PasswordPolicy::validate($password, $userContext);
if (!$policy['valid']) {
    exit(json_encode(['error' => implode(' ', $policy['errors'])]));
}

// ── 4. Check for Existing Email (Resolves DP-P3-008: Account Enumeration Defense) ─
$check = $conn->prepare("SELECT id FROM users WHERE email = ?");
$check->bind_param("s", $email);
$check->execute();
$check->store_result();
$alreadyExists = ($check->num_rows > 0);
$check->close();

if ($alreadyExists) {
    // Perform password hashing work to mitigate timing-based account enumeration oracle
    CryptoService::hashPassword($password);
    $logger->log('REGISTRATION_ATTEMPT_EXISTING', 'FAILED', null, $email);
    exit(json_encode([
        'error' => 'Unable to complete registration with the provided details. If you already have an account, please log in or reset your password.'
    ]));
}

// ── 5. Hash Password with HMAC-SHA256 Pepper and Argon2id ────────────────────
$hashedPassword = CryptoService::hashPassword($password);

// ── 6. Insert User Record ────────────────────────────────────────────────────
$stmt = $conn->prepare(
    "INSERT INTO users (fname, lname, email, password, status, Dp, Coverpic, password_version, is_temporary_password, two_factor_enabled) 
     VALUES (?, ?, ?, ?, 'Offline', '', '', 1, 0, 0)"
);
$stmt->bind_param("ssss", $fname, $lname, $email, $hashedPassword);

if ($stmt->execute()) {
    $newUserId = $conn->insert_id;
    $stmt->close();

    $logger->log('USER_REGISTERED', 'SUCCESS', $newUserId, $email);

    exit(json_encode(['success' => true]));
} else {
    $stmt->close();
    $logger->log('REGISTRATION_FAILED', 'DB_ERROR', null, $email);
    http_response_code(500);
    exit(json_encode(['error' => 'Registration failed. Please try again.']));
}
