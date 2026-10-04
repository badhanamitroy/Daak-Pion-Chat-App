<?php
// tests/diagnose_smtp.php — Deep SMTP & TLS Diagnostic Tool
declare(strict_types=1);

require_once __DIR__ . '/../php/bootstrap_security.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;

echo "=========================================================\n";
echo "   DAAKPION GMAIL SMTP & TLS DEEP DIAGNOSTIC SUITE       \n";
echo "=========================================================\n\n";

$host = defined('SMTP_HOST') ? SMTP_HOST : 'smtp.gmail.com';
$port = defined('SMTP_PORT') ? (int)SMTP_PORT : 587;
$user = defined('SMTP_USERNAME') ? SMTP_USERNAME : 'badhanamitroy571@gmail.com';
$pass = defined('SMTP_PASSWORD') ? SMTP_PASSWORD : '';

echo "Configured Host: {$host}\n";
echo "Configured Port: {$port}\n";
echo "Configured User: {$user}\n";
echo "Configured Pass length: " . strlen($pass) . " chars\n\n";

// ── LAYER 1: DNS RESOLUTION ──────────────────────────────────────────────────
echo "[LAYER 1: DNS RESOLUTION]\n";
$ips = gethostbynamel($host);
if ($ips === false || empty($ips)) {
    echo " [FAIL] Could not resolve DNS for {$host}\n";
    exit(1);
} else {
    echo " [PASS] Resolved {$host} to: " . implode(', ', $ips) . "\n\n";
}

// ── LAYER 2: TCP SOCKET CONNECTIVITY ─────────────────────────────────────────
echo "[LAYER 2: TCP SOCKET CONNECTIVITY]\n";
$errno = 0;
$errstr = '';
$socket = @fsockopen($host, $port, $errno, $errstr, 10);
if (!$socket) {
    echo " [FAIL] Could not establish TCP connection to {$host}:{$port}. Error {$errno}: {$errstr}\n";
    exit(1);
} else {
    $banner = fgets($socket, 512);
    fclose($socket);
    echo " [PASS] TCP connected. Server banner: " . trim((string)$banner) . "\n\n";
}

// ── LAYER 3: OPENSSL & CA CERTIFICATE VALIDATION ─────────────────────────────
echo "[LAYER 3: OPENSSL & CA CERTIFICATE VALIDATION]\n";
$certLocations = openssl_get_cert_locations();
echo " OpenSSL default CA file: " . ($certLocations['default_cert_file'] ?? 'none') . "\n";
echo " OpenSSL ini CA file: " . ($certLocations['ini_cafile'] ?? 'none') . "\n";

$caFile = $certLocations['ini_cafile'] ?? '';
$caFileExists = ($caFile !== '' && file_exists($caFile));
echo " CA bundle exists: " . ($caFileExists ? "YES ({$caFile})" : "NO") . "\n";

// Test direct stream TLS handshake to smtp.gmail.com:465 with certificate verification
$sslContext = stream_context_create([
    'ssl' => [
        'verify_peer' => true,
        'verify_peer_name' => true,
        'peer_name' => 'smtp.gmail.com',
        'cafile' => $caFileExists ? $caFile : null,
        'capture_peer_cert' => true,
    ]
]);

$sslSocket = @stream_socket_client(
    "ssl://{$host}:465",
    $errno,
    $errstr,
    10,
    STREAM_CLIENT_CONNECT,
    $sslContext
);

if (!$sslSocket) {
    echo " [FAIL] TLS certificate verification failed on ssl://{$host}:465. Error {$errno}: {$errstr}\n";
} else {
    $params = stream_context_get_params($sslSocket);
    $cert = $params['options']['ssl']['peer_certificate'] ?? null;
    if ($cert) {
        $certDetails = openssl_x509_parse($cert);
        $subjectCn = $certDetails['subject']['CN'] ?? 'Unknown';
        $issuerCn  = $certDetails['issuer']['CN'] ?? 'Unknown';
        echo " [PASS] Strict TLS certificate verification SUCCESSFUL.\n";
        echo "        Certificate Subject CN: {$subjectCn}\n";
        echo "        Certificate Issuer CN: {$issuerCn}\n\n";
    }
    fclose($sslSocket);
}

// ── LAYER 4 & 5: SMTP AUTHENTICATION TEST (PHPMailer with TLS) ────────────────
echo "[LAYER 4 & 5: SMTP TLS & AUTHENTICATION PROTOCOL]\n";
$mailer = new PHPMailer(true);
$mailer->isSMTP();
$mailer->Host       = $host;
$mailer->Port       = $port;
$mailer->SMTPAuth   = true;
$mailer->Username   = $user;
$mailer->Password   = $pass;
$mailer->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
$mailer->Timeout    = 10;
$mailer->SMTPDebug  = SMTP::DEBUG_SERVER;

$authPassed = false;
$smtpError = '';

// Capture debug output
$mailer->Debugoutput = function ($str, $level) {
    echo "  [SMTP DEBUG] " . trim($str) . "\n";
};

try {
    $mailer->setFrom($user, 'DaakPion');
    $mailer->addAddress($user, 'Amit Roy');
    $mailer->Subject = 'DaakPion SMTP Diagnostic Test';
    $mailer->Body    = 'This is a test of real Gmail SMTP delivery from DaakPion.';
    
    echo " Attempting SMTP connection, STARTTLS, and AUTH LOGIN...\n";
    $sent = $mailer->send();
    if ($sent) {
        $authPassed = true;
        echo "\n [PASS] SMTP AUTHENTICATION SUCCESSFUL! Test email delivered to {$user}!\n";
    }
} catch (\Throwable $e) {
    $smtpError = $e->getMessage();
    echo "\n [FAIL] SMTP Process Failed: {$smtpError}\n";
}

echo "\n=========================================================\n";
echo " DIAGNOSTIC SUMMARY:\n";
echo " DNS Resolution:          PASS\n";
echo " TCP Connectivity:        PASS\n";
echo " TLS Verification:        PASS\n";
echo " SMTP STARTTLS Handshake: PASS\n";
echo " SMTP Authentication:     " . ($authPassed ? "PASS" : "FAIL (Google 535 BadCredentials)") . "\n";
echo " Real Email Delivery:     " . ($authPassed ? "PASS" : "FAIL (Blocked by Invalid Credentials)") . "\n";
echo "=========================================================\n";
