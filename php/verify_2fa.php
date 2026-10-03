<?php
// verify_2fa.php — Two-factor verification challenge endpoint
declare(strict_types=1);

require_once __DIR__ . '/bootstrap_security.php';

use Daakpion\Security\TwoFactorService;
use Daakpion\Security\SessionManager;
use Daakpion\Security\AuditLogger;
use Daakpion\Security\CsrfProtection;
use Daakpion\Security\RateLimiter;

$userId = (int)($_SESSION['2fa_preauth_user_id'] ?? 0);
$email  = (string)($_SESSION['2fa_preauth_email'] ?? '');
$user   = $_SESSION['2fa_preauth_user'] ?? null;

if ($userId <= 0 || !$user) {
    header("Location: ../index.html");
    exit;
}

$twoFactor   = new TwoFactorService($conn);
$logger      = new AuditLogger($conn);
$rateLimiter = new RateLimiter($conn);

$error   = null;
$message = null;
$devOtp  = null;

// Handle Resend OTP action
if (isset($_POST['resend_otp'])) {
    if (!CsrfProtection::validateToken($_POST['csrf_token'] ?? '')) {
        $error = "Security token mismatch.";
    } else {
        $resendKey = RateLimiter::buildKey('otp_resend', (string)$userId);
        $resendHit = $rateLimiter->hit($resendKey, 1, 60, 60);

        if ($resendHit['blocked']) {
            $error = "Please wait {$resendHit['retryAfter']} seconds before requesting a new code.";
        } else {
            $rawOtp = $twoFactor->issueOtp($userId, $email);
            $message = "A new verification code has been sent.";
            if (\Daakpion\Security\Environment::allowDevSecrets()) {
                $devOtp = $rawOtp;
            }
        }
    }
}

// Handle OTP Verification submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['verify_otp'])) {
    if (!CsrfProtection::validateToken($_POST['csrf_token'] ?? '')) {
        $error = "Security token mismatch.";
    } else {
        $otp = trim($_POST['otp'] ?? '');
        $res = $twoFactor->verifyOtp($userId, $otp, $email);

        if ($res['success']) {
            // Clear pre-auth session state
            unset($_SESSION['2fa_preauth_user_id'], $_SESSION['2fa_preauth_email'], $_SESSION['2fa_preauth_user']);

            // Update user status and activity timestamp (Resolves DP-P4-009)
            $upd = $conn->prepare("UPDATE users SET status = 'Active now', last_activity_at = NOW() WHERE id = ?");
            $upd->bind_param("i", $userId);
            $upd->execute();
            $upd->close();

            $isTemp = !empty($user['is_temporary_password']);
            SessionManager::loginUser($user, $isTemp);

            $logger->log('LOGIN_SUCCESS', '2FA_COMPLETED', $userId, $email);

            if ($isTemp) {
                header("Location: force_change_password.php");
            } else {
                header("Location: chatboard.php");
            }
            exit;
        } else {
            $error = $res['error'] ?? "Verification failed.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="dark">
  <title>Two-Factor Authentication — DaakPion</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="../Register.css?v=2.0">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" crossorigin="anonymous">
  <style>
    body {
      background-color: #18191a;
      color: #e4e6eb;
      font-family: 'Inter', sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      box-sizing: border-box;
    }
    .otp-card {
      background-color: #242526;
      border: 1px solid #3a3b3c;
      border-radius: 12px;
      padding: 32px;
      width: 100%;
      max-width: 440px;
      box-shadow: 0 12px 28px rgba(0,0,0,0.35);
    }
    .otp-card h1 {
      font-size: 22px;
      margin-bottom: 8px;
      color: #e4e6eb;
    }
    .otp-card p.subtitle {
      font-size: 14px;
      color: #b0b3b8;
      margin-bottom: 24px;
      line-height: 1.5;
    }
    .alert-banner {
      background-color: rgba(240, 40, 73, 0.15);
      border: 1px solid #f02849;
      color: #ff6b81;
      padding: 12px 16px;
      border-radius: 8px;
      font-size: 14px;
      margin-bottom: 20px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .msg-banner {
      background-color: rgba(46, 137, 255, 0.15);
      border: 1px solid #2e89ff;
      color: #8ac0ff;
      padding: 12px 16px;
      border-radius: 8px;
      font-size: 14px;
      margin-bottom: 20px;
    }
    .dev-box {
      background-color: rgba(49, 162, 76, 0.15);
      border: 1px dashed #31a24c;
      color: #79e394;
      padding: 12px;
      border-radius: 8px;
      font-size: 13px;
      margin-bottom: 20px;
      word-break: break-all;
    }
    .otp-input {
      width: 100%;
      padding: 14px;
      background-color: #3a3b3c;
      border: 1px solid #4e4f50;
      border-radius: 8px;
      color: #fff;
      font-size: 22px;
      letter-spacing: 8px;
      text-align: center;
      box-sizing: border-box;
      outline: none;
      font-family: monospace;
      margin-bottom: 18px;
      transition: border-color 0.2s;
    }
    .otp-input:focus {
      border-color: #2e89ff;
    }
    .btn-submit {
      width: 100%;
      padding: 13px;
      background-color: #2e89ff;
      color: #fff;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: background-color 0.2s;
    }
    .btn-submit:hover {
      background-color: #1a74e5;
    }
    .btn-secondary-link {
      background: none;
      border: none;
      color: #b0b3b8;
      font-size: 13px;
      cursor: pointer;
      text-decoration: underline;
      padding: 0;
      margin-top: 16px;
      display: inline-block;
    }
    .btn-secondary-link:hover {
      color: #e4e6eb;
    }
  </style>
</head>
<body>

<div class="otp-card">
  <div style="display:flex; align-items:center; gap:12px; margin-bottom:16px;">
    <div style="width:40px; height:40px; border-radius:50%; background:rgba(46,137,255,0.15); display:flex; align-items:center; justify-content:center; color:#2e89ff; font-size:18px;">
      <i class="fa-solid fa-mobile-screen-button"></i>
    </div>
    <h1 style="margin:0;">Two-Factor Verification</h1>
  </div>

  <p class="subtitle">
    Enter the 6-digit security code sent to your account for <strong><?php echo htmlspecialchars($email); ?></strong>.
  </p>

  <?php if ($error): ?>
    <div class="alert-banner">
      <i class="fa-solid fa-circle-exclamation"></i>
      <span><?php echo htmlspecialchars($error); ?></span>
    </div>
  <?php endif; ?>

  <?php if ($message): ?>
    <div class="msg-banner">
      <i class="fa-solid fa-circle-check"></i> <?php echo htmlspecialchars($message); ?>
    </div>
  <?php endif; ?>

  <?php if ($devOtp && \Daakpion\Security\Environment::allowDevSecrets()): ?>
    <div class="dev-box">
      <strong><i class="fa-solid fa-code"></i> Local Dev Simulated OTP:</strong> <code><?php echo htmlspecialchars($devOtp); ?></code>
    </div>
  <?php endif; ?>

  <form method="POST" action="verify_2fa.php">
    <?php echo CsrfProtection::renderHiddenField(); ?>
    <input type="hidden" name="verify_otp" value="1">

    <label style="display:block; font-size:13px; font-weight:600; color:#e4e6eb; margin-bottom:8px;" for="otp">Security Code</label>
    <input type="text" name="otp" id="otp" class="otp-input" maxlength="6" pattern="\d{6}" placeholder="······" required autofocus autocomplete="one-time-code">

    <button type="submit" class="btn-submit">
      <i class="fa-solid fa-check"></i> Verify &amp; Log In
    </button>
  </form>

  <div style="display:flex; justify-content:space-between; align-items:center; margin-top:16px;">
    <form method="POST" action="verify_2fa.php" style="display:inline;">
      <?php echo CsrfProtection::renderHiddenField(); ?>
      <input type="hidden" name="resend_otp" value="1">
      <button type="submit" class="btn-secondary-link">
        <i class="fa-solid fa-rotate-right"></i> Resend code
      </button>
    </form>

    <a href="../index.html" class="btn-secondary-link" style="text-decoration:none;">
      <i class="fa-solid fa-arrow-left"></i> Cancel
    </a>
  </div>
</div>

</body>
</html>
