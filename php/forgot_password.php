<?php
// forgot_password.php — Password reset request endpoint with anti-enumeration defense
declare(strict_types=1);

require_once __DIR__ . '/bootstrap_security.php';

use Daakpion\Security\PasswordResetService;
use Daakpion\Security\CsrfProtection;

$message = null;
$devToken = null;
$devMailNotice = null;
$service = new PasswordResetService($conn);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!CsrfProtection::validateToken($submittedToken)) {
        $message = "Security token mismatch. Please try again.";
    } else {
        $email = trim($_POST['email'] ?? '');
        $res = $service->requestReset($email);
        $message = $res['message'];
        if (\Daakpion\Security\Environment::allowDevSecrets()) {
            if (!empty($res['dev_token'])) {
                $devToken = $res['dev_token'];
            }
            if (!empty($res['dev_mail_error'])) {
                $devMailNotice = $res['dev_mail_error'];
            }
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
  <title>Forgot Password — DaakPion</title>
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
    .reset-card {
      background-color: #242526;
      border: 1px solid #3a3b3c;
      border-radius: 12px;
      padding: 32px;
      width: 100%;
      max-width: 440px;
      box-shadow: 0 12px 28px rgba(0,0,0,0.35);
    }
    .reset-card h1 {
      font-size: 22px;
      margin-bottom: 8px;
      color: #e4e6eb;
    }
    .reset-card p.subtitle {
      font-size: 14px;
      color: #b0b3b8;
      margin-bottom: 24px;
      line-height: 1.5;
    }
    .msg-banner {
      background-color: rgba(46, 137, 255, 0.15);
      border: 1px solid #2e89ff;
      color: #8ac0ff;
      padding: 14px 16px;
      border-radius: 8px;
      font-size: 14px;
      margin-bottom: 20px;
      line-height: 1.4;
    }
    .dev-box {
      background-color: rgba(49, 162, 76, 0.15);
      border: 1px dashed #31a24c;
      color: #79e394;
      padding: 12px;
      border-radius: 8px;
      font-size: 13px;
      margin-top: 14px;
      word-break: break-all;
    }
    .dev-box a {
      color: #fff;
      font-weight: 600;
      text-decoration: underline;
    }
    .form-group {
      margin-bottom: 18px;
    }
    .form-group label {
      display: block;
      font-size: 13px;
      font-weight: 600;
      color: #e4e6eb;
      margin-bottom: 6px;
    }
    .form-group input {
      width: 100%;
      padding: 12px 14px;
      background-color: #3a3b3c;
      border: 1px solid #4e4f50;
      border-radius: 8px;
      color: #fff;
      font-size: 15px;
      box-sizing: border-box;
      outline: none;
      transition: border-color 0.2s;
    }
    .form-group input:focus {
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
      margin-top: 10px;
      transition: background-color 0.2s;
    }
    .btn-submit:hover {
      background-color: #1a74e5;
    }
    .back-link {
      display: block;
      text-align: center;
      margin-top: 20px;
      font-size: 14px;
      color: #b0b3b8;
      text-decoration: none;
    }
    .back-link:hover {
      color: #e4e6eb;
      text-decoration: underline;
    }
  </style>
</head>
<body>

<div class="reset-card">
  <div style="display:flex; align-items:center; gap:12px; margin-bottom:16px;">
    <div style="width:40px; height:40px; border-radius:50%; background:rgba(46,137,255,0.15); display:flex; align-items:center; justify-content:center; color:#2e89ff; font-size:18px;">
      <i class="fa-solid fa-key"></i>
    </div>
    <h1 style="margin:0;">Reset Your Password</h1>
  </div>

  <p class="subtitle">
    Enter the email address associated with your account. If the account exists, we will generate secure password reset instructions.
  </p>

  <?php if ($message): ?>
    <div class="msg-banner">
      <i class="fa-solid fa-circle-check"></i> <?php echo htmlspecialchars($message); ?>
    </div>

    <?php if (($devToken || $devMailNotice) && \Daakpion\Security\Environment::allowDevSecrets()): ?>
      <div class="dev-box">
        <?php if ($devToken): ?>
          <strong><i class="fa-solid fa-laptop-code"></i> Local Dev Simulated Reset Link:</strong><br>
          <a href="reset_password.php?token=<?php echo urlencode($devToken); ?>">Click here to proceed to Password Reset Form</a>
        <?php endif; ?>
        <?php if ($devMailNotice): ?>
          <div style="<?php echo $devToken ? 'margin-top:8px; padding-top:6px; border-top:1px dashed rgba(255,255,255,0.2);' : ''; ?> font-size:12px;">
            <strong><i class="fa-solid fa-circle-info"></i> Dev Mail Diagnostic:</strong> <?php echo htmlspecialchars($devMailNotice); ?>
          </div>
        <?php endif; ?>
      </div>
    <?php endif; ?>
  <?php endif; ?>

  <form method="POST" action="forgot_password.php">
    <?php echo CsrfProtection::renderHiddenField(); ?>

    <div class="form-group">
      <label for="email">Account Email Address</label>
      <input type="email" name="email" id="email" placeholder="name@example.com" required autocomplete="email">
    </div>

    <button type="submit" class="btn-submit">
      <i class="fa-solid fa-paper-plane"></i> Send Reset Instructions
    </button>
  </form>

  <a href="../index.html" class="back-link">
    <i class="fa-solid fa-arrow-left"></i> Back to Login
  </a>
</div>

</body>
</html>
