<?php
// reset_password.php — Token verification and password reset completion
declare(strict_types=1);

require_once __DIR__ . '/bootstrap_security.php';

use Daakpion\Security\PasswordResetService;
use Daakpion\Security\CsrfProtection;

$token = trim($_GET['token'] ?? $_POST['token'] ?? '');
$service = new PasswordResetService($conn);

$record = null;
$error = null;
$success = false;

if (empty($token)) {
    $error = "Missing or invalid password reset token.";
} else {
    $record = $service->verifyToken($token);
    if (!$record) {
        $error = "This password reset link is invalid or has expired. Please request a new one.";
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $record) {
    $submittedCsrf = $_POST['csrf_token'] ?? '';
    if (!CsrfProtection::validateToken($submittedCsrf)) {
        $error = "Security token mismatch. Please try again.";
    } else {
        $newPassword     = (string)($_POST['new_password'] ?? '');
        $confirmPassword = (string)($_POST['confirm_password'] ?? '');

        if (empty($newPassword) || empty($confirmPassword)) {
            $error = "All fields are required.";
        } elseif ($newPassword !== $confirmPassword) {
            $error = "Passwords do not match.";
        } else {
            $result = $service->completeReset($token, $newPassword);
            if ($result['success']) {
                $success = true;
            } else {
                $error = $result['error'] ?? "Failed to reset password.";
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
  <title>Set New Password — DaakPion</title>
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
    .success-banner {
      background-color: rgba(49, 162, 76, 0.15);
      border: 1px solid #31a24c;
      color: #79e394;
      padding: 16px;
      border-radius: 8px;
      font-size: 15px;
      margin-bottom: 20px;
      text-align: center;
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
    .policy-hint {
      font-size: 12px;
      color: #9a9da3;
      margin-top: 4px;
      line-height: 1.4;
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
      <i class="fa-solid fa-lock"></i>
    </div>
    <h1 style="margin:0;">Create New Password</h1>
  </div>

  <?php if ($success): ?>
    <div class="success-banner">
      <i class="fa-solid fa-circle-check" style="font-size:24px; margin-bottom:8px; display:block;"></i>
      <strong>Password Reset Successful!</strong>
      <p style="margin: 8px 0 0 0; font-size: 14px; color: #b0b3b8;">
        Your password has been updated and all previous sessions have been securely signed out.
      </p>
    </div>
    <a href="../index.html" class="btn-submit" style="display:block; text-align:center; text-decoration:none;">
      Go to Login
    </a>
  <?php else: ?>
    <?php if ($error): ?>
      <div class="alert-banner">
        <i class="fa-solid fa-circle-exclamation"></i>
        <span><?php echo htmlspecialchars($error); ?></span>
      </div>
    <?php endif; ?>

    <?php if ($record): ?>
      <p class="subtitle">
        Account: <strong><?php echo htmlspecialchars($record['email']); ?></strong><br>
        Please enter your new secure password below.
      </p>

      <form method="POST" action="reset_password.php">
        <?php echo CsrfProtection::renderHiddenField(); ?>
        <input type="hidden" name="token" value="<?php echo htmlspecialchars($token); ?>">

        <div class="form-group">
          <label for="new_password">New Password</label>
          <input type="password" name="new_password" id="new_password" required autocomplete="new-password">
          <div class="policy-hint">
            <i class="fa-solid fa-circle-info"></i> Minimum 12 characters. Avoid common passwords or personal names.
          </div>
        </div>

        <div class="form-group">
          <label for="confirm_password">Confirm New Password</label>
          <input type="password" name="confirm_password" id="confirm_password" required autocomplete="new-password">
        </div>

        <button type="submit" class="btn-submit">
          <i class="fa-solid fa-key"></i> Update Password
        </button>
      </form>
    <?php else: ?>
      <a href="forgot_password.php" class="btn-submit" style="display:block; text-align:center; text-decoration:none;">
        Request New Reset Link
      </a>
    <?php endif; ?>

    <a href="../index.html" class="back-link">
      <i class="fa-solid fa-arrow-left"></i> Back to Login
    </a>
  <?php endif; ?>
</div>

</body>
</html>
