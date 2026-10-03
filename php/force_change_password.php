<?php
// force_change_password.php — Mandatory first-login / temporary password change
declare(strict_types=1);

require_once __DIR__ . '/bootstrap_security.php';

use Daakpion\Security\CryptoService;
use Daakpion\Security\PasswordPolicy;
use Daakpion\Security\SessionManager;
use Daakpion\Security\AuditLogger;
use Daakpion\Security\CsrfProtection;

// Must be authenticated
if (!isset($_SESSION['user_id'])) {
    header("Location: ../index.html");
    exit;
}

// If user is not under restricted temporary password state, go to chatboard
if (empty($_SESSION['must_change_password'])) {
    header("Location: chatboard.php");
    exit;
}

$userId = (int)$_SESSION['user_id'];
$logger = new AuditLogger($conn);
$error  = null;
$success = false;

// Fetch user context
$stmt = $conn->prepare("SELECT email, fname, lname, password, is_temporary_password FROM users WHERE id = ?");
$stmt->bind_param("i", $userId);
$stmt->execute();
$user = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$user) {
    SessionManager::destroySession($conn);
    header("Location: ../index.html");
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!CsrfProtection::validateToken($submittedToken)) {
        $error = "Invalid or expired security token. Please refresh and try again.";
    } else {
        $currentPassword = (string)($_POST['current_password'] ?? '');
        $newPassword     = (string)($_POST['new_password'] ?? '');
        $confirmPassword = (string)($_POST['confirm_password'] ?? '');

        if (empty($currentPassword) || empty($newPassword) || empty($confirmPassword)) {
            $error = "All fields are required.";
        } elseif ($newPassword !== $confirmPassword) {
            $error = "New passwords do not match.";
        } else {
            // 1. Verify current temporary password
            $rehash = false;
            if (!CryptoService::verifyPassword($currentPassword, $user['password'], $rehash)) {
                $logger->log('PASSWORD_CHANGE_FAILURE', 'INVALID_CURRENT_PASSWORD', $userId, $user['email']);
                $error = "Current temporary password is incorrect.";
            } else {
                // 2. Validate new password against policy
                $userContext = [
                    'email' => $user['email'],
                    'fname' => $user['fname'],
                    'lname' => $user['lname']
                ];
                $policy = PasswordPolicy::validate($newPassword, $userContext);
                if (!$policy['valid']) {
                    $error = implode(' ', $policy['errors']);
                } elseif (hash_equals($currentPassword, $newPassword)) {
                    $error = "New password cannot be the same as your temporary password.";
                } else {
                    // 3. Hash with pepper + Argon2id
                    $newHash = CryptoService::hashPassword($newPassword);

                    // 4. Update database: save permanent hash, remove temp flag & expiration, increment password_version
                    $conn->begin_transaction();
                    try {
                        $upd = $conn->prepare(
                            "UPDATE users 
                             SET password = ?, 
                                 is_temporary_password = 0, 
                                 temp_password_expires_at = NULL, 
                                 password_version = password_version + 1 
                             WHERE id = ?"
                        );
                        $upd->bind_param("si", $newHash, $userId);
                        $upd->execute();
                        $upd->close();
                        $conn->commit();

                        // 5. Invalidate temporary restriction state & regenerate session
                        $_SESSION['must_change_password'] = false;
                        SessionManager::invalidateOtherSessions($userId, $conn);

                        $logger->log('TEMPORARY_PASSWORD_CONSUMED', 'PERMANENT_PASSWORD_SET', $userId, $user['email']);

                        header("Location: chatboard.php?password_set=1");
                        exit;
                    } catch (\Throwable $e) {
                        $conn->rollback();
                        $error = "Failed to update password. Please try again.";
                    }
                }
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
  <title>Set Permanent Password — DaakPion</title>
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
    .security-card {
      background-color: #242526;
      border: 1px solid #3a3b3c;
      border-radius: 12px;
      padding: 32px;
      width: 100%;
      max-width: 480px;
      box-shadow: 0 12px 28px rgba(0,0,0,0.35);
    }
    .security-card h1 {
      font-size: 24px;
      margin-bottom: 8px;
      color: #e4e6eb;
    }
    .security-card p.subtitle {
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
    .logout-link {
      display: block;
      text-align: center;
      margin-top: 18px;
      font-size: 14px;
      color: #b0b3b8;
      text-decoration: none;
    }
    .logout-link:hover {
      color: #e4e6eb;
      text-decoration: underline;
    }
  </style>
</head>
<body>

<div class="security-card">
  <div style="display:flex; align-items:center; gap:12px; margin-bottom:16px;">
    <div style="width:44px; height:44px; border-radius:50%; background:rgba(46,137,255,0.15); display:flex; align-items:center; justify-content:center; color:#2e89ff; font-size:20px;">
      <i class="fa-solid fa-shield-halved"></i>
    </div>
    <div>
      <h1 style="margin:0;">Password Update Required</h1>
      <span style="font-size:13px; color:#b0b3b8;">Welcome, <?php echo htmlspecialchars($user['fname'] . ' ' . $user['lname']); ?></span>
    </div>
  </div>

  <p class="subtitle">
    You have logged in using a temporary credential. For your account security, you must establish a strong permanent password before accessing your account.
  </p>

  <?php if ($error): ?>
    <div class="alert-banner">
      <i class="fa-solid fa-circle-exclamation"></i>
      <span><?php echo htmlspecialchars($error); ?></span>
    </div>
  <?php endif; ?>

  <form method="POST" action="force_change_password.php">
    <?php echo CsrfProtection::renderHiddenField(); ?>

    <div class="form-group">
      <label for="current_password">Current Temporary Password</label>
      <input type="password" name="current_password" id="current_password" required autocomplete="current-password">
    </div>

    <div class="form-group">
      <label for="new_password">New Permanent Password</label>
      <input type="password" name="new_password" id="new_password" required autocomplete="new-password">
      <div class="policy-hint">
        <i class="fa-solid fa-circle-info"></i> Minimum 12 characters. Avoid common phrases, sequences, or names.
      </div>
    </div>

    <div class="form-group">
      <label for="confirm_password">Confirm New Password</label>
      <input type="password" name="confirm_password" id="confirm_password" required autocomplete="new-password">
    </div>

    <button type="submit" class="btn-submit">
      <i class="fa-solid fa-lock"></i> Save Permanent Password
    </button>
  </form>

  <a href="logout.php" class="logout-link">
    <i class="fa-solid fa-arrow-right-from-bracket"></i> Log Out
  </a>
</div>

</body>
</html>
