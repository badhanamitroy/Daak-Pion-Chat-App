<?php
declare(strict_types=1);

require_once __DIR__ . "/bootstrap_security.php";

use Daakpion\Security\CryptoService;
use Daakpion\Security\PasswordPolicy;
use Daakpion\Security\SessionManager;
use Daakpion\Security\AuditLogger;
use Daakpion\Security\CsrfProtection;
use Daakpion\Security\RateLimiter;

if (!isset($_SESSION['user_id'])) {
    header("Location: ../index.html");
    exit;
}

// Server-side enforcement: block restricted temporary sessions
SessionManager::checkRestrictedAccess();

$user_id = (int)$_SESSION['user_id'];
$logger = new AuditLogger($conn);
$rateLimiter = new RateLimiter($conn);

// Upload directories
$profilePicDir = __DIR__ . "/../ProfilePics/";
$coverPicDir   = __DIR__ . "/../Coverpics/";
if (!is_dir($profilePicDir)) mkdir($profilePicDir, 0755, true);
if (!is_dir($coverPicDir))   mkdir($coverPicDir,   0755, true);

/**
 * Validates an uploaded image file.
 */
function validateUpload(array $file): ?string {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $errMap = [
            UPLOAD_ERR_INI_SIZE   => 'File exceeds server size limit.',
            UPLOAD_ERR_FORM_SIZE  => 'File exceeds form size limit.',
            UPLOAD_ERR_PARTIAL    => 'File was only partially uploaded.',
            UPLOAD_ERR_NO_FILE    => 'No file was uploaded.',
            UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder.',
            UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk.',
        ];
        return $errMap[$file['error']] ?? 'Unknown upload error.';
    }

    if ($file['size'] > MAX_UPLOAD_BYTES) {
        return 'File is too large. Maximum allowed size is 5 MB.';
    }

    $finfo    = new finfo(FILEINFO_MIME_TYPE);
    $mimeType = $finfo->file($file['tmp_name']);
    if (!in_array($mimeType, ALLOWED_MIME_TYPES, true)) {
        return 'Invalid file type. Only JPEG, PNG, GIF, and WebP images are allowed.';
    }

    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($ext, ALLOWED_EXTENSIONS, true)) {
        return 'Invalid file extension.';
    }

    return null;
}

$uploadError     = null;
$securitySuccess = null;
$securityError   = null;

// Fetch user
$sql = "SELECT fname, lname, email, password, dp, coverpic, two_factor_enabled FROM users WHERE id = ?";
$stmt = $conn->prepare($sql);
if (!$stmt) {
    error_log("Prepare failed in edit-profile.php: " . $conn->error);
    http_response_code(500);
    die("A system error occurred. Please try again later.");
}
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();
$stmt->close();

if (!$user) {
    SessionManager::destroySession($conn);
    header("Location: ../index.html");
    exit;
}

$userfName   = $user['fname'] ?? "User";
$userlName   = $user['lname'] ?? "";
$userName    = trim($userfName . " " . $userlName);
$userEmail   = $user['email'] ?? "";
$twoFactorOn = !empty($user['two_factor_enabled']);
$profilePic  = (!empty($user['dp']) && $user['dp'] !== 'ProfilePics/default.jpg') ? "../" . $user['dp'] : "../dp.png";
$coverPic    = !empty($user['coverpic']) ? "../" . $user['coverpic'] : "../Coverpics/default.jpg";

// ── Update Name ─────────────────────────────────────────────────────────────
if (isset($_POST['update_name'])) {
    if (!CsrfProtection::validateToken($_POST['csrf_token'] ?? '')) {
        $uploadError = "Security token mismatch.";
    } else {
        $newFName = trim(substr($_POST['fname'] ?? '', 0, 80));
        $newLName = trim(substr($_POST['lname'] ?? '', 0, 80));
        if (!empty($newFName) || !empty($newLName)) {
            $update = $conn->prepare("UPDATE users SET fname = ?, lname = ? WHERE id = ?");
            $update->bind_param("ssi", $newFName, $newLName, $user_id);
            $update->execute();
            $update->close();
            $_SESSION['user_name'] = trim($newFName . ' ' . $newLName);
            header("Location: edit-profile.php?updated=name");
            exit;
        }
    }
}

// ── Update Profile Pic ───────────────────────────────────────────────────────
if (isset($_POST['update_profile_pic']) && isset($_FILES['profile_pic'])) {
    if (!CsrfProtection::validateToken($_POST['csrf_token'] ?? '')) {
        $uploadError = "Security token mismatch.";
    } else {
        $uploadError = validateUpload($_FILES['profile_pic']);
        if ($uploadError === null) {
            $oldDp    = $user['dp'] ?? null;
            $fileName = "profile_" . $user_id . "_" . time() . ".jpg";
            $target   = $profilePicDir . $fileName;
            $dbPath   = "ProfilePics/" . $fileName;
            if (move_uploaded_file($_FILES['profile_pic']['tmp_name'], $target)) {
                $update = $conn->prepare("UPDATE users SET dp = ? WHERE id = ?");
                $update->bind_param("si", $dbPath, $user_id);
                $update->execute();
                $update->close();
                if ($oldDp && $oldDp !== 'dp.png' && $oldDp !== 'ProfilePics/dp.png' && file_exists(__DIR__ . "/../" . $oldDp)) {
                    @unlink(__DIR__ . "/../" . $oldDp);
                }
                header("Location: edit-profile.php?updated=dp");
                exit;
            }
        }
    }
}

// ── Update Cover Pic ────────────────────────────────────────────────────────
if (isset($_POST['update_cover_pic']) && isset($_FILES['cover_pic'])) {
    if (!CsrfProtection::validateToken($_POST['csrf_token'] ?? '')) {
        $uploadError = "Security token mismatch.";
    } else {
        $uploadError = validateUpload($_FILES['cover_pic']);
        if ($uploadError === null) {
            $oldCover = $user['coverpic'] ?? null;
            $fileName = "cover_" . $user_id . "_" . time() . ".jpg";
            $target   = $coverPicDir . $fileName;
            $dbPath   = "Coverpics/" . $fileName;
            if (move_uploaded_file($_FILES['cover_pic']['tmp_name'], $target)) {
                $update = $conn->prepare("UPDATE users SET coverpic = ? WHERE id = ?");
                $update->bind_param("si", $dbPath, $user_id);
                $update->execute();
                $update->close();
                if ($oldCover && file_exists(__DIR__ . "/../" . $oldCover)) {
                    @unlink(__DIR__ . "/../" . $oldCover);
                }
                header("Location: edit-profile.php?updated=cover");
                exit;
            }
        }
    }
}

// ── Change Password (Authenticated Flow) ────────────────────────────────────
if (isset($_POST['change_password'])) {
    if (!CsrfProtection::validateToken($_POST['csrf_token'] ?? '')) {
        $securityError = "Security token validation failed. Please refresh.";
    } else {
        $pwdKey = RateLimiter::buildKey('pwd_change', (string)$user_id);
        $hit = $rateLimiter->hit($pwdKey, 5, 900, 900);

        if ($hit['blocked']) {
            $logger->log('PASSWORD_CHANGE_FAILURE', 'RATE_LIMITED', $user_id, $userEmail);
            $securityError = "Too many failed password change attempts. Please wait {$hit['retryAfter']} seconds.";
        } else {
            $currentPwd = (string)($_POST['current_password'] ?? '');
            $newPwd     = (string)($_POST['new_password'] ?? '');
            $confirmPwd = (string)($_POST['confirm_password'] ?? '');

            if (empty($currentPwd) || empty($newPwd) || empty($confirmPwd)) {
                $securityError = "All password fields are required.";
            } elseif ($newPwd !== $confirmPwd) {
                $securityError = "New passwords do not match.";
            } else {
                // Verify current password
                $rehash = false;
                if (!CryptoService::verifyPassword($currentPwd, $user['password'], $rehash)) {
                    $logger->log('PASSWORD_CHANGE_FAILURE', 'INVALID_CURRENT_PASSWORD', $user_id, $userEmail);
                    $securityError = "Current password is incorrect.";
                } else {
                    // Validate new password against policy
                    $userContext = ['email' => $userEmail, 'fname' => $userfName, 'lname' => $userlName];
                    $policy = PasswordPolicy::validate($newPwd, $userContext);

                    if (!$policy['valid']) {
                        $securityError = implode(' ', $policy['errors']);
                    } elseif (hash_equals($currentPwd, $newPwd)) {
                        $securityError = "New password cannot be the same as your current password.";
                    } else {
                        // Hash with pepper + Argon2id
                        $newHash = CryptoService::hashPassword($newPwd);

                        // Update password and invalidate other sessions
                        $conn->begin_transaction();
                        try {
                            $updPwd = $conn->prepare("UPDATE users SET password = ? WHERE id = ?");
                            $updPwd->bind_param("si", $newHash, $user_id);
                            $updPwd->execute();
                            $updPwd->close();
                            $conn->commit();

                            $rateLimiter->clear($pwdKey);
                            SessionManager::invalidateOtherSessions($user_id, $conn);
                            $logger->log('PASSWORD_CHANGE_SUCCESS', 'SUCCESS', $user_id, $userEmail);

                            $securitySuccess = "Password updated successfully! All other active sessions have been signed out.";
                        } catch (\Throwable $e) {
                            $conn->rollback();
                            $securityError = "Failed to update password. Please try again.";
                        }
                    }
                }
            }
        }
    }
}

// ── 2FA is Mandatory (Cannot be disabled or toggled) ─────────────────────────
if (isset($_POST['toggle_2fa']) || isset($_POST['two_factor_enabled'])) {
    $securityError = "Two-Factor Authentication is mandatory and cannot be disabled.";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="dark">
  <title><?php echo htmlspecialchars($userName); ?> | Edit Profile — DaakPion</title>
  <meta name="description" content="Edit your DaakPion profile — update your name, profile picture, and cover photo.">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" crossorigin="anonymous" referrerpolicy="no-referrer">
  <link rel="stylesheet" href="../edit-user-profile.css?v=<?php echo time(); ?>">
  <style>
<?php @readfile(__DIR__ . '/../edit-user-profile.css'); ?>
  .alert-banner.success {
    background-color: rgba(49, 162, 76, 0.15);
    border-color: #31a24c;
    color: #79e394;
  }
  .security-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
  }
  .security-badge.on {
    background: rgba(49, 162, 76, 0.2);
    color: #79e394;
    border: 1px solid #31a24c;
  }
  .security-badge.off {
    background: rgba(240, 40, 73, 0.2);
    color: #ff6b81;
    border: 1px solid #f02849;
  }
  </style>
</head>
<body>

<!-- ── Sticky Navbar ── -->
<nav class="edit-navbar">
  <a class="nav-brand" href="../index.html">
    <img src="../Dakpion-logo.png" alt="DaakPion Logo">
    <span>DaakPion</span>
  </a>
  <div class="nav-actions">
    <a class="nav-btn" href="user-profile.php">
      <i class="fa-solid fa-arrow-left"></i> Back to Profile
    </a>
    <a class="nav-btn primary" href="chatboard.php">
      <i class="fa-solid fa-comments"></i> Messenger
    </a>
  </div>
</nav>

<!-- ── Page ── -->
<div class="edit-page">

  <!-- Error & Success banners -->
  <?php if ($uploadError): ?>
  <div class="alert-banner error">
    <i class="fa-solid fa-circle-exclamation"></i>
    <span><strong>Upload failed:</strong> <?php echo htmlspecialchars($uploadError); ?></span>
  </div>
  <?php endif; ?>

  <?php if ($securityError): ?>
  <div class="alert-banner error">
    <i class="fa-solid fa-circle-exclamation"></i>
    <span><strong>Security notice:</strong> <?php echo htmlspecialchars($securityError); ?></span>
  </div>
  <?php endif; ?>

  <?php if ($securitySuccess): ?>
  <div class="alert-banner success">
    <i class="fa-solid fa-circle-check"></i>
    <span><?php echo htmlspecialchars($securitySuccess); ?></span>
  </div>
  <?php endif; ?>

  <!-- Page Title -->
  <div class="page-title">
    <i class="fa-solid fa-pen-to-square"></i>
    Edit Profile &amp; Account Security
  </div>

  <!-- ════════════════════════════
       CARD 1: Cover Photo
  ════════════════════════════ -->
  <div class="edit-card">
    <div class="card-header">
      <i class="fa-solid fa-image"></i>
      <h2>Cover Photo</h2>
    </div>
    <div class="card-body">
      <form method="POST" enctype="multipart/form-data" id="coverForm">
        <?php echo CsrfProtection::renderHiddenField(); ?>
        <input type="hidden" name="update_cover_pic" value="1">

        <label for="coverInput">
          <div class="cover-preview-wrap" title="Click to change cover photo">
            <img id="coverPreview" src="<?php echo htmlspecialchars($coverPic); ?>" alt="Cover Photo">
            <div class="cover-overlay">
              <i class="fa-solid fa-camera"></i>
              <span>Change Cover Photo</span>
            </div>
          </div>
        </label>

        <input type="file" id="coverInput" name="cover_pic" accept="image/*" class="hidden-input"
               onchange="previewImage(this, 'coverPreview'); submitWithDelay('coverForm')">

        <p class="file-hint">
          <i class="fa-solid fa-circle-info"></i> JPG, PNG, GIF or WebP · Max 5 MB · Recommended: 820×312 px
        </p>
      </form>
    </div>
  </div>

  <!-- ════════════════════════════
       CARD 2: Profile Picture
  ════════════════════════════ -->
  <div class="edit-card">
    <div class="card-header">
      <i class="fa-solid fa-user-circle"></i>
      <h2>Profile Picture</h2>
    </div>
    <div class="card-body">
      <form method="POST" enctype="multipart/form-data" id="avatarForm">
        <?php echo CsrfProtection::renderHiddenField(); ?>
        <input type="hidden" name="update_profile_pic" value="1">

        <div class="profile-pic-row">
          <label for="avatarInput">
            <div class="avatar-preview-wrap" title="Click to change profile picture">
              <img id="avatarPreview" src="<?php echo htmlspecialchars($profilePic); ?>" alt="Profile Picture">
              <div class="avatar-overlay">
                <i class="fa-solid fa-camera"></i>
              </div>
            </div>
          </label>

          <div class="avatar-info">
            <p>
              Your profile picture is visible to all your friends.<br>
              For best results, use a square image at least <strong>400×400 px</strong>.
            </p>
            <label for="avatarInput" class="btn-secondary" style="cursor:pointer;">
              <i class="fa-solid fa-upload"></i> Upload New Photo
            </label>
            <p class="file-hint" style="margin-top:8px;">JPG, PNG, GIF or WebP · Max 5 MB</p>
          </div>
        </div>

        <input type="file" id="avatarInput" name="profile_pic" accept="image/*" class="hidden-input"
               onchange="previewImage(this, 'avatarPreview'); submitWithDelay('avatarForm')">
      </form>
    </div>
  </div>

  <!-- ════════════════════════════
       CARD 3: Name
  ════════════════════════════ -->
  <div class="edit-card">
    <div class="card-header">
      <i class="fa-solid fa-id-card"></i>
      <h2>Your Name</h2>
    </div>
    <div class="card-body">
      <form method="POST" id="nameForm">
        <?php echo CsrfProtection::renderHiddenField(); ?>
        <input type="hidden" name="update_name" value="1">
        <div class="name-row">
          <div class="form-field">
            <label for="fname">First Name</label>
            <input type="text" id="fname" name="fname" value="<?php echo htmlspecialchars($userfName); ?>" placeholder="First name" autocomplete="given-name">
          </div>
          <div class="form-field">
            <label for="lname">Last Name</label>
            <input type="text" id="lname" name="lname" value="<?php echo htmlspecialchars($userlName); ?>" placeholder="Last name" autocomplete="family-name">
          </div>
        </div>
        <p class="file-hint">
          <i class="fa-solid fa-circle-info"></i> Your name appears on your profile and in search results.
        </p>
      </form>
    </div>
    <div class="card-footer">
      <button class="btn-primary" onclick="document.getElementById('nameForm').submit()">
        <i class="fa-solid fa-check"></i> Save Changes
      </button>
    </div>
  </div>

  <!-- ════════════════════════════
       CARD 4: Change Password (Harden Security)
  ════════════════════════════ -->
  <div class="edit-card">
    <div class="card-header">
      <i class="fa-solid fa-shield-halved"></i>
      <h2>Change Password</h2>
    </div>
    <div class="card-body">
      <form method="POST" id="passwordForm">
        <?php echo CsrfProtection::renderHiddenField(); ?>
        <input type="hidden" name="change_password" value="1">

        <div class="form-field" style="margin-bottom:16px;">
          <label for="current_password">Current Password</label>
          <input type="password" id="current_password" name="current_password" required autocomplete="current-password" placeholder="Enter current password">
        </div>

        <div class="name-row">
          <div class="form-field">
            <label for="new_password">New Password</label>
            <input type="password" id="new_password" name="new_password" required autocomplete="new-password" placeholder="At least 12 characters">
          </div>
          <div class="form-field">
            <label for="confirm_password">Confirm New Password</label>
            <input type="password" id="confirm_password" name="confirm_password" required autocomplete="new-password" placeholder="Re-type new password">
          </div>
        </div>

        <p class="file-hint">
          <i class="fa-solid fa-lock"></i> Minimum 12 characters. Changing your password immediately invalidates all other active login sessions.
        </p>
      </form>
    </div>
    <div class="card-footer">
      <button class="btn-primary" onclick="document.getElementById('passwordForm').submit()">
        <i class="fa-solid fa-key"></i> Update Password
      </button>
    </div>
  </div>

  <!-- ════════════════════════════
       CARD 5: Two-Factor Authentication (2FA)
  ════════════════════════════ -->
  <div class="edit-card">
    <div class="card-header" style="justify-content:space-between;">
      <div style="display:flex; align-items:center; gap:8px;">
        <i class="fa-solid fa-shield-halved"></i>
        <h2>Two-Factor Authentication (2FA)</h2>
      </div>
      <div>
        <span class="security-badge on"><i class="fa-solid fa-lock"></i> Mandatory &amp; Active</span>
      </div>
    </div>
    <div class="card-body">
      <p style="font-size:14px; color:var(--text-muted); line-height:1.5; margin-bottom:0;">
        Two-Factor Authentication is mandatory for all DaakPion accounts to protect your conversations and account privacy. A 6-digit one-time verification code (OTP) is sent to your registered email address on every sign-in. This security protection cannot be turned off.
      </p>
    </div>
  </div>

</div><!-- /edit-page -->

<script>
function previewImage(input, previewId) {
  if (!input.files || !input.files[0]) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    document.getElementById(previewId).src = e.target.result;
  };
  reader.readAsDataURL(input.files[0]);
}

function submitWithDelay(formId) {
  const btn = document.querySelector(`#${formId} .btn-primary`);
  if (btn) { btn.classList.add('loading'); btn.disabled = true; }
  setTimeout(() => {
    document.getElementById(formId).submit();
  }, 600);
}
</script>

</body>
</html>
