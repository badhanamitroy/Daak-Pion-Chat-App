<?php
session_start();
require_once "db_connect.php";
require_once "app_config.php"; // Upload constants & limits

if (!isset($_SESSION['user_id'])) {
    header("Location: index.html");
    exit;
}

$user_id = $_SESSION['user_id'];

// Upload directories
$profilePicDir = __DIR__ . "/../ProfilePics/";
$coverPicDir   = __DIR__ . "/../Coverpics/";
if (!is_dir($profilePicDir)) mkdir($profilePicDir, 0755, true);
if (!is_dir($coverPicDir))   mkdir($coverPicDir,   0755, true);

/**
 * Validates an uploaded image file.
 * Returns null on success, or an error string on failure.
 */
function validateUpload(array $file): ?string {
    // Check for PHP upload errors
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

    // Check file size
    if ($file['size'] > MAX_UPLOAD_BYTES) {
        return 'File is too large. Maximum allowed size is 5 MB.';
    }

    // Verify real MIME type using finfo (not the browser-supplied Content-Type)
    $finfo    = new finfo(FILEINFO_MIME_TYPE);
    $mimeType = $finfo->file($file['tmp_name']);
    if (!in_array($mimeType, ALLOWED_MIME_TYPES, true)) {
        return 'Invalid file type. Only JPEG, PNG, GIF, and WebP images are allowed.';
    }

    // Check file extension against whitelist
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($ext, ALLOWED_EXTENSIONS, true)) {
        return 'Invalid file extension.';
    }

    return null; // All checks passed
}

$uploadError = null; // Will hold any upload error message to show the user

// Fetch user
$sql = "SELECT fname, lname, dp, coverpic FROM users WHERE id = ?";
$stmt = $conn->prepare($sql);
if (!$stmt) die("Prepare failed: " . $conn->error);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();

$userfName  = $user['fname'] ?? "User";
$userlName  = $user['lname'] ?? "";
$userName   = trim($userfName . " " . $userlName);
$profilePic = !empty($user['dp']) ? "../" . $user['dp'] : "../ProfilePics/default.jpg";
$coverPic   = !empty($user['coverpic']) ? "../" . $user['coverpic'] : "../Coverpics/default.jpg";

// Update name
if (isset($_POST['update_name'])) {
    $newFName = trim(substr($_POST['fname'] ?? '', 0, 80));
    $newLName = trim(substr($_POST['lname'] ?? '', 0, 80));
    if (!empty($newFName) || !empty($newLName)) {
        $update = $conn->prepare("UPDATE users SET fname = ?, lname = ? WHERE id = ?");
        $update->bind_param("ssi", $newFName, $newLName, $user_id);
        $update->execute();
        header("Location: edit-profile.php");
        exit;
    }
}

// Update profile pic
if (isset($_POST['update_profile_pic']) && isset($_FILES['profile_pic'])) {
    $uploadError = validateUpload($_FILES['profile_pic']); // Security: validate before touching disk
    if ($uploadError === null) {
        $oldDp    = $user['dp'] ?? null;
        $fileName = "profile_" . $user_id . "_" . time() . ".jpg";
        $target   = $profilePicDir . $fileName;
        $dbPath   = "ProfilePics/" . $fileName;
        if (move_uploaded_file($_FILES['profile_pic']['tmp_name'], $target)) {
            $update = $conn->prepare("UPDATE users SET dp = ? WHERE id = ?");
            $update->bind_param("si", $dbPath, $user_id);
            $update->execute();
            // Delete old profile pic from disk to save space
            if ($oldDp && file_exists(__DIR__ . "/../" . $oldDp)) {
                @unlink(__DIR__ . "/../" . $oldDp);
            }
            header("Location: edit-profile.php");
            exit;
        }
    }
    // If we reach here, either validation failed or move failed — $uploadError is set
}

// Update cover pic
if (isset($_POST['update_cover_pic']) && isset($_FILES['cover_pic'])) {
    $uploadError = validateUpload($_FILES['cover_pic']); // Security: validate before touching disk
    if ($uploadError === null) {
        $oldCover = $user['coverpic'] ?? null;
        $fileName = "cover_" . $user_id . "_" . time() . ".jpg";
        $target   = $coverPicDir . $fileName;
        $dbPath   = "Coverpics/" . $fileName;
        if (move_uploaded_file($_FILES['cover_pic']['tmp_name'], $target)) {
            $update = $conn->prepare("UPDATE users SET coverpic = ? WHERE id = ?");
            $update->bind_param("si", $dbPath, $user_id);
            $update->execute();
            // Delete old cover pic from disk
            if ($oldCover && file_exists(__DIR__ . "/../" . $oldCover)) {
                @unlink(__DIR__ . "/../" . $oldCover);
            }
            header("Location: edit-profile.php");
            exit;
        }
    }
    // If we reach here, either validation failed or move failed — $uploadError is set
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?php echo htmlspecialchars($userName); ?> | Edit Profile — DaakPion</title>
  <meta name="description" content="Edit your DaakPion profile — update your name, profile picture, and cover photo.">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" crossorigin="anonymous" referrerpolicy="no-referrer">
  <link rel="stylesheet" href="../edit-user-profile.css?v=<?php echo time(); ?>">
  <style>
<?php @readfile(__DIR__ . '/../edit-user-profile.css'); ?>
  </style>
</head>
<body>

<!-- ── Sticky Navbar ── -->
<nav class="edit-navbar">
  <a class="nav-brand" href="../index.html">
    <img src="../Daak-pion.png" alt="DaakPion Logo">
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

  <!-- Error banner -->
  <?php if ($uploadError): ?>
  <div class="alert-banner error">
    <i class="fa-solid fa-circle-exclamation"></i>
    <span><strong>Upload failed:</strong> <?php echo htmlspecialchars($uploadError); ?></span>
  </div>
  <?php endif; ?>

  <!-- Page Title -->
  <div class="page-title">
    <i class="fa-solid fa-pen-to-square"></i>
    Edit Profile
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
        <input type="hidden" name="update_cover_pic" value="1">

        <!-- Live preview click zone -->
        <label for="coverInput">
          <div class="cover-preview-wrap" title="Click to change cover photo">
            <img id="coverPreview"
                 src="<?php echo htmlspecialchars($coverPic); ?>"
                 alt="Cover Photo">
            <div class="cover-overlay">
              <i class="fa-solid fa-camera"></i>
              <span>Change Cover Photo</span>
            </div>
          </div>
        </label>

        <input type="file" id="coverInput" name="cover_pic"
               accept="image/*" class="hidden-input"
               onchange="previewImage(this, 'coverPreview'); submitWithDelay('coverForm')">

        <p class="file-hint">
          <i class="fa-solid fa-circle-info"></i>
          JPG, PNG, GIF or WebP · Max 5 MB · Recommended: 820×312 px
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
        <input type="hidden" name="update_profile_pic" value="1">

        <div class="profile-pic-row">
          <!-- Avatar preview -->
          <label for="avatarInput">
            <div class="avatar-preview-wrap" title="Click to change profile picture">
              <img id="avatarPreview"
                   src="<?php echo htmlspecialchars($profilePic); ?>"
                   alt="Profile Picture">
              <div class="avatar-overlay">
                <i class="fa-solid fa-camera"></i>
              </div>
            </div>
          </label>

          <!-- Info + action -->
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

        <input type="file" id="avatarInput" name="profile_pic"
               accept="image/*" class="hidden-input"
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
        <div class="name-row">
          <div class="form-field">
            <label for="fname">First Name</label>
            <input type="text" id="fname" name="fname"
                   value="<?php echo htmlspecialchars($userfName); ?>"
                   placeholder="First name" autocomplete="given-name">
          </div>
          <div class="form-field">
            <label for="lname">Last Name</label>
            <input type="text" id="lname" name="lname"
                   value="<?php echo htmlspecialchars($userlName); ?>"
                   placeholder="Last name" autocomplete="family-name">
          </div>
        </div>
        <p class="file-hint">
          <i class="fa-solid fa-circle-info"></i>
          Your name appears on your profile and in search results.
        </p>
      </form>
    </div>
    <div class="card-footer">
      <a href="user-profile.php" class="btn-secondary">
        <i class="fa-solid fa-xmark"></i> Cancel
      </a>
      <button class="btn-primary" onclick="document.getElementById('nameForm').submit()">
        <i class="fa-solid fa-check"></i> Save Changes
      </button>
      <input type="hidden" name="update_name" value="1" form="nameForm">
    </div>
  </div>

</div><!-- /edit-page -->

<script>
// Live image preview before upload
function previewImage(input, previewId) {
  if (!input.files || !input.files[0]) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    document.getElementById(previewId).src = e.target.result;
  };
  reader.readAsDataURL(input.files[0]);
}

// Submit form after a short delay so user sees the preview
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
