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
    <title><?php echo htmlspecialchars($userName); ?> | Profile</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <link rel="stylesheet" href="../edit-user-profile.css">

</head>
<body>

<div class="profile-container">
    <?php if ($uploadError): ?>
        <div style="background:#e63946;color:#fff;padding:12px 20px;border-radius:8px;margin-bottom:14px;font-size:14px;font-family:Arial,sans-serif;">
            <strong>Upload failed:</strong> <?php echo htmlspecialchars($uploadError); ?>
        </div>
    <?php endif; ?>
    <!-- Cover Photo -->
    <div class="cover-photo" style="background-image: url('<?php echo htmlspecialchars($coverPic); ?>');">
        <form method="POST" enctype="multipart/form-data" class="cover-upload">
            <label class="cover-btn">
                <i class="fa-solid fa-camera"></i>
                <input type="file" name="cover_pic" accept="image/*" required hidden onchange="this.form.submit()">
            </label>
            <input type="hidden" name="update_cover_pic" value="1">
        </form>
    </div>

    <!-- Profile Section -->
    <div class="profile-section">
        <div class="profile-pic">
            <img src="<?php echo htmlspecialchars($profilePic); ?>" alt="Profile">
            <form method="POST" enctype="multipart/form-data" class="profile-upload">
                <label class="profile-btn">
                    <i class="fa-solid fa-camera"></i>
                    <input type="file" name="profile_pic" accept="image/*" required hidden onchange="this.form.submit()">
                </label>
                <input type="hidden" name="update_profile_pic" value="1">
            </form>
        </div>

        <div class="profile-name">
            <h1><?php echo htmlspecialchars($userName); ?>
                <i class="fa-solid fa-pen-to-square edit-icon" onclick="document.getElementById('name-form').classList.toggle('show')"></i>
            </h1>
            <form id="name-form" method="POST">
                <input type="text" name="fname" value="<?php echo htmlspecialchars($userfName); ?>" placeholder="First Name">
                <input type="text" name="lname" value="<?php echo htmlspecialchars($userlName); ?>" placeholder="Last Name">
                <button type="submit" name="update_name"><i class="fa-solid fa-check"></i> Save</button>
            </form>
        </div>
    </div>
</div>

<a href="user-profile.php" 
   style="
       position: fixed;
       bottom: 20px;
       left: 20px;
       background-color: #4CAF50;
       color: white;
       padding: 12px 24px;
       border-radius: 8px;
       text-decoration: none;
       font-size: 16px;
       font-family: Arial, sans-serif;
       box-shadow: 0 4px 8px rgba(0,0,0,0.2);
   "
>
    Back to Profile
</a>


</body>
</html>
