<?php
session_start();
require_once "db_connect.php"; // DB connection file

if (!isset($_SESSION['user_id'])) {
    header("Location: index.html");
    exit;
}

$user_id = $_SESSION['user_id'];

// Folders
$profilePicDir = __DIR__ . "/../ProfilePics/";
$coverPicDir   = __DIR__ . "/../Coverpics/";
if (!is_dir($profilePicDir)) mkdir($profilePicDir, 0777, true);
if (!is_dir($coverPicDir)) mkdir($coverPicDir, 0777, true);

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
    $newFName = trim($_POST['fname']);
    $newLName = trim($_POST['lname']);
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
    $fileTmp  = $_FILES['profile_pic']['tmp_name'];
    $fileName = "profile_" . $user_id . "_" . time() . ".jpg";
    $target   = $profilePicDir . $fileName;
    $dbPath   = "ProfilePics/" . $fileName;
    if (move_uploaded_file($fileTmp, $target)) {
        $update = $conn->prepare("UPDATE users SET dp = ? WHERE id = ?");
        $update->bind_param("si", $dbPath, $user_id);
        $update->execute();
        header("Location: edit-profile.php");
        exit;
    }
}

// Update cover pic
if (isset($_POST['update_cover_pic']) && isset($_FILES['cover_pic'])) {
    $fileTmp  = $_FILES['cover_pic']['tmp_name'];
    $fileName = "cover_" . $user_id . "_" . time() . ".jpg";
    $target   = $coverPicDir . $fileName;
    $dbPath   = "Coverpics/" . $fileName;
    if (move_uploaded_file($fileTmp, $target)) {
        $update = $conn->prepare("UPDATE users SET coverpic = ? WHERE id = ?");
        $update->bind_param("si", $dbPath, $user_id);
        $update->execute();
        header("Location: edit-profile.php");
        exit;
    }
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
