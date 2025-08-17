<?php
session_start();
require_once "db_connect.php"; 

// Check if user is logged in, e.g., user_id is set in session
if (!isset($_SESSION['user_id'])) {
    // User not logged in, redirect to login page
    header("Location: index.html"); // Adjust to your login page URL
    exit;
}

$user_id = $_SESSION['user_id'];

// Optionally, get user info from session
$userName = isset($_SESSION['user_name']) ? $_SESSION['user_name'] : "User";


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

?>


<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Profile - DaakPion</title>
  <link rel="stylesheet" href="../user-profile.css" />
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/7.0.0/css/all.min.css" integrity="sha512-DxV+EoADOkOygM4IR9yXP8Sb2qwgidEmeqAEmDKIOfPRQZOWbXCzLC6vjbZyy0vPisbH2SyW27+ddLVCN+OMzQ==" crossorigin="anonymous" referrerpolicy="no-referrer" />

  <style>
        header {
      background: linear-gradient(135deg, #1e3c72, #2a5298);
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 15px 40px;
      height: 15vh;              /* Professional height */
      color: #fff;
      flex-wrap: wrap;
      gap: 15px;
      box-shadow: 0 4px 8px rgba(0,0,0,0.1);
    }

    /* Left: Logo & Title */
    header .left {
      display: flex;
      align-items: center;
      gap: 15px;
    }

    header .left img {
      height: 55px;             /* Professional logo size */
      width: auto;
    }

    header .left h1 {
      font-size: 1.8rem;
      font-weight: 700;
      white-space: nowrap;
    }
    header .right button {
      background: #fff;
      color: #1877f2;
      padding: 8px 14px;
      border-radius: 6px;
      font-weight: 500;
      transition: background 0.3s ease;
    }
    .friend-btn {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 10px 16px;
      background: #1877f2;       /* Facebook blue */
      color: white;
      border-radius: 25px;
      text-decoration: none;
      font-size: 14px;
      font-weight: 500;
      transition: background 0.3s ease, transform 0.2s ease;
    }

    .friend-btn:hover {
      background: #0d65d9;
      transform: translateY(-2px);
    }

  </style>


</head>
<body>

    <header>
        <div class="left">
            <img src="../Daak-pion.png" alt="Logo">
            <h1>DAAK-PION</h1>
        </div>
        <div class="right">
            <a href="chatboard.php"><button>Back to Chat</button></a>
        </div>
    </header>

  <main class="profile-wrapper">
    <div class="cover-photo">
      <img src="<?php echo htmlspecialchars($coverPic); ?>" alt="Add Cover Photo">

    </div>

    <div class="profile-section">
      <div class="avatar-wrapper">
        <div class="avatar">
            <img src="<?php echo htmlspecialchars($profilePic); ?>" alt="Profile">
        </div>
      </div>

      <div class="info-actions">
        <h1 class="username"><?php echo htmlspecialchars($userName); ?></h1>
        <div class="display = 'flex'">
        <a href="friendlist.php" class="friend-btn">
          <i class="fa-solid fa-user-group"></i>
          <span>Your Friends</span>
        </a>

        <p class="friend-count"></p>
        </div>

        <div class="btn-group">
          <button class="btn primary" onclick="PrfEditRedirect()">Edit Profile</button>
          <a href="logout.php">
            <button class="btn danger">Log Out</button>
          </a>
        </div>
      </div>
    </div>
  </main>

  <script>
    function PrfEditRedirect(){
      window.location.href='edit-profile.php';
    }
  </script>

  
</body>
</html>
