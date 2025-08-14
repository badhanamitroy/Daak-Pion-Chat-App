<?php
session_start();

// Check if user is logged in, e.g., user_id is set in session
if (!isset($_SESSION['user_id'])) {
    // User not logged in, redirect to login page
    header("Location: index.html"); // Adjust to your login page URL
    exit;
}

// Optionally, get user info from session
$userName = isset($_SESSION['user_name']) ? $_SESSION['user_name'] : "User";
?>


<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Profile - DaakPion</title>
  <link rel="stylesheet" href="../user-profile.css" />
</head>
<body>

  <header class="topbar">
    <div class="logo">DaakPion</div>
    <a href="chatboard.php" class="back-chat-btn">Back to Chat</a>
  </header>

  <main class="profile-wrapper">
    <div class="cover-photo">
      <img src="" alt="Add Cover Photo">
    </div>

    <div class="profile-section">
      <div class="avatar-wrapper">
        <div class="avatar">
            <img src="<?php echo htmlspecialchars($profilePic); ?>" alt="Profile">
          <!-- <img src="../dp.png" alt="Profile Picture"> -->
        </div>
      </div>

      <div class="info-actions">
        <h1 class="username"><?php echo htmlspecialchars($userName); ?></h1>
        <p class="friend-count">123 Friends</p>

        <div class="btn-group">
          <button class="btn primary" onclick="PrfEditRedirect()">Edit Profile</button>
          <button class="btn danger">Log Out</button>
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
