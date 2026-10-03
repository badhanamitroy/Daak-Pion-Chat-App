<?php
// user-profile.php
require_once __DIR__ . "/bootstrap_security.php";

if (!isset($_SESSION['user_id'])) {
    header("Location: ../index.html");
    exit;
}

\Daakpion\Security\SessionManager::checkRestrictedAccess();


$user_id = (int)$_SESSION['user_id'];

// Fetch user profile
$stmt = $conn->prepare("SELECT fname, lname, dp, coverpic FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$user = $stmt->get_result()->fetch_assoc();
$stmt->close();

$userfName  = $user['fname'] ?? "User";
$userlName  = $user['lname'] ?? "";
$userName   = trim($userfName . " " . $userlName);
$profilePic = !empty($user['dp'])      ? "../" . $user['dp']      : "../ProfilePics/default.jpg";
$coverPic   = !empty($user['coverpic']) ? "../" . $user['coverpic'] : "../Coverpics/default.jpg";

// Step 3.5 — Fetch friend count (was always empty before)
$cntStmt = $conn->prepare("
    SELECT COUNT(*) AS cnt FROM friends
    WHERE (user1_id = ? OR user2_id = ?) AND status = 'active'
");
$cntStmt->bind_param("ii", $user_id, $user_id);
$cntStmt->execute();
$friendCount = (int)($cntStmt->get_result()->fetch_assoc()['cnt'] ?? 0);
$cntStmt->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="color-scheme" content="dark" />
  <title><?php echo htmlspecialchars($userName); ?> — DaakPion Profile</title>
  <meta name="description" content="View <?php echo htmlspecialchars($userName); ?>'s profile on DaakPion.">

  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="../css/shared-header.css?v=<?php echo time(); ?>" />
  <link rel="stylesheet" href="../user-profile.css?v=<?php echo time(); ?>" />
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" crossorigin="anonymous" referrerpolicy="no-referrer" />
  <style>
<?php @readfile(__DIR__ . '/../css/shared-header.css'); ?>
<?php @readfile(__DIR__ . '/../user-profile.css'); ?>
  </style>
</head>
<body>

  <!-- ── Shared Header ── -->
  <header>
    <div class="left">
      <img src="../Daak-pion.png" alt="DaakPion Logo">
      <h1>DaakPion</h1>
    </div>
    <div class="right">
      <a href="friendlist.php"><button><i class="fa-solid fa-user-group"></i> Friends</button></a>
      <a href="chatboard.php"><button class="primary"><i class="fa-solid fa-comments"></i> Messenger</button></a>
    </div>
  </header>

  <!-- ── Profile Page ── -->
  <main class="profile-wrapper">

    <!-- Cover Photo -->
    <div class="cover-photo">
      <img src="<?php echo htmlspecialchars($coverPic); ?>" alt="Cover Photo">
    </div>

    <!-- Profile Card Section -->
    <div class="profile-section">

      <!-- Avatar overlapping cover -->
      <div class="avatar-wrapper">
        <div class="avatar">
          <img src="<?php echo htmlspecialchars($profilePic); ?>" alt="Profile Picture">
        </div>
      </div>

      <!-- Name + Stats + Actions -->
      <div class="info-actions">
        <div class="profile-name-section">
          <h1 class="username"><?php echo htmlspecialchars($userName); ?></h1>
          <div class="friend-count-row">
            <i class="fa-solid fa-user-group"></i>
            <strong><?php echo $friendCount; ?></strong>
            <?php echo $friendCount === 1 ? 'friend' : 'friends'; ?>
          </div>
          <div class="btn-group">
            <a href="friendlist.php" class="friend-btn">
              <i class="fa-solid fa-user-group"></i> Your Friends
            </a>
          </div>
        </div>

        <!-- Action Buttons -->
        <div class="btn-group">
          <button class="btn primary" onclick="window.location.href='edit-profile.php'">
            <i class="fa-solid fa-pen-to-square"></i> Edit Profile
          </button>
          <a href="chatboard.php">
            <button class="btn secondary">
              <i class="fa-solid fa-message"></i> Messages
            </button>
          </a>
          <form method="post" action="logout.php" style="display:inline;">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(\Daakpion\Security\CsrfProtection::getToken()); ?>" />
            <button class="btn danger" type="submit">
              <i class="fa-solid fa-right-from-bracket"></i> Log Out
            </button>
          </form>
        </div>
      </div>

      <div class="profile-divider"></div>
    </div>

    <!-- Two-column body -->
    <div class="profile-body">

      <!-- Left: Intro -->
      <div class="intro-card">
        <h3>Intro</h3>
        <div class="intro-item">
          <i class="fa-solid fa-user"></i>
          <span><?php echo htmlspecialchars($userName); ?></span>
        </div>
        <div class="intro-item">
          <i class="fa-solid fa-envelope"></i>
          <span>Member of DaakPion</span>
        </div>
        <div class="intro-item">
          <i class="fa-solid fa-user-group"></i>
          <span><?php echo $friendCount; ?> <?php echo $friendCount === 1 ? 'friend' : 'friends'; ?></span>
        </div>
        <div class="intro-item">
          <i class="fa-solid fa-message"></i>
          <span>Real-time messaging</span>
        </div>
      </div>

      <!-- Right: Activity Placeholder -->
      <div class="activity-card">
        <i class="fa-solid fa-layer-group"></i>
        <h3>Timeline & Activity</h3>
        <p style="color:#6e6f72; font-size:0.875rem;">Coming soon — posts and activity will appear here.</p>
      </div>

    </div>
  </main>

</body>
</html>

