<?php
session_start();
require_once "db_connect.php";

if (!isset($_SESSION['user_id'])) {
    // header("Location: index.html");
    exit;
}

$user_id = $_SESSION['user_id'];

/**
 * SMALL HELPER: die with DB error if prepare() fails
 */
function must_prepare(mysqli $conn, string $sql, string $label) : mysqli_stmt {
    $stmt = $conn->prepare($sql);
    if (!$stmt) {
        die("$label prepare() failed: " . $conn->error . "\nSQL: " . $sql);
    }
    return $stmt;
}

/* =========================
   1) USER INFO (ALIAS FIELDS)
   ========================= */
$sql = "SELECT Fname AS fname, lname AS iname, Dp AS dp FROM users WHERE id = ?";
$stmt = must_prepare($conn, $sql, "User info");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$user = $stmt->get_result()->fetch_assoc();
$stmt->close();

$userName   = htmlspecialchars(trim(($user['fname'] ?? '') . " " . ($user['iname'] ?? '')));
$profilePic = !empty($user['dp']) ? "../" . $user['dp'] : "https://cdn-icons-png.flaticon.com/512/149/149071.png";

/* =========================
   2) FRIENDS (UNION + ALIASES)
   friends: id, user1_id, user2_id, friends_since, status
   We fetch "the other party" for the logged-in user
   ========================= */
$friends = [];
$fq = "
(SELECT u.id, u.Fname AS fname, u.lname AS iname, u.Dp AS dp
   FROM friends f
   JOIN users u ON u.id = f.user2_id
  WHERE f.user1_id = ? AND f.status = 'active')
UNION
(SELECT u.id, u.Fname AS fname, u.lname AS iname, u.Dp AS dp
   FROM friends f
   JOIN users u ON u.id = f.user1_id
  WHERE f.user2_id = ? AND f.status = 'active')
";
$stmt = must_prepare($conn, $fq, "Friends");
$stmt->bind_param("ii", $user_id, $user_id);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) {
    $friends[] = $row;
}
$stmt->close();

/* For quick in-PHP filtering later */
$friendIds = array_column($friends, 'id');

/* =========================
   3) PENDING FRIEND REQUESTS (ALIAS FIELDS)
   friendrequests: id, sender_id, receiver_id, status, sent_at, responded_at
   Show requests sent TO the logged-in user
   ========================= */
$pending = [];
$pq = "
SELECT fr.id,
       u.Fname AS fname,
       u.lname AS lname,
       u.Dp    AS dp
  FROM friendrequests fr
  JOIN users u ON u.id = fr.sender_id
 WHERE fr.receiver_id = ?
   AND fr.status = 'pending'
ORDER BY fr.sent_at DESC
";
$stmt = must_prepare($conn, $pq, "Pending requests");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) {
    $pending[] = $row;
}
$stmt->close();

/* =========================
   4) ALL USERS (ALIAS FIELDS)
   We exclude self here, then exclude friends in PHP
   ========================= */
$allUsers = [];
$uq = "SELECT id, Fname AS fname, lname AS iname, Dp AS dp FROM users WHERE id != ?";
$stmt = must_prepare($conn, $uq, "All users");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) {
    if (!in_array($row['id'], $friendIds, true)) {
        $allUsers[] = $row;
    }
}
$stmt->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>DAAK-PION - Friends</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/7.0.0/css/all.min.css" />
  <style>
    body{font-family:Poppins,Arial,sans-serif;margin:0;background:#f4f6f9;}
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
    .container{max-width:1100px;margin:20px auto;padding:0 20px;}
    .profile-card{display:flex;justify-content:space-between;align-items:center;background:#fff;padding:15px;border-radius:10px;box-shadow:0 2px 6px rgba(0,0,0,0.1);}
    .profile-info{display:flex;align-items:center;gap:10px;}
    .profile-info img{width:50px;height:50px;border-radius:50%;object-fit:cover;}
    .section{margin-top:20px;}
    .section h2{margin-bottom:10px;}
    .friends-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:15px;}
    .friend-card{background:#fff;border-radius:10px;padding:12px;display:flex;justify-content:space-between;align-items:center;box-shadow:0 2px 5px rgba(0,0,0,0.08);}
    .friend-info{display:flex;align-items:center;gap:10px;}
    .friend-info img{width:42px;height:42px;border-radius:50%;object-fit:cover;}
    .btn-sm{padding:6px 10px;border:none;border-radius:6px;cursor:pointer;margin-left:5px;}
    .btn-accept{background:#2a9d8f;color:#fff;}
    .btn-decline{background:#e63946;color:#fff;}
    .chat-btn{font-size:18px;cursor:pointer;color:#1d3557;}
    .chat-btn:hover{color:#e63946;}
    .muted{color:#666;font-size:14px;}
    input[type="text"]{padding:8px 12px;border:1px solid #ccc;border-radius:8px;min-width:260px;}
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

<div class="container">
  <!-- Profile -->
  <div class="profile-card">
    <div class="profile-info">
      <a href="user-profile.php">
        <img src="<?php echo htmlspecialchars($profilePic); ?>" alt="profile">
      </a>
      <span><strong><?php echo $userName; ?></strong></span>
    </div>
    <input type="text" id="friendSearch" placeholder="Search users...">
  </div>

  <!-- Friends -->
  <div class="section">
    <h2>Your Friends</h2>
    <div class="friends-grid" id="friendsList">
      <?php if (empty($friends)) : ?>
        <p class="muted">No friends yet.</p>
      <?php else: ?>
        <?php foreach ($friends as $fr): ?>
          <div class="friend-card">
            <div class="friend-info">
              <img src="<?php echo !empty($fr['dp']) ? "../" . htmlspecialchars($fr['dp']) : "https://cdn-icons-png.flaticon.com/512/149/149071.png"; ?>" alt="friend">
              <span><?php echo htmlspecialchars($fr['fname'] . " " . $fr['iname']); ?></span>
            </div>
            <span class="chat-btn" title="Message"><i class="fa-solid fa-message"></i></span>
          </div>
        <?php endforeach; ?>
      <?php endif; ?>
    </div>
  </div>

  <!-- Friend Requests -->
  <div class="section">
    <h2>Friend Requests</h2>
    <div class="friends-grid" id="pendingList">
      <?php if (empty($pending)) : ?>
        <p class="muted">No pending requests.</p>
      <?php else: ?>
        <?php foreach ($pending as $req): ?>
          <div class="friend-card">
            <div class="friend-info">
              <img src="<?php echo !empty($req['dp']) ? "../" . htmlspecialchars($req['dp']) : "https://cdn-icons-png.flaticon.com/512/149/149071.png"; ?>" alt="requester">
              <span><?php echo htmlspecialchars($req['fname'] . " " . $req['lname']); ?></span>
            </div>
            <div>
              <button class="btn-sm btn-accept" onclick="respond(<?php echo (int)$req['id']; ?>,'accept')">Accept</button>
              <button class="btn-sm btn-decline" onclick="respond(<?php echo (int)$req['id']; ?>,'decline')">Decline</button>
            </div>
          </div>
        <?php endforeach; ?>
      <?php endif; ?>
    </div>
  </div>

  <!-- All Users -->
  <div class="section">
    <h2>Find New Friends</h2>
    <div class="friends-grid" id="allUsersList">
      <?php if (empty($allUsers)) : ?>
        <p class="muted">No users to show.</p>
      <?php else: ?>
        <?php foreach ($allUsers as $u): ?>
          <div class="friend-card">
            <div class="friend-info">
              <img src="<?php echo !empty($u['dp']) ? "../" . htmlspecialchars($u['dp']) : "https://cdn-icons-png.flaticon.com/512/149/149071.png"; ?>" alt="user">
              <span class="user-name"><?php echo htmlspecialchars($u['fname'] . " " . $u['iname']); ?></span>
            </div>
            <span class="chat-btn add-friend-btn" data-id="<?php echo (int)$u['id']; ?>" title="Add Friend">
              <i class="fa-solid fa-user-plus"></i>
            </span>
          </div>
        <?php endforeach; ?>
      <?php endif; ?>
    </div>
  </div>
</div>

<script>
// --- Search Filter (on Find New Friends list) ---
const searchInput = document.getElementById('friendSearch');
const allUsersList = document.getElementById('allUsersList');
searchInput?.addEventListener('keyup', () => {
  const filter = searchInput.value.toLowerCase();
  const cards = allUsersList.querySelectorAll('.friend-card');
  cards.forEach(card => {
    const name = card.querySelector('.user-name')?.innerText?.toLowerCase() || '';
    card.style.display = name.includes(filter) ? '' : 'none';
  });
});

// --- Send Friend Request ---
document.querySelectorAll('.add-friend-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const receiverId = btn.dataset.id;
    fetch("send_request.php", {
      method: "POST",
      headers: {"Content-Type":"application/x-www-form-urlencoded"},
      body: "receiver_id=" + encodeURIComponent(receiverId)
    })
    .then(r => r.text())
    .then(msg => alert(msg))
    .catch(() => alert('Network error'));
  });
});

// --- Respond to Friend Request ---
function respond(id, action){
  fetch("respond_request.php", {
    method: "POST",
    headers: {"Content-Type":"application/x-www-form-urlencoded"},
    body: "request_id=" + encodeURIComponent(id) + "&action=" + encodeURIComponent(action)
  })
  .then(r => r.text())
  .then(msg => alert(msg))
  .catch(() => alert('Network error'));
}
</script>
</body>
</html>