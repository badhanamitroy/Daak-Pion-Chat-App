<?php
require_once __DIR__ . "/bootstrap_security.php";

if (!isset($_SESSION['user_id'])) {
    header("Location: ../index.html");
    exit;
}

\Daakpion\Security\SessionManager::checkRestrictedAccess();


$user_id = $_SESSION['user_id'];

function must_prepare(mysqli $conn, string $sql, string $label) : mysqli_stmt {
    $stmt = $conn->prepare($sql);
    if (!$stmt) {
        // Resolves DP-VULN-04: Log technical error details on the server, suppress SQL/table leakage to client
        error_log("Database prepare error in {$label}: " . $conn->error . " | SQL: " . $sql);
        http_response_code(500);
        die("A system error occurred. Please try again later.");
    }
    return $stmt;
}

$sql = "SELECT Fname AS fname, lname AS iname, Dp AS dp FROM users WHERE id = ?";
$stmt = must_prepare($conn, $sql, "User info");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$user = $stmt->get_result()->fetch_assoc();
$stmt->close();

$userName   = htmlspecialchars(trim(($user['fname'] ?? '') . " " . ($user['iname'] ?? '')));
$profilePic = !empty($user['dp']) ? "../" . $user['dp'] : "https://cdn-icons-png.flaticon.com/512/149/149071.png";

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
LIMIT 100
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
LIMIT 100
";
$stmt = must_prepare($conn, $pq, "Pending requests");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) {
    $pending[] = $row;
}
$stmt->close();

$allUsers = [];
$uq = "SELECT id, Fname AS fname, lname AS iname, Dp AS dp FROM users WHERE id != ? ORDER BY id ASC LIMIT 100";
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
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>DaakPion — Friends</title>
  <meta name="description" content="Find and connect with friends on DaakPion.">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <meta name="csrf-token" content="<?php echo htmlspecialchars(\Daakpion\Security\CsrfProtection::getToken()); ?>" />
  <link rel="stylesheet" href="../css/shared-header.css?v=<?php echo time(); ?>" />
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" crossorigin="anonymous" referrerpolicy="no-referrer" />
  <style>
<?php @readfile(__DIR__ . '/../css/shared-header.css'); ?>
    /* ── Page-level dark styles ── */
    body { background: #18191a; color: #e4e6eb; }

    .page-container {
      max-width: 1100px;
      margin: 0 auto;
      padding: 24px 20px 60px;
      animation: fadeUp 0.4s ease both;
    }

    @keyframes fadeUp {
      from { opacity: 0; transform: translateY(14px); }
      to   { opacity: 1; transform: translateY(0); }
    }

    /* ── Search bar area ── */
    .search-bar-area {
      display: flex;
      align-items: center;
      gap: 14px;
      background: #242526;
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 12px;
      padding: 14px 20px;
      margin-bottom: 28px;
      box-shadow: 0 2px 12px rgba(0,0,0,0.3);
    }

    .search-bar-area .user-avatar {
      width: 44px;
      height: 44px;
      border-radius: 50%;
      object-fit: cover;
      border: 2px solid rgba(255,255,255,0.15);
      cursor: pointer;
      flex-shrink: 0;
    }

    .search-bar-area .search-wrap {
      flex: 1;
      display: flex;
      align-items: center;
      gap: 10px;
      background: #3a3b3c;
      border-radius: 24px;
      padding: 9px 16px;
    }

    .search-bar-area .search-wrap i {
      color: #b0b3b8;
      font-size: 14px;
    }

    .search-bar-area input {
      flex: 1;
      background: transparent;
      border: none;
      outline: none;
      color: #e4e6eb;
      font-family: 'Inter', Arial, sans-serif;
      font-size: 14px;
    }

    .search-bar-area input::placeholder { color: #b0b3b8; }

    /* ── Section headings ── */
    .section { margin-bottom: 32px; }

    .section-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 16px;
    }

    .section-header h2 {
      font-size: 1.2rem;
      font-weight: 800;
      color: #e4e6eb;
    }

    .section-count {
      font-size: 0.85rem;
      color: #b0b3b8;
      background: #3a3b3c;
      padding: 3px 10px;
      border-radius: 20px;
    }

    /* ── People Grid ── */
    .people-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
      gap: 14px;
    }

    /* ── People Card (FB-style: photo top, name middle, buttons bottom) ── */
    .person-card {
      background: #242526;
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,0.08);
      overflow: hidden;
      transition: transform 0.2s, box-shadow 0.2s;
      box-shadow: 0 2px 10px rgba(0,0,0,0.3);
    }

    .person-card:hover {
      transform: translateY(-3px);
      box-shadow: 0 6px 20px rgba(0,0,0,0.4);
    }

    .person-card .card-photo {
      width: 100%;
      height: 160px;
      object-fit: cover;
      display: block;
      background: #3a3b3c;
    }

    .person-card .card-body {
      padding: 12px 12px 14px;
    }

    .person-card .card-name {
      font-size: 0.95rem;
      font-weight: 700;
      color: #e4e6eb;
      margin-bottom: 10px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .person-card .card-actions {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .card-btn {
      width: 100%;
      padding: 8px 10px;
      border: none;
      border-radius: 8px;
      font-family: 'Inter', Arial, sans-serif;
      font-size: 0.85rem;
      font-weight: 700;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      text-decoration: none;
      transition: background 0.2s, transform 0.15s;
    }

    .card-btn:active { transform: scale(0.97); }

    .card-btn.blue  { background: #1877f2; color: #fff; }
    .card-btn.blue:hover  { background: #166fe5; }

    .card-btn.gray  { background: #3a3b3c; color: #e4e6eb; }
    .card-btn.gray:hover  { background: #4e4f50; }

    .card-btn.green { background: #42b72a; color: #fff; }
    .card-btn.green:hover { background: #36a020; }

    .card-btn.red   { background: rgba(228,30,63,0.15); color: #e41e3f; border: 1px solid rgba(228,30,63,0.3); }
    .card-btn.red:hover { background: #e41e3f; color: #fff; }

    /* ── Empty state ── */
    .empty-state {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 10px;
      padding: 40px 20px;
      color: #b0b3b8;
      text-align: center;
    }

    .empty-state i {
      font-size: 2.8rem;
      color: #4e4f50;
    }

    .empty-state p {
      font-size: 0.9rem;
    }

    /* ── Toast notification ── */
    #toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: #242526;
      border: 1px solid rgba(255,255,255,0.15);
      color: #e4e6eb;
      padding: 12px 22px;
      border-radius: 10px;
      font-size: 14px;
      opacity: 0;
      transition: opacity 0.3s ease, transform 0.3s ease;
      pointer-events: none;
      z-index: 9999;
      transform: translateY(10px);
    }
    #toast.show { opacity: 1; transform: translateY(0); }

    @media (max-width: 600px) {
      .people-grid { grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); }
      .person-card .card-photo { height: 130px; }
    }
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
      <a href="user-profile.php"><button><i class="fa-solid fa-user"></i> Profile</button></a>
      <a href="chatboard.php"><button class="primary"><i class="fa-solid fa-comments"></i> Messenger</button></a>
    </div>
  </header>

  <div class="page-container">

    <!-- ── Search + User Row ── -->
    <div class="search-bar-area">
      <a href="user-profile.php">
        <img class="user-avatar" src="<?php echo htmlspecialchars($profilePic); ?>" alt="My Profile">
      </a>
      <div class="search-wrap">
        <i class="fa-solid fa-magnifying-glass"></i>
        <input type="text" id="friendSearch" placeholder="Search people…">
      </div>
    </div>

    <!-- ── Your Friends ── -->
    <div class="section">
      <div class="section-header">
        <h2>Your Friends</h2>
        <span class="section-count"><?php echo count($friends); ?></span>
      </div>
      <div class="people-grid" id="friendsList">
        <?php if (empty($friends)) : ?>
          <div class="empty-state">
            <i class="fa-solid fa-user-slash"></i>
            <p>No friends yet.<br>Find people below!</p>
          </div>
        <?php else: ?>
          <?php foreach ($friends as $fr): ?>
            <div class="person-card">
              <img class="card-photo"
                   src="<?php echo !empty($fr['dp']) ? '../'.htmlspecialchars($fr['dp']) : 'https://cdn-icons-png.flaticon.com/512/149/149071.png'; ?>"
                   alt="<?php echo htmlspecialchars($fr['fname'].' '.$fr['iname']); ?>">
              <div class="card-body">
                <div class="card-name"><?php echo htmlspecialchars($fr['fname'].' '.$fr['iname']); ?></div>
                <div class="card-actions">
                  <a class="card-btn blue" href="chatboard.php?friend_id=<?php echo (int)$fr['id']; ?>">
                    <i class="fa-solid fa-message"></i> Message
                  </a>
                </div>
              </div>
            </div>
          <?php endforeach; ?>
        <?php endif; ?>
      </div>
    </div>

    <!-- ── Friend Requests ── -->
    <?php if (!empty($pending)) : ?>
    <div class="section">
      <div class="section-header">
        <h2>Friend Requests</h2>
        <span class="section-count"><?php echo count($pending); ?></span>
      </div>
      <div class="people-grid" id="pendingList">
        <?php foreach ($pending as $req): ?>
          <div class="person-card">
            <img class="card-photo"
                 src="<?php echo !empty($req['dp']) ? '../'.htmlspecialchars($req['dp']) : 'https://cdn-icons-png.flaticon.com/512/149/149071.png'; ?>"
                 alt="<?php echo htmlspecialchars($req['fname'].' '.$req['lname']); ?>">
            <div class="card-body">
              <div class="card-name"><?php echo htmlspecialchars($req['fname'].' '.$req['lname']); ?></div>
              <div class="card-actions">
                <button class="card-btn green" onclick="respond(<?php echo (int)$req['id']; ?>,'accept')">
                  <i class="fa-solid fa-check"></i> Confirm
                </button>
                <button class="card-btn red" onclick="respond(<?php echo (int)$req['id']; ?>,'decline')">
                  <i class="fa-solid fa-xmark"></i> Delete
                </button>
              </div>
            </div>
          </div>
        <?php endforeach; ?>
      </div>
    </div>
    <?php endif; ?>

    <!-- ── People You May Know ── -->
    <div class="section">
      <div class="section-header">
        <h2>People You May Know</h2>
        <span class="section-count"><?php echo count($allUsers); ?></span>
      </div>
      <div class="people-grid" id="allUsersList">
        <?php if (empty($allUsers)) : ?>
          <div class="empty-state">
            <i class="fa-solid fa-users"></i>
            <p>No new people to show right now.</p>
          </div>
        <?php else: ?>
          <?php foreach ($allUsers as $u): ?>
            <div class="person-card">
              <img class="card-photo"
                   src="<?php echo !empty($u['dp']) ? '../'.htmlspecialchars($u['dp']) : 'https://cdn-icons-png.flaticon.com/512/149/149071.png'; ?>"
                   alt="<?php echo htmlspecialchars($u['fname'].' '.$u['iname']); ?>">
              <div class="card-body">
                <div class="card-name user-name"><?php echo htmlspecialchars($u['fname'].' '.$u['iname']); ?></div>
                <div class="card-actions">
                  <button class="card-btn blue add-friend-btn" data-id="<?php echo (int)$u['id']; ?>">
                    <i class="fa-solid fa-user-plus"></i> Add Friend
                  </button>
                </div>
              </div>
            </div>
          <?php endforeach; ?>
        <?php endif; ?>
      </div>
    </div>

  </div><!-- /page-container -->

<div id="toast"></div>

<script>
// ── Toast notification helper (replaces alert() calls) ──────────────────────
function showToast(msg, duration = 3000) {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), duration);
}

// ── Search filter: Find New Friends list ─────────────────────────────────────
const searchInput  = document.getElementById('friendSearch');
const allUsersList = document.getElementById('allUsersList');
searchInput?.addEventListener('keyup', () => {
  const filter = searchInput.value.toLowerCase();
  allUsersList.querySelectorAll('.friend-card').forEach(card => {
    const name = card.querySelector('.user-name')?.textContent?.toLowerCase() || '';
    card.style.display = name.includes(filter) ? '' : 'none';
  });
});

// ── Send Friend Request ──────────────────────────────────────────────────────
document.querySelectorAll('.add-friend-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const receiverId = btn.dataset.id;
    const csrfToken  = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
    btn.style.pointerEvents = 'none'; // prevent double-click
    fetch('send_request.php', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-CSRF-Token': csrfToken
      },
      body: 'receiver_id=' + encodeURIComponent(receiverId) + '&csrf_token=' + encodeURIComponent(csrfToken)
    })
    .then(r => r.text())
    .then(msg => {
      showToast(msg);
      // Swap icon to a checkmark to give visual feedback
      btn.innerHTML = '<i class="fa-solid fa-check"></i>';
      btn.title = 'Request sent';
    })
    .catch(() => {
      showToast('Network error — please try again.');
      btn.style.pointerEvents = '';
    });
  });
});

// ── Accept / Decline Friend Request ─────────────────────────────────────────
function respond(id, action) {
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
  fetch('respond_request.php', {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-CSRF-Token': csrfToken
    },
    body: 'request_id=' + encodeURIComponent(id) + '&action=' + encodeURIComponent(action) + '&csrf_token=' + encodeURIComponent(csrfToken)
  })
  .then(r => r.text())
  .then(msg => {
    showToast(msg);
    // Reload the page after a short delay so the card disappears
    setTimeout(() => location.reload(), 1500);
  })
  .catch(() => showToast('Network error — please try again.'));
}
</script>
</body>
</html>
