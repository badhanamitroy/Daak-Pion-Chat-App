<?php
require_once __DIR__ . "/bootstrap_security.php";

if (!isset($_SESSION['user_id'])) {
    header("Location: ../index.html");
    exit;
}

\Daakpion\Security\SessionManager::checkRestrictedAccess();


$user_id = $_SESSION['user_id'];

// --- Fetch user info ---
$sql = "SELECT fname, lname, dp, coverpic FROM users WHERE id = ?";
$stmt = $conn->prepare($sql); 
$stmt->bind_param("i", $user_id);
$stmt->execute();
$user = $stmt->get_result()->fetch_assoc();
$stmt->close();

$userName   = trim(($user['fname'] ?? "User") . " " . ($user['lname'] ?? ""));
$profilePic = !empty($user['dp']) ? "../" . $user['dp'] : "../ProfilePics/default.jpg";
$coverPic   = !empty($user['coverpic']) ? "../" . $user['coverpic'] : "../Coverpics/default.jpg";

// --- Fetch Friends with Presence State (Resolves DP-P4-009) ---
$friends = [];
$sql = "
(SELECT u.id, u.fname, u.lname, u.dp,
        (CASE WHEN u.status != 'Offline' 
                   AND u.last_activity_at IS NOT NULL 
                   AND TIMESTAMPDIFF(SECOND, u.last_activity_at, NOW()) <= 120 
              THEN 1 ELSE 0 END) AS is_online
 FROM friends f 
 JOIN users u ON u.id = f.user2_id 
 WHERE f.user1_id=? AND f.status='active')
UNION
(SELECT u.id, u.fname, u.lname, u.dp,
        (CASE WHEN u.status != 'Offline' 
                   AND u.last_activity_at IS NOT NULL 
                   AND TIMESTAMPDIFF(SECOND, u.last_activity_at, NOW()) <= 120 
              THEN 1 ELSE 0 END) AS is_online
 FROM friends f 
 JOIN users u ON u.id = f.user1_id 
 WHERE f.user2_id=? AND f.status='active')
LIMIT 100
";
$stmt = $conn->prepare($sql);
$stmt->bind_param("ii", $user_id, $user_id);
$stmt->execute();
$res = $stmt->get_result();
while($row = $res->fetch_assoc()) $friends[] = $row;
$stmt->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>DaakPion — Messenger</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<meta name="csrf-token" content="<?php echo htmlspecialchars(\Daakpion\Security\CsrfProtection::getToken()); ?>" />
<link rel="stylesheet" href="../chatboard.css?v=<?php echo time()?>"/>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" crossorigin="anonymous" referrerpolicy="no-referrer"/>
<style>
<?php @readfile(__DIR__ . '/../chatboard.css'); ?>
</style>
</head>
<body>

<div class="messenger-app">

  <!-- ══ SIDEBAR ══ -->
  <aside class="sidebar">

    <!-- Sidebar Header -->
    <div class="sidebar-header">
      <div class="sidebar-top">
        <a class="sidebar-brand" href="../index.html">
          <img src="../Daak-pion.png" alt="DaakPion Logo"/>
          <span>DaakPion</span>
        </a>
        <div class="sidebar-top-actions">
          <a class="icon-btn" href="user-profile.php" title="Profile"><i class="fa-solid fa-user"></i></a>
          <a class="icon-btn" href="friendlist.php" title="Friends"><i class="fa-solid fa-user-group"></i></a>
        </div>
      </div>
      <!-- Search -->
      <div class="sidebar-search">
        <i class="fa-solid fa-magnifying-glass"></i>
        <input type="text" placeholder="Search Messenger" id="friendSearch"/>
      </div>
    </div>

    <!-- Friends Label -->
    <div class="friends-label">Conversations</div>

    <!-- Friend List -->
    <div class="friend-list" id="friendList">
      <?php if(empty($friends)) : ?>
        <div class="no-friends-msg">
          <i class="fa-solid fa-user-slash"></i>
          <p>No friends yet.<br>Go to <a href="friendlist.php" style="color:#1877f2">Find Friends</a> to connect!</p>
        </div>
      <?php else: ?>
        <?php foreach($friends as $fr): ?>
        <div class="friend-card" data-id="<?php echo (int)$fr['id']; ?>"
             data-name="<?php echo htmlspecialchars($fr['fname'].' '.$fr['lname']); ?>"
             data-img="<?php echo !empty($fr['dp']) ? '../'.htmlspecialchars($fr['dp']) : 'https://cdn-icons-png.flaticon.com/512/149/149071.png'; ?>"
             data-online="<?php echo !empty($fr['is_online']) ? '1' : '0'; ?>">
          <div class="friend-avatar-wrap">
            <img src="<?php echo !empty($fr['dp']) ? '../'.htmlspecialchars($fr['dp']) : 'https://cdn-icons-png.flaticon.com/512/149/149071.png'; ?>"
                 alt="<?php echo htmlspecialchars($fr['fname'].' '.$fr['lname']); ?>"/>
            <span class="online-dot" id="dot-<?php echo (int)$fr['id']; ?>" style="<?php echo !empty($fr['is_online']) ? '' : 'display:none;'; ?>"></span>
          </div>
          <div class="friend-text">
            <div class="friend-name"><?php echo htmlspecialchars($fr['fname'].' '.$fr['lname']); ?></div>
            <div class="friend-preview">Click to start chatting</div>
          </div>
          <i class="fa-solid fa-message friend-chat-icon"></i>
        </div>
        <?php endforeach; ?>
      <?php endif; ?>
    </div>

    <!-- Sidebar Footer: Profile + Logout -->
    <div class="sidebar-footer">
      <img src="<?php echo htmlspecialchars($profilePic); ?>" alt="Profile" onclick="profileRedirect()" title="My Profile"/>
      <span class="footer-name" onclick="profileRedirect()"><?php echo htmlspecialchars($userName); ?></span>
      <form method="post" action="logout.php" class="logout-form">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(\Daakpion\Security\CsrfProtection::getToken()); ?>" />
        <button class="logout-btn" type="submit" name="logout" title="Log Out">
          <i class="fa-solid fa-right-from-bracket"></i>
        </button>
      </form>
    </div>

  </aside>

  <!-- ══ CHAT AREA ══ -->
  <main class="chat-area">

    <!-- Chat Header -->
    <div class="chat-header">
      <div class="chat-header-avatar">
        <img src="" alt="Friend" id="chatHeaderImg"/>
      </div>
      <div class="chat-header-info">
        <div id="chatHeaderName" class="chat-header-placeholder">Select a conversation</div>
        <div id="chatHeaderStatus" style="display:none;">Offline</div>
      </div>
    </div>

    <!-- Messages -->
    <div class="chat-box" id="chatBox">
      <div class="chat-empty">
        <i class="fa-solid fa-comments"></i>
        <h3>Your Messages</h3>
        <p>Select a conversation from the left<br>to start chatting.</p>
      </div>
    </div>

    <!-- Input Bar -->
    <div class="chat-input-bar">
      <button class="input-icon-btn" title="Emoji"><i class="fa-regular fa-face-smile"></i></button>
      <div class="chat-input-wrap">
        <input type="text" placeholder="Aa" id="chatInput" autocomplete="off"/>
      </div>
      <button class="input-icon-btn" title="Attach"><i class="fa-solid fa-paperclip"></i></button>
      <button class="send-btn" id="sendBtn" title="Send">
        <i class="fa-solid fa-paper-plane"></i>
      </button>
    </div>

  </main>
</div>

<script>
// --- Redirect to profile ---
function profileRedirect(){ window.location.href='user-profile.php'; }

// --- DOM references ---
const userId          = <?php echo (int)$user_id; ?>;
const friendCards     = document.querySelectorAll('.friend-card');
const chatHeaderName  = document.getElementById('chatHeaderName');
const chatHeaderImg   = document.getElementById('chatHeaderImg');
const chatHeaderStatus = document.getElementById('chatHeaderStatus');
const chatBox         = document.getElementById('chatBox');
const chatInput       = document.getElementById('chatInput');
const sendBtn         = document.getElementById('sendBtn');
const searchInput     = document.getElementById('friendSearch');

let currentFriendId = null;
let lastMessageId   = 0;
let pollTimer       = null;

// --- Click a friend card to open chat ---
friendCards.forEach(card => {
  card.addEventListener('click', () => {
    friendCards.forEach(c => c.classList.remove('active'));
    card.classList.add('active');

    currentFriendId = card.dataset.id;
    lastMessageId   = 0;

    const friendName = card.dataset.name || 'Friend';
    const friendImg  = card.dataset.img  || '';
    const isOnline   = card.dataset.online === '1';

    chatHeaderName.textContent = friendName;
    chatHeaderName.classList.remove('chat-header-placeholder');
    chatHeaderImg.src  = friendImg;
    chatHeaderImg.style.display = 'block';

    // Set initial presence from card and fetch latest server status (Resolves DP-P4-009)
    chatHeaderStatus.textContent = isOnline ? 'Active now' : 'Offline';
    chatHeaderStatus.style.color = isOnline ? '#31a24c' : 'var(--text-muted, #888)';
    chatHeaderStatus.style.display = 'block';
    updateFriendPresence(currentFriendId);

    chatBox.innerHTML = '<p class="muted">Loading messages...</p>';
    loadMessages(currentFriendId, true);
    startPolling();
  });
});

// --- Render a single message bubble (XSS-safe) ---
function renderMessage(msg) {
  const div = document.createElement('div');
  div.className = msg.sender_id == userId ? 'message sent' : 'message received';
  const p = document.createElement('p');
  p.textContent = msg.message;
  div.appendChild(p);
  chatBox.appendChild(div);
  if (parseInt(msg.id) > lastMessageId) lastMessageId = parseInt(msg.id);
}

// --- Load messages from server ---
function loadMessages(friendId, isInitialLoad = false) {
  fetch(`get_messages.php?friend_id=${friendId}&since_id=${isInitialLoad ? 0 : lastMessageId}`)
    .then(res => res.json())
    .then(data => {
      if (isInitialLoad) chatBox.innerHTML = '';
      if (data.length === 0 && isInitialLoad) {
        chatBox.innerHTML = '<p class="muted">No messages yet. Say hello! 👋</p>';
        return;
      }
      if (data.length > 0) {
        const placeholder = chatBox.querySelector('.muted');
        if (placeholder) placeholder.remove();
        data.forEach(renderMessage);
        chatBox.scrollTop = chatBox.scrollHeight;
      }
    })
    .catch(err => console.error('loadMessages error:', err));
}

// --- Poll every 3 seconds for messages and friend presence ---
function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(() => {
    if (currentFriendId) {
      loadMessages(currentFriendId, false);
      updateFriendPresence(currentFriendId);
    }
  }, 3000);
}

// --- Presence & Heartbeat Tracking (Resolves DP-P4-009) ---
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';

function updateFriendPresence(friendId) {
  if (!friendId) return;
  fetch(`get_presence.php?friend_id=${friendId}`)
    .then(res => res.json())
    .then(data => {
      if (data && currentFriendId == friendId) {
        chatHeaderStatus.textContent = data.status_text || 'Offline';
        chatHeaderStatus.style.color = data.is_online ? '#31a24c' : 'var(--text-muted, #888)';
        const dot = document.getElementById(`dot-${friendId}`);
        if (dot) dot.style.display = data.is_online ? 'block' : 'none';
        const card = document.querySelector(`.friend-card[data-id="${friendId}"]`);
        if (card) card.dataset.online = data.is_online ? '1' : '0';
      }
    })
    .catch(() => {});
}

function updateAllPresence() {
  fetch('get_presence.php')
    .then(res => res.json())
    .then(data => {
      if (data && data.presence) {
        for (const [fid, p] of Object.entries(data.presence)) {
          const dot = document.getElementById(`dot-${fid}`);
          if (dot) dot.style.display = p.is_online ? 'block' : 'none';
          const card = document.querySelector(`.friend-card[data-id="${fid}"]`);
          if (card) card.dataset.online = p.is_online ? '1' : '0';
          if (currentFriendId == fid) {
            chatHeaderStatus.textContent = p.status_text;
            chatHeaderStatus.style.color = p.is_online ? '#31a24c' : 'var(--text-muted, #888)';
          }
        }
      }
    })
    .catch(() => {});
}

function sendHeartbeat() {
  if (!csrfToken) return;
  const formData = new FormData();
  formData.append('csrf_token', csrfToken);
  fetch('heartbeat.php', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    body: formData
  }).catch(() => {});
}

sendHeartbeat();
setInterval(sendHeartbeat, 30000);
setInterval(updateAllPresence, 10000);

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') {
    sendHeartbeat();
    if (currentFriendId) updateFriendPresence(currentFriendId);
    updateAllPresence();
  }
});

// --- Auto-open from URL ?friend_id=X ---
(function autoOpenFromUrl() {
  const urlParams    = new URLSearchParams(window.location.search);
  const autoFriendId = urlParams.get('friend_id');
  if (!autoFriendId) return;
  const targetCard = document.querySelector(`.friend-card[data-id="${autoFriendId}"]`);
  if (targetCard) {
    targetCard.click();
    targetCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
    history.replaceState(null, '', window.location.pathname);
  }
})();

// --- Send message ---
function doSend() {
  const msg = chatInput.value.trim();
  if (!msg || !currentFriendId) return;
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
  fetch('send_message.php', {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-CSRF-Token': csrfToken
    },
    body: `receiver_id=${currentFriendId}&message=${encodeURIComponent(msg)}&csrf_token=${encodeURIComponent(csrfToken)}`
  }).then(async res => {
    if (!res.ok) {
      const errText = await res.text();
      alert(errText || 'Failed to send message.');
      return;
    }
    chatInput.value = '';
    loadMessages(currentFriendId, false);
  }).catch(err => {
    console.error('Send error:', err);
  });
}
sendBtn.addEventListener('click', doSend);
chatInput.addEventListener('keydown', e => { if (e.key === 'Enter') doSend(); });

// --- Search filter ---
searchInput.addEventListener('keyup', () => {
  const filter = searchInput.value.toLowerCase();
  friendCards.forEach(card => {
    const name = (card.dataset.name || '').toLowerCase();
    card.style.display = name.includes(filter) ? '' : 'none';
  });
});
</script>
</body>
</html>

