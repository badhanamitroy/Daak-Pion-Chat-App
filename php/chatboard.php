<?php
session_start();
require_once "db_connect.php"; 

if (!isset($_SESSION['user_id'])) {
    header("Location: index.html");
    exit;
}

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

// --- Fetch Friends ---
$friends = [];
$sql = "
(SELECT u.id, u.fname, u.lname, u.dp 
 FROM friends f 
 JOIN users u ON u.id = f.user2_id 
 WHERE f.user1_id=? AND f.status='active')
UNION
(SELECT u.id, u.fname, u.lname, u.dp 
 FROM friends f 
 JOIN users u ON u.id = f.user1_id 
 WHERE f.user2_id=? AND f.status='active')
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
<title>DaakPion Messenger</title>
<link rel="stylesheet" href="../chatboard.css?v=<?php echo time()?>"/>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/7.0.0/css/all.min.css"/>
<style>

</style>
</head>
<body>
<div class="container">
  <!-- Sidebar -->
  <aside class="sidebar">
    <div class="logo"><img src="../Daak-pion.png" alt="Logo"/><h1>DaakPion</h1></div>
    <div class="searching">
      <input type="text" placeholder="Search for your friend" class="search-bar" id="friendSearch"/>
      <button class="Search-btn">Search</button>
    </div>
    <h2>Your Friends</h2>
    <div class="friend-list" id="friendList">
      <?php if(empty($friends)) : ?>
        <p class="muted">No friends yet.</p>
      <?php else: ?>
        <?php foreach($friends as $fr): ?>
        <div class="friend-card" data-id="<?php echo $fr['id']; ?>">
          <div class="friend-info">
            
          <div class="friend"> 
            <img src="<?php echo !empty($fr['dp']) ? "../".htmlspecialchars($fr['dp']) : "https://cdn-icons-png.flaticon.com/512/149/149071.png"; ?>" alt="<?php echo htmlspecialchars($fr['fname']." ".$fr['lname']); ?>"/> 
            <span><?php echo htmlspecialchars($fr['fname']." ".$fr['lname']); ?></span> 
            <span class="chat-btn" style="margin: left 10px; ;">
              <i class="fa-solid fa-message"></i>
            </span>
          </div>

          </div>
        </div>
        <?php endforeach; ?>
      <?php endif; ?>
    </div>
    <div class="profile-info">
      <img src="<?php echo htmlspecialchars($profilePic); ?>" alt="Profile" onclick="profileRedirect()"/>
      <div class="profile-text"><p class="profile-name"><?php echo htmlspecialchars($userName); ?></p></div>
      <form method="post" action="logout.php" style="display:inline;">
        <button class="logout-btn" type="submit" name="logout">Logout</button>
      </form>
    </div>
  </aside>

  <!-- Chat Area -->
  <main class="chat-area">
    <div class="chat-header">
      <img src="" alt="Friend" id="chatHeaderImg"/>
      <span id="chatHeaderName">Select a friend</span>
    </div>
    <div class="chat-box" id="chatBox">
      <p class="muted">No chat selected.</p>
    </div>
    <div class="chat-input">
      <input type="text" placeholder="Type your text..." id="chatInput"/>
      <button id="sendBtn">Send</button>
    </div>
  </main>
</div>

<script>
// --- Redirect to profile ---
function profileRedirect(){ window.location.href='user-profile.php'; }

// --- Load messages when clicking friend ---
const userId = <?php echo $user_id; ?>;
const friendCards = document.querySelectorAll('.friend-card');
const chatHeaderName = document.getElementById('chatHeaderName');
const chatHeaderImg  = document.getElementById('chatHeaderImg');
const chatBox = document.getElementById('chatBox');
let currentFriendId = null;

friendCards.forEach(card=>{
  card.addEventListener('click', ()=>{
    currentFriendId = card.dataset.id;
    chatHeaderName.innerText = card.querySelector('span').innerText;
    chatHeaderImg.src = card.querySelector('img').src;
    loadMessages(currentFriendId);
  });
});

function loadMessages(friendId){
  chatBox.innerHTML = '<p class="muted">Loading messages...</p>';
  fetch(`get_messages.php?friend_id=${friendId}`)
    .then(res=>res.json())
    .then(data=>{
      chatBox.innerHTML = '';
      if(data.length===0){
        chatBox.innerHTML = '<p class="muted">No messages yet.</p>';
      } else {
        data.forEach(msg=>{
          const div = document.createElement('div');
          div.className = msg.sender_id==userId ? 'message sent' : 'message received';
          div.innerHTML = msg.sender_id==userId ? `<p>${msg.message}</p>` : `<p>${msg.message}</p>`;
          chatBox.appendChild(div);
        });
        chatBox.scrollTop = chatBox.scrollHeight;
      }
    });
}

// --- Send message ---
const sendBtn = document.getElementById('sendBtn');
sendBtn.addEventListener('click', ()=>{
  const msg = document.getElementById('chatInput').value.trim();
  if(!msg || !currentFriendId) return;
  fetch('send_message.php',{
    method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:`receiver_id=${currentFriendId}&message=${encodeURIComponent(msg)}`
  }).then(res=>res.text()).then(res=>{
    document.getElementById('chatInput').value='';
    loadMessages(currentFriendId);
  });
});

// --- Optional: search filter ---
const searchInput = document.getElementById('friendSearch');
searchInput.addEventListener('keyup', ()=>{
  const filter = searchInput.value.toLowerCase();
  friendCards.forEach(card=>{
    const name = card.querySelector('span').innerText.toLowerCase();
    card.style.display = name.includes(filter) ? '' : 'none';
  });
});
</script>
</body>
</html>
