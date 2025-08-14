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
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>DaakPion Messenger</title>
  <link rel="stylesheet" href="../chatboard.css?v=<?php echo time()?>">
</head>
<body>
  <div class="container">
    <!-- Sidebar -->
    <aside class="sidebar">
      <div class="logo">
        <img src="../Daak-pion.png" alt="Logo"/>
        <h1>DaakPion</h1>
      </div>
      <div class="searching">
        <input type="text" placeholder="Search for your friend" class="search-bar"/>
        <button class="Search-btn">Search</button>
      </div>
      <h2>Your Friends</h2>
      <div class="friend-list">
        <div class="friend">
        <img src="f1.jpg" alt="Friend1"/>
        <span>Friend 1</span>
        </div>
        <div class="friend">
          <img src="f2.png" alt="Friend 2"/>
          <span>Friend 2</span>
        </div>
        <div class="friend">
          <img src="f3.png" alt="Friend 3"/>
          <span>Friend 3</span>
        </div>
        <div class="friend">
          <img src="f4.png" alt="Friend 4"/>
          <span>Friend 4</span>
        </div>
        <div class="friend">
          <img src="f5.png" alt="Friend 5"/>
          <span>Friend 5</span>
        </div>
        <div class="friend">
          <img src="f6.png" alt="Friend 6"/>
          <span>Friend 6</span>
        </div>
      </div>
      <div class="profile-info">
        <img src="../dp.png" alt="user" onclick="profileRedirect()">
        <div class="profile-text">
            <p class="profile-name"><?php echo htmlspecialchars($userName); ?></p>

        </div>
        <form method="post" action="logout.php" style="display:inline;">
          <button class="logout-btn" type="submit" name="logout">Logout</button>
        </form>
      </div>

    </aside>

    <!-- Chat Area -->
    <main class="chat-area">
      <div class="chat-header">
        <img src="f1.jpg" alt="Friend1"/>
        <span>Friend 1</span>
      </div>
      <div class="chat-box">
        <div class="message received">
          <img src="user.png" alt="User"/>
          <p>This is a message from friend.</p>
        </div>
        <div class="message sent">
          <p>This is your message reply.</p>
        </div>
        <div class="message received">
          <img src="user.png" alt="User"/>
          <p>Another message from friend.</p>
        </div>
        <div class="message sent">
          <p>This is your message reply.</p>
        </div>
      </div>
      <div class="chat-input">
        <input type="text" placeholder="Type your text and click send" />
        <button>Send</button>
      </div>
    </main>
  </div>

      <script>
        function profileRedirect() {
            window.location.href = 'user-profile.php';
        }
    </script>

</body>
</html>
