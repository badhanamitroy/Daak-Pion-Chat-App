<?php
require_once __DIR__ . "/bootstrap_security.php";

if (!isset($_SESSION['user_id'])) {
    header("Location: ../index.html");
    exit;
}

\Daakpion\Security\SessionManager::checkRestrictedAccess();

$user_id = (int)$_SESSION['user_id'];

// --- Fetch user info ---
$sql = "SELECT fname, lname, dp, coverpic FROM users WHERE id = ?";
$stmt = $conn->prepare($sql); 
$stmt->bind_param("i", $user_id);
$stmt->execute();
$user = $stmt->get_result()->fetch_assoc();
$stmt->close();

$userName   = trim(($user['fname'] ?? "User") . " " . ($user['lname'] ?? ""));
$profilePic = (!empty($user['dp']) && $user['dp'] !== 'ProfilePics/default.jpg') ? "../" . $user['dp'] : "../dp.png";
$coverPic   = !empty($user['coverpic']) ? "../" . $user['coverpic'] : "../Coverpics/default.jpg";

// --- Fetch Friends with Presence & Initial Unread Count ---
$friends = [];
$sql = "
(SELECT u.id, u.fname, u.lname, u.dp,
        (CASE WHEN u.status != 'Offline' 
                   AND u.last_activity_at IS NOT NULL 
                   AND TIMESTAMPDIFF(SECOND, u.last_activity_at, NOW()) <= 120 
              THEN 1 ELSE 0 END) AS is_online,
        (SELECT COUNT(*) FROM messages m WHERE m.receiver_id = ? AND m.sender_id = u.id AND m.is_read = 0 AND m.deleted_by_receiver = 0 AND m.is_deleted_all = 0) AS unread_count
 FROM friends f 
 JOIN users u ON u.id = f.user2_id 
 WHERE f.user1_id=? AND f.status='active')
UNION
(SELECT u.id, u.fname, u.lname, u.dp,
        (CASE WHEN u.status != 'Offline' 
                   AND u.last_activity_at IS NOT NULL 
                   AND TIMESTAMPDIFF(SECOND, u.last_activity_at, NOW()) <= 120 
              THEN 1 ELSE 0 END) AS is_online,
        (SELECT COUNT(*) FROM messages m WHERE m.receiver_id = ? AND m.sender_id = u.id AND m.is_read = 0 AND m.deleted_by_receiver = 0 AND m.is_deleted_all = 0) AS unread_count
 FROM friends f 
 JOIN users u ON u.id = f.user1_id 
 WHERE f.user2_id=? AND f.status='active')
LIMIT 100
";
$stmt = $conn->prepare($sql);
$stmt->bind_param("iiii", $user_id, $user_id, $user_id, $user_id);
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
<link rel="stylesheet" href="../chatboard.css?v=2.0"/>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" crossorigin="anonymous" referrerpolicy="no-referrer"/>
</head>
<body>

<div class="messenger-app">

  <!-- ══ SIDEBAR ══ -->
  <aside class="sidebar">

    <!-- Sidebar Header -->
    <div class="sidebar-header">
      <div class="sidebar-top">
        <a class="sidebar-brand" href="../index.html">
          <img src="../Dakpion-logo.png" alt="DaakPion Logo"/>
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
        <?php foreach($friends as $fr): 
          $uCount = (int)($fr['unread_count'] ?? 0);
        ?>
        <div class="friend-card" data-id="<?php echo (int)$fr['id']; ?>"
             data-name="<?php echo htmlspecialchars($fr['fname'].' '.$fr['lname']); ?>"
             data-img="<?php echo (!empty($fr['dp']) && $fr['dp'] !== 'ProfilePics/default.jpg') ? '../'.htmlspecialchars($fr['dp']) : '../dp.png'; ?>"
             data-online="<?php echo !empty($fr['is_online']) ? '1' : '0'; ?>">
          <div class="friend-avatar-wrap">
            <img src="<?php echo (!empty($fr['dp']) && $fr['dp'] !== 'ProfilePics/default.jpg') ? '../'.htmlspecialchars($fr['dp']) : '../dp.png'; ?>"
                 alt="<?php echo htmlspecialchars($fr['fname'].' '.$fr['lname']); ?>"/>
            <span class="online-dot" id="dot-<?php echo (int)$fr['id']; ?>" style="<?php echo !empty($fr['is_online']) ? '' : 'display:none;'; ?>"></span>
          </div>
          <div class="friend-text">
            <div class="friend-name"><?php echo htmlspecialchars($fr['fname'].' '.$fr['lname']); ?></div>
            <div class="friend-preview" id="preview-<?php echo (int)$fr['id']; ?>">Click to start chatting</div>
          </div>
          <span class="unread-badge" id="badge-<?php echo (int)$fr['id']; ?>" style="<?php echo $uCount > 0 ? '' : 'display:none;'; ?>">
            <?php echo $uCount; ?>
          </span>
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
  <main class="chat-area" style="position:relative;">

    <!-- Chat Header -->
    <div class="chat-header">
      <div class="chat-header-avatar">
        <img src="" alt="Friend" id="chatHeaderImg"/>
      </div>
      <div class="chat-header-info">
        <div id="chatHeaderName" class="chat-header-placeholder">Select a conversation</div>
        <div id="chatHeaderStatus" style="display:none;">Offline</div>
      </div>
      <div class="chat-header-actions" id="chatHeaderActions" style="display:none;">
        <div class="chat-search-bar" id="chatSearchBar" style="display:none;">
          <input type="text" id="msgSearchInput" placeholder="Search in chat..." autocomplete="off"/>
          <span class="search-match-count" id="searchMatchCount">0/0</span>
          <button type="button" class="search-nav-btn" id="searchPrevBtn" title="Previous match"><i class="fa-solid fa-chevron-up"></i></button>
          <button type="button" class="search-nav-btn" id="searchNextBtn" title="Next match"><i class="fa-solid fa-chevron-down"></i></button>
          <button type="button" class="search-nav-btn" id="searchCloseBtn" title="Close search"><i class="fa-solid fa-xmark"></i></button>
        </div>
        <button class="icon-btn" id="searchToggleBtn" title="Search messages in chat">
          <i class="fa-solid fa-magnifying-glass"></i>
        </button>
      </div>
    </div>

    <!-- Messages Container -->
    <div class="chat-box" id="chatBox">
      <div class="chat-empty" id="chatEmptyState">
        <i class="fa-solid fa-comments"></i>
        <h3>Your Messages</h3>
        <p>Select a conversation from the left<br>to start chatting.</p>
      </div>
    </div>

    <!-- Floating "New Messages" Pill -->
    <button class="new-messages-pill" id="newMessagesPill" style="display:none;">
      <i class="fa-solid fa-arrow-down"></i> New messages
    </button>

    <!-- Typing Indicator Bar -->
    <div class="typing-indicator-bar" id="typingIndicatorBar" style="display:none;">
      <div class="typing-dots"><span></span><span></span><span></span></div>
      <span id="typingText" class="typing-text">Amit is typing...</span>
    </div>

    <!-- Reply Preview Bar -->
    <div class="reply-preview-bar" id="replyPreviewBar" style="display:none;">
      <div class="reply-preview-content">
        <i class="fa-solid fa-reply"></i>
        <div class="reply-preview-text">
          <span class="reply-author" id="replyAuthor">Replying to Amit</span>
          <span class="reply-snippet" id="replySnippet">Original message snippet</span>
        </div>
      </div>
      <button type="button" class="reply-cancel-btn" id="replyCancelBtn" title="Cancel reply">
        <i class="fa-solid fa-xmark"></i>
      </button>
    </div>

    <!-- Input Bar -->
    <div class="chat-input-bar">
      <!-- Emoji Picker -->
      <div class="emoji-picker-container" id="emojiPickerContainer">
        <button type="button" class="input-icon-btn emoji-picker-trigger" id="emojiTrigger" aria-label="Open emoji picker" title="Emoji" aria-expanded="false" aria-controls="emojiPicker">
          <i class="fa-solid fa-face-smile"></i>
        </button>
        <div class="emoji-picker-popover" id="emojiPicker" role="dialog" aria-label="Emoji library" aria-hidden="true">
          <div class="emoji-picker-header">
            <span class="emoji-picker-title">Emojis</span>
            <span class="emoji-preview-name" id="emojiPreviewName">Pick an emoji</span>
          </div>
          <div class="emoji-picker-grid" id="emojiPickerGrid" role="grid" aria-label="Emoji library">
            <!-- Dynamically populated from whitelisted emojiLibrary -->
          </div>
        </div>
      </div>
      <div class="chat-input-wrap">
        <textarea id="chatInput" placeholder="Aa" rows="1" maxlength="2000" autocomplete="off" disabled></textarea>
      </div>

      <!-- Attachment Popover Menu -->
      <div class="attach-menu-container" id="attachMenuContainer">
        <button type="button" class="input-icon-btn" id="attachBtn" title="Attach photo, video, document, or audio" aria-expanded="false" disabled>
          <i class="fa-solid fa-paperclip"></i>
        </button>
        <div class="attach-menu-popover" id="attachMenu" role="menu">
          <button type="button" class="attach-menu-item attach-item-photo" id="attachPhotoBtn">
            <i class="fa-solid fa-image"></i> Photos &amp; Images
          </button>
          <button type="button" class="attach-menu-item attach-item-video" id="attachVideoBtn">
            <i class="fa-solid fa-video"></i> Video
          </button>
          <button type="button" class="attach-menu-item attach-item-doc" id="attachDocBtn">
            <i class="fa-solid fa-file-arrow-up"></i> Document / File
          </button>
          <button type="button" class="attach-menu-item attach-item-voice" id="attachVoiceBtn">
            <i class="fa-solid fa-microphone"></i> Voice Note
          </button>
        </div>
      </div>

      <!-- Hidden file inputs -->
      <input type="file" id="imageFileInput" accept="image/jpeg,image/png,image/webp,image/gif" style="display:none;" />
      <input type="file" id="videoFileInput" accept="video/mp4,video/webm,video/quicktime" style="display:none;" />
      <input type="file" id="docFileInput" accept=".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.zip" style="display:none;" />

      <!-- Voice Record Bar inside chat-input-bar -->
      <div class="voice-record-bar" id="voiceRecordBar">
        <div class="voice-record-status">
          <span class="voice-record-dot"></span>
          <span class="voice-record-timer" id="voiceRecordTimer">00:00</span>
          <span style="font-size:0.8rem; color:var(--text-muted); margin-left:6px;">Recording voice note...</span>
        </div>
        <div class="voice-record-actions">
          <button type="button" class="voice-btn-cancel" id="voiceCancelBtn" title="Cancel recording">
            <i class="fa-solid fa-trash-can"></i>
          </button>
          <button type="button" class="voice-btn-stop" id="voiceStopBtn" title="Stop &amp; preview">
            <i class="fa-solid fa-stop"></i>
          </button>
        </div>
      </div>

      <button class="send-btn" id="sendBtn" title="Send" disabled>
        <i class="fa-solid fa-paper-plane"></i>
      </button>
    </div>

  </main>
</div>

<!-- Pre-Send Media Preview Modal -->
<div class="media-modal-backdrop" id="mediaPreviewModal" role="dialog" aria-modal="true" aria-hidden="true">
  <div class="media-modal-box">
    <div class="media-modal-header">
      <span class="media-modal-title" id="mediaModalTitle">Send Media</span>
      <button type="button" class="media-modal-close-btn" id="mediaModalCloseBtn" title="Close">
        <i class="fa-solid fa-xmark"></i>
      </button>
    </div>
    <div class="media-modal-body">
      <div class="media-preview-container" id="mediaPreviewContainer"></div>
      <input type="text" class="media-caption-input" id="mediaCaptionInput" placeholder="Add a caption... (optional)" maxlength="1000" autocomplete="off" />
      <div class="upload-progress-wrap" id="uploadProgressWrap">
        <div class="upload-progress-bar">
          <div class="upload-progress-fill" id="uploadProgressFill"></div>
        </div>
        <div class="upload-progress-status">
          <span id="uploadProgressText">Uploading...</span>
          <span id="uploadProgressPercent">0%</span>
        </div>
      </div>
    </div>
    <div class="media-modal-footer">
      <button type="button" class="media-btn-cancel" id="mediaModalCancelBtn">Cancel</button>
      <button type="button" class="media-btn-send" id="mediaModalSendBtn">
        <i class="fa-solid fa-paper-plane"></i> Send
      </button>
    </div>
  </div>
</div>

<!-- Fullscreen Lightbox Media Viewer -->
<div class="lightbox-modal" id="lightboxModal" role="dialog" aria-modal="true" aria-hidden="true">
  <div class="lightbox-header">
    <span class="lightbox-title" id="lightboxTitle">Media</span>
    <div class="lightbox-actions">
      <a href="#" class="lightbox-btn" id="lightboxDownloadBtn" download title="Download">
        <i class="fa-solid fa-download"></i>
      </a>
      <button type="button" class="lightbox-btn" id="lightboxCloseBtn" title="Close (Esc)">
        <i class="fa-solid fa-xmark"></i>
      </button>
    </div>
  </div>
  <div class="lightbox-body" id="lightboxBody"></div>
</div>

<script>
// --- Redirect to profile ---
function profileRedirect(){ window.location.href='user-profile.php'; }

// --- DOM references ---
const userId            = <?php echo (int)$user_id; ?>;
const csrfToken         = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
const friendCards       = document.querySelectorAll('.friend-card');
const chatHeaderName    = document.getElementById('chatHeaderName');
const chatHeaderImg     = document.getElementById('chatHeaderImg');
const chatHeaderStatus  = document.getElementById('chatHeaderStatus');
const chatHeaderActions = document.getElementById('chatHeaderActions');
const chatBox           = document.getElementById('chatBox');
const chatInput         = document.getElementById('chatInput');
const sendBtn           = document.getElementById('sendBtn');
const searchInput       = document.getElementById('friendSearch');
const newMessagesPill   = document.getElementById('newMessagesPill');
const typingIndicatorBar= document.getElementById('typingIndicatorBar');
const typingText        = document.getElementById('typingText');
const replyPreviewBar   = document.getElementById('replyPreviewBar');
const replyAuthorEl     = document.getElementById('replyAuthor');
const replySnippetEl    = document.getElementById('replySnippet');
const replyCancelBtn    = document.getElementById('replyCancelBtn');
const searchToggleBtn   = document.getElementById('searchToggleBtn');
const chatSearchBar     = document.getElementById('chatSearchBar');
const msgSearchInput    = document.getElementById('msgSearchInput');
const searchMatchCount  = document.getElementById('searchMatchCount');
const searchPrevBtn     = document.getElementById('searchPrevBtn');
const searchNextBtn     = document.getElementById('searchNextBtn');
const searchCloseBtn    = document.getElementById('searchCloseBtn');

// --- Phase 2: Media & Attachment DOM references ---
const attachBtn           = document.getElementById('attachBtn');
const attachMenu          = document.getElementById('attachMenu');
const attachPhotoBtn      = document.getElementById('attachPhotoBtn');
const attachVideoBtn      = document.getElementById('attachVideoBtn');
const attachDocBtn        = document.getElementById('attachDocBtn');
const attachVoiceBtn      = document.getElementById('attachVoiceBtn');
const imageFileInput      = document.getElementById('imageFileInput');
const videoFileInput      = document.getElementById('videoFileInput');
const docFileInput        = document.getElementById('docFileInput');
const voiceRecordBar      = document.getElementById('voiceRecordBar');
const voiceRecordTimer    = document.getElementById('voiceRecordTimer');
const voiceCancelBtn      = document.getElementById('voiceCancelBtn');
const voiceStopBtn        = document.getElementById('voiceStopBtn');
const mediaPreviewModal   = document.getElementById('mediaPreviewModal');
const mediaModalTitle     = document.getElementById('mediaModalTitle');
const mediaPreviewContainer = document.getElementById('mediaPreviewContainer');
const mediaCaptionInput   = document.getElementById('mediaCaptionInput');
const uploadProgressWrap  = document.getElementById('uploadProgressWrap');
const uploadProgressFill  = document.getElementById('uploadProgressFill');
const uploadProgressText  = document.getElementById('uploadProgressText');
const uploadProgressPercent = document.getElementById('uploadProgressPercent');
const mediaModalCancelBtn = document.getElementById('mediaModalCancelBtn');
const mediaModalSendBtn   = document.getElementById('mediaModalSendBtn');
const mediaModalCloseBtn  = document.getElementById('mediaModalCloseBtn');
const lightboxModal       = document.getElementById('lightboxModal');
const lightboxTitle       = document.getElementById('lightboxTitle');
const lightboxDownloadBtn = document.getElementById('lightboxDownloadBtn');
const lightboxCloseBtn    = document.getElementById('lightboxCloseBtn');
const lightboxBody        = document.getElementById('lightboxBody');

let currentMediaFile      = null;
let currentMediaType      = null; // 'image' | 'video' | 'doc' | 'audio'
let mediaRecorderInstance = null;
let audioRecordingChunks  = [];
let voiceTimerInterval    = null;
let voiceDurationSeconds  = 0;

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

let currentFriendId     = null;
let currentFriendName   = '';
let lastMessageId       = 0;
let oldestMessageId     = 0;
let pollTimer           = null;
let isLoadingOlder      = false;
let reachedEndOfHistory = false;
let activeReplyTarget   = null; // { id, author, snippet }
let lastRenderedDateStr = '';
let searchMatches       = [];
let currentSearchIndex  = -1;
let isTypingActive      = false;
let typingDebounceTimer = null;
let typingStopTimer     = null;

// Track pending/in-flight messages for instant UI and safe retry
const pendingMessagesMap = new Map(); // client_message_id => { element, msgObj }

// --- Whitelisted Font Awesome Emoji Library ---
const emojiLibrary = {
  smile:    { icon: 'fa-face-smile',            name: 'Smiley',   shortcode: ':smile:' },
  angry:    { icon: 'fa-face-angry',            name: 'Angry',    shortcode: ':angry:' },
  sad:      { icon: 'fa-face-frown',            name: 'Sad',      shortcode: ':sad:' },
  shock:    { icon: 'fa-face-flushed',          name: 'Shock',    shortcode: ':shock:' },
  laugh:    { icon: 'fa-face-grin-squint',      name: 'Laugh',    shortcode: ':laugh:' },
  love:     { icon: 'fa-face-grin-hearts',      name: 'Love',     shortcode: ':love:' },
  kiss:     { icon: 'fa-face-kiss-wink-heart',  name: 'Kiss',     shortcode: ':kiss:' },
  cry:      { icon: 'fa-face-sad-cry',          name: 'Cry',      shortcode: ':cry:' },
  surprise: { icon: 'fa-face-surprise',         name: 'Surprise', shortcode: ':surprise:' }
};

// Safe formatting: generates DOM fragments with text nodes & whitelisted FA icons
function formatMessageContent(rawText) {
  const fragment = document.createDocumentFragment();
  if (typeof rawText !== 'string' || !rawText) return fragment;

  const regex = /:(smile|angry|sad|shock|laugh|love|kiss|cry|surprise):/g;
  let lastIdx = 0;
  let match;

  while ((match = regex.exec(rawText)) !== null) {
    if (match.index > lastIdx) {
      fragment.appendChild(document.createTextNode(rawText.substring(lastIdx, match.index)));
    }
    const key = match[1];
    const emoji = emojiLibrary[key];
    if (emoji) {
      const icon = document.createElement('i');
      icon.className = `fa-solid ${emoji.icon} chat-emoji`;
      icon.setAttribute('aria-label', emoji.name);
      icon.setAttribute('title', emoji.name);
      icon.setAttribute('role', 'img');
      fragment.appendChild(icon);
    } else {
      fragment.appendChild(document.createTextNode(match[0]));
    }
    lastIdx = regex.lastIndex;
  }

  if (lastIdx < rawText.length) {
    fragment.appendChild(document.createTextNode(rawText.substring(lastIdx)));
  }

  return fragment;
}

// Format readable timestamps: Today "10:42 PM", Yesterday "Yesterday, 10:42 PM", Older "Oct 4, 10:42 PM"
function formatTimestamp(dateStr) {
  if (!dateStr) return { short: '', full: '', dayKey: '' };
  const d = new Date(dateStr.replace(' ', 'T'));
  if (isNaN(d.getTime())) return { short: dateStr, full: dateStr, dayKey: dateStr };

  const now = new Date();
  const isToday = d.toDateString() === now.toDateString();
  
  const yesterday = new Date();
  yesterday.setDate(now.getDate() - 1);
  const isYesterday = d.toDateString() === yesterday.toDateString();

  const timeOptions = { hour: 'numeric', minute: '2-digit', hour12: true };
  const timeFormatted = d.toLocaleTimeString([], timeOptions);
  const fullFormatted = d.toLocaleString([], { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit', hour12: true });

  let shortFormatted = timeFormatted;
  let dayKey = d.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });

  if (isToday) {
    dayKey = 'Today';
  } else if (isYesterday) {
    shortFormatted = `Yesterday, ${timeFormatted}`;
    dayKey = 'Yesterday';
  } else if (d.getFullYear() === now.getFullYear()) {
    shortFormatted = `${d.toLocaleDateString([], { month: 'short', day: 'numeric' })}, ${timeFormatted}`;
  } else {
    shortFormatted = fullFormatted;
  }

  return { short: shortFormatted, full: fullFormatted, dayKey };
}

// Toast notification helper
function showToast(text) {
  const existing = document.querySelector('.chat-toast');
  if (existing) existing.remove();
  const toast = document.createElement('div');
  toast.className = 'chat-toast';
  toast.textContent = text;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 2500);
}

// --- Render Status Icons ---
function getStatusIconHtml(state) {
  if (state === 'sending') {
    return `<i class="fa-solid fa-spinner fa-spin msg-status msg-sending" title="Sending..."></i>`;
  } else if (state === 'read') {
    return `<i class="fa-solid fa-check-double msg-status msg-read" title="Read"></i>`;
  } else if (state === 'delivered') {
    return `<i class="fa-solid fa-check-double msg-status msg-delivered" title="Delivered"></i>`;
  } else if (state === 'sent') {
    return `<i class="fa-solid fa-check msg-status msg-sent" title="Sent"></i>`;
  } else if (state === 'failed') {
    return `<span class="msg-failed-wrap"><i class="fa-solid fa-circle-exclamation"></i> <button type="button" class="btn-retry">Retry</button></span>`;
  }
  return '';
}

// --- Create a Message DOM Node ---
function buildMessageNode(msg) {
  const isSent = msg.sender_id == userId;
  const isDeleted = !!msg.is_deleted;
  const row = document.createElement('div');
  row.className = `message-row ${isSent ? 'sent' : 'received'}`;
  row.dataset.msgId = msg.id || 'temp';
  if (msg.client_message_id) row.dataset.clientMsgId = msg.client_message_id;

  const bubbleWrap = document.createElement('div');
  bubbleWrap.className = 'message-bubble-wrap';

  // Reply preview quote box inside message bubble
  if (msg.reply_to && !isDeleted) {
    const replyQuote = document.createElement('div');
    replyQuote.className = 'message-reply-quote';
    replyQuote.title = 'Click to jump to quoted message';
    replyQuote.innerHTML = `
      <div class="reply-quote-author"><i class="fa-solid fa-reply"></i> ${escapeHtml(msg.reply_to.author)}</div>
      <div class="reply-quote-text">${escapeHtml(msg.reply_to.snippet)}</div>
    `;
    replyQuote.addEventListener('click', () => {
      const targetRow = chatBox.querySelector(`.message-row[data-msg-id="${msg.reply_to.id}"]`);
      if (targetRow) {
        targetRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
        targetRow.style.transition = 'background 0.3s';
        targetRow.style.backgroundColor = 'rgba(24,119,242,0.2)';
        setTimeout(() => { targetRow.style.backgroundColor = ''; }, 1200);
      } else {
        showToast('Quoted message is older in conversation history.');
      }
    });
    bubbleWrap.appendChild(replyQuote);
  }

  // Attachment Rendering (Phase 2)
  if (msg.attachment && !isDeleted) {
    const mediaWrap = document.createElement('div');
    mediaWrap.className = 'msg-media-wrap';
    const attach = msg.attachment;
    const mediaType = attach.media_type;

    if (mediaType === 'image') {
      const imgCard = document.createElement('div');
      imgCard.className = 'msg-image-card';
      const imgUrl = `download_attachment.php?id=${attach.id}`;
      imgCard.innerHTML = `
        <img src="${escapeHtml(imgUrl)}" alt="${escapeHtml(attach.original_name)}" loading="lazy" />
        <span class="msg-image-overlay" title="View full image"><i class="fa-solid fa-expand"></i></span>
      `;
      imgCard.addEventListener('click', () => {
        openLightbox(imgUrl, 'image', attach.original_name, `download_attachment.php?id=${attach.id}&download=1`);
      });
      mediaWrap.appendChild(imgCard);
    } else if (mediaType === 'video') {
      const vidCard = document.createElement('div');
      vidCard.className = 'msg-video-card';
      const vidUrl = `download_attachment.php?id=${attach.id}`;
      vidCard.innerHTML = `
        <video controls playsinline preload="metadata">
          <source src="${escapeHtml(vidUrl)}" type="${escapeHtml(attach.mime_type)}">
          Your browser does not support HTML5 video.
        </video>
      `;
      mediaWrap.appendChild(vidCard);
    } else if (mediaType === 'audio') {
      const audioCard = document.createElement('div');
      audioCard.className = 'msg-audio-card';
      const audUrl = `download_attachment.php?id=${attach.id}`;
      audioCard.innerHTML = `
        <i class="fa-solid fa-microphone" style="color:var(--blue); font-size:16px;"></i>
        <audio controls preload="metadata" style="flex:1;">
          <source src="${escapeHtml(audUrl)}" type="${escapeHtml(attach.mime_type)}">
          Your browser does not support audio playback.
        </audio>
      `;
      mediaWrap.appendChild(audioCard);
    } else {
      // Document or generic file
      const docCard = document.createElement('div');
      docCard.className = 'msg-doc-card';
      const downUrl = `download_attachment.php?id=${attach.id}&download=1`;
      const ext = (attach.original_name || '').split('.').pop().toLowerCase();
      let iconClass = 'fa-solid fa-file';
      if (ext === 'pdf') iconClass = 'fa-solid fa-file-pdf';
      else if (['doc', 'docx'].includes(ext)) iconClass = 'fa-solid fa-file-word';
      else if (['xls', 'xlsx'].includes(ext)) iconClass = 'fa-solid fa-file-excel';
      else if (['ppt', 'pptx'].includes(ext)) iconClass = 'fa-solid fa-file-powerpoint';
      else if (['zip', 'rar'].includes(ext)) iconClass = 'fa-solid fa-file-zipper';
      else if (ext === 'txt') iconClass = 'fa-solid fa-file-lines';

      docCard.innerHTML = `
        <div class="doc-icon-wrap"><i class="${iconClass}"></i></div>
        <div class="doc-info">
          <span class="doc-name" title="${escapeHtml(attach.original_name)}">${escapeHtml(attach.original_name)}</span>
          <span class="doc-meta">${formatBytes(attach.size_bytes)}</span>
        </div>
        <a href="${escapeHtml(downUrl)}" class="doc-download-btn" title="Download ${escapeHtml(attach.original_name)}" download>
          <i class="fa-solid fa-download"></i>
        </a>
      `;
      mediaWrap.appendChild(docCard);
    }

    bubbleWrap.appendChild(mediaWrap);
  }

  // Message paragraph / caption
  const raw = msg.message || '';
  if (isDeleted) {
    const p = document.createElement('p');
    p.classList.add('message-tombstone');
    const tombIcon = document.createElement('i');
    tombIcon.className = 'fa-solid fa-ban';
    tombIcon.style.marginRight = '6px';
    p.appendChild(tombIcon);
    p.appendChild(document.createTextNode('This message was deleted'));
    bubbleWrap.appendChild(p);
  } else if (raw.trim().length > 0 && (!msg.attachment || raw.trim() !== '')) {
    const p = document.createElement('p');
    if (msg.attachment) {
      p.className = 'msg-caption-text';
    } else {
      // Emoji-only check
      const remaining = raw.replace(/:(smile|angry|sad|shock|laugh|love|kiss|cry|surprise):/g, '').trim();
      if (remaining === '' && raw.trim().length > 0) {
        p.classList.add('emoji-only');
      }
    }
    p.appendChild(formatMessageContent(raw));
    bubbleWrap.appendChild(p);
  }

  // Metadata: Timestamp & Status
  const meta = document.createElement('div');
  meta.className = 'msg-meta';
  const tsInfo = formatTimestamp(msg.sent_at);
  meta.innerHTML = `<span class="msg-time" title="${escapeHtml(tsInfo.full)}">${escapeHtml(tsInfo.short)}</span>`;

  if (isSent && !isDeleted) {
    let state = 'sent';
    if (msg.status === 'sending' || msg.status === 'failed') {
      state = msg.status;
    } else if (msg.is_read == 1) {
      state = 'read';
    } else if (msg.is_delivered == 1) {
      state = 'delivered';
    }
    meta.innerHTML += ` <span class="msg-status-holder">${getStatusIconHtml(state)}</span>`;
  }
  bubbleWrap.appendChild(meta);

  // Hover Action Trigger & Menu (Only if not deleted)
  if (!isDeleted) {
    const actionTrigger = document.createElement('button');
    actionTrigger.type = 'button';
    actionTrigger.className = 'msg-action-trigger';
    actionTrigger.title = 'Message actions';
    actionTrigger.innerHTML = '<i class="fa-solid fa-ellipsis-vertical"></i>';

    const menu = document.createElement('div');
    menu.className = 'msg-actions-menu';

    // Copy action
    const copyBtn = document.createElement('button');
    copyBtn.type = 'button';
    copyBtn.className = 'msg-action-item';
    copyBtn.innerHTML = '<i class="fa-regular fa-copy"></i> Copy';
    copyBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      menu.classList.remove('active');
      navigator.clipboard.writeText(raw).then(() => showToast('Copied to clipboard!'));
    });
    menu.appendChild(copyBtn);

    // Reply action
    const replyBtn = document.createElement('button');
    replyBtn.type = 'button';
    replyBtn.className = 'msg-action-item';
    replyBtn.innerHTML = '<i class="fa-solid fa-reply"></i> Reply';
    replyBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      menu.classList.remove('active');
      initiateReply(msg.id, isSent ? 'You' : currentFriendName, raw);
    });
    menu.appendChild(replyBtn);

    // Delete for me action
    const delMeBtn = document.createElement('button');
    delMeBtn.type = 'button';
    delMeBtn.className = 'msg-action-item delete-item';
    delMeBtn.innerHTML = '<i class="fa-regular fa-trash-can"></i> Delete for me';
    delMeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      menu.classList.remove('active');
      executeDeleteMessage(msg.id, 'for_me', row);
    });
    menu.appendChild(delMeBtn);

    // Delete for everyone action (only if sent by current user)
    if (isSent && msg.id) {
      const delAllBtn = document.createElement('button');
      delAllBtn.type = 'button';
      delAllBtn.className = 'msg-action-item delete-item';
      delAllBtn.innerHTML = '<i class="fa-solid fa-trash-arrow-up"></i> Delete for everyone';
      delAllBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        menu.classList.remove('active');
        if (confirm('Delete this message for everyone in the chat?')) {
          executeDeleteMessage(msg.id, 'for_everyone', row);
        }
      });
      menu.appendChild(delAllBtn);
    }

    actionTrigger.addEventListener('click', (e) => {
      e.stopPropagation();
      // Close other open menus
      document.querySelectorAll('.msg-actions-menu.active').forEach(m => {
        if (m !== menu) m.classList.remove('active');
      });
      menu.classList.toggle('active');
    });

    if (isSent) {
      row.appendChild(actionTrigger);
      row.appendChild(menu);
      row.appendChild(bubbleWrap);
    } else {
      row.appendChild(bubbleWrap);
      row.appendChild(actionTrigger);
      row.appendChild(menu);
    }
  } else {
    row.appendChild(bubbleWrap);
  }

  // Handle retry click if message failed
  const retryBtn = meta.querySelector('.btn-retry');
  if (retryBtn) {
    retryBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      retrySendingMessage(msg.client_message_id);
    });
  }

  return row;
}

function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}

// --- Render Date Separator ---
function maybeInsertDateSeparator(dateStr, container, isPrepend = false, beforeNode = null) {
  const tsInfo = formatTimestamp(dateStr);
  if (!tsInfo.dayKey) return;

  if (isPrepend) {
    // If prepending older messages, caller manages date boundaries
    return;
  }

  if (tsInfo.dayKey !== lastRenderedDateStr) {
    lastRenderedDateStr = tsInfo.dayKey;
    const sep = document.createElement('div');
    sep.className = 'date-separator';
    sep.innerHTML = `<span>${escapeHtml(tsInfo.dayKey)}</span>`;
    container.appendChild(sep);
  }
}

// --- Render Message (Append or Prepend) ---
function renderMessage(msg, isPrepend = false, beforeNode = null) {
  const node = buildMessageNode(msg);

  if (isPrepend && beforeNode) {
    chatBox.insertBefore(node, beforeNode);
  } else {
    maybeInsertDateSeparator(msg.sent_at, chatBox);
    chatBox.appendChild(node);
  }

  const numericId = parseInt(msg.id, 10);
  if (!isNaN(numericId) && numericId > 0) {
    if (numericId > lastMessageId) lastMessageId = numericId;
    if (oldestMessageId === 0 || numericId < oldestMessageId) oldestMessageId = numericId;
  }
}

// --- Load Messages from Server ---
function loadMessages(friendId, isInitialLoad = false) {
  if (!friendId) return;

  const since = isInitialLoad ? 0 : lastMessageId;
  fetch(`get_messages.php?friend_id=${friendId}&since_id=${since}`)
    .then(res => res.json())
    .then(data => {
      if (friendId !== currentFriendId) return; // Discard if user switched chat

      if (isInitialLoad) {
        chatBox.innerHTML = '';
        lastRenderedDateStr = '';
        oldestMessageId = 0;
        lastMessageId = 0;
        reachedEndOfHistory = false;

        // Add top loaders
        const histDiv = document.createElement('div');
        histDiv.id = 'historyStart';
        histDiv.className = 'history-start';
        histDiv.style.display = 'none';
        histDiv.innerHTML = '<i class="fa-solid fa-circle-check"></i> Beginning of conversation';
        chatBox.appendChild(histDiv);

        const loadDiv = document.createElement('div');
        loadDiv.id = 'olderLoader';
        loadDiv.className = 'older-loader';
        loadDiv.style.display = 'none';
        loadDiv.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Loading older messages...';
        chatBox.appendChild(loadDiv);

        if (!data || data.length === 0) {
          chatBox.innerHTML += '<p class="muted">No messages yet. Say hello! 👋</p>';
          return;
        }
      }

      if (data && data.length > 0) {
        const placeholder = chatBox.querySelector('.muted');
        if (placeholder) placeholder.remove();

        const wasNearBottom = isNearBottom();
        let hasIncomingUnread = false;

        data.forEach(msg => {
          // Check if message is already rendered (e.g. from optimistic send matching id or client_message_id)
          let existingNode = null;
          if (msg.client_message_id) {
            existingNode = chatBox.querySelector(`.message-row[data-client-msg-id="${msg.client_message_id}"]`);
          }
          if (!existingNode && msg.id) {
            existingNode = chatBox.querySelector(`.message-row[data-msg-id="${msg.id}"]`);
          }

          if (existingNode) {
            // Update status or replace tombstone
            updateExistingMessageNode(existingNode, msg);
          } else {
            renderMessage(msg, false);
            if (msg.sender_id != userId && msg.is_read == 0) {
              hasIncomingUnread = true;
            }
          }
        });

        // Mark incoming messages read if conversation is open
        if (hasIncomingUnread) {
          markConversationRead(friendId, lastMessageId);
        }

        // Auto-scroll or show floating indicator
        if (isInitialLoad || wasNearBottom) {
          scrollToBottom(isInitialLoad ? 'auto' : 'smooth');
          newMessagesPill.style.display = 'none';
        } else {
          newMessagesPill.style.display = 'flex';
        }
      }
    })
    .catch(err => console.error('loadMessages error:', err));
}

// Update existing optimistic or tombstone message node
function updateExistingMessageNode(node, msg) {
  if (msg.id) node.dataset.msgId = msg.id;
  const isSent = msg.sender_id == userId;
  const isDeleted = !!msg.is_deleted;

  if (isDeleted && !node.querySelector('.message-tombstone')) {
    const p = node.querySelector('p');
    if (p) {
      p.className = 'message-tombstone';
      p.innerHTML = '<i class="fa-solid fa-ban" style="margin-right:6px;"></i>This message was deleted';
    }
    const trig = node.querySelector('.msg-action-trigger');
    if (trig) trig.remove();
    const menu = node.querySelector('.msg-actions-menu');
    if (menu) menu.remove();
  }

  // Update status icon for sent message
  if (isSent && !isDeleted) {
    const statusHolder = node.querySelector('.msg-status-holder');
    if (statusHolder) {
      let state = 'sent';
      if (msg.is_read == 1) state = 'read';
      else if (msg.is_delivered == 1) state = 'delivered';
      statusHolder.innerHTML = getStatusIconHtml(state);
    }
  }
}

// --- Load Older Messages (Historical Pagination) ---
function loadOlderMessages() {
  if (isLoadingOlder || reachedEndOfHistory || oldestMessageId <= 1 || !currentFriendId) return;
  isLoadingOlder = true;

  const olderLoader = document.getElementById('olderLoader');
  if (olderLoader) olderLoader.style.display = 'flex';

  const oldScrollHeight = chatBox.scrollHeight;
  const oldScrollTop = chatBox.scrollTop;

  fetch(`get_messages.php?friend_id=${currentFriendId}&before_id=${oldestMessageId}&limit=30`)
    .then(res => res.json())
    .then(data => {
      if (olderLoader) olderLoader.style.display = 'none';
      isLoadingOlder = false;

      if (!data || data.length === 0) {
        reachedEndOfHistory = true;
        const histStart = document.getElementById('historyStart');
        if (histStart) histStart.style.display = 'flex';
        return;
      }

      // Prepend older messages before the first rendered message-row
      const firstRow = chatBox.querySelector('.message-row');
      data.forEach(msg => {
        renderMessage(msg, true, firstRow);
      });

      // Maintain scroll position cleanly
      const newScrollHeight = chatBox.scrollHeight;
      chatBox.scrollTop = newScrollHeight - oldScrollHeight + oldScrollTop;

      if (data.length < 30) {
        reachedEndOfHistory = true;
        const histStart = document.getElementById('historyStart');
        if (histStart) histStart.style.display = 'flex';
      }
    })
    .catch(err => {
      console.error('loadOlderMessages error:', err);
      if (olderLoader) olderLoader.style.display = 'none';
      isLoadingOlder = false;
    });
}

// Detect scroll position for pagination and new message pill
function isNearBottom() {
  const threshold = 120;
  return (chatBox.scrollHeight - chatBox.scrollTop - chatBox.clientHeight) <= threshold;
}

function scrollToBottom(behavior = 'smooth') {
  chatBox.scrollTo({ top: chatBox.scrollHeight, behavior });
}

chatBox.addEventListener('scroll', () => {
  if (chatBox.scrollTop < 60 && !isLoadingOlder && !reachedEndOfHistory) {
    loadOlderMessages();
  }
  if (isNearBottom()) {
    newMessagesPill.style.display = 'none';
  }
});

newMessagesPill.addEventListener('click', () => {
  scrollToBottom('smooth');
  newMessagesPill.style.display = 'none';
});

// --- Mark Conversation Read ---
function markConversationRead(friendId, maxId = 0) {
  if (!friendId || !csrfToken) return;

  const formData = new FormData();
  formData.append('friend_id', friendId);
  formData.append('csrf_token', csrfToken);
  if (maxId > 0) formData.append('max_id', maxId);

  fetch('mark_messages_read.php', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    body: formData
  }).then(res => res.json()).then(data => {
    if (data && data.success) {
      const badge = document.getElementById(`badge-${friendId}`);
      if (badge) {
        badge.style.display = 'none';
        badge.textContent = '0';
      }
    }
  }).catch(() => {});
}

// --- Message Sending with Idempotency & Optimistic UI ---
function doSend() {
  const text = chatInput.value.trim();
  if (!text || !currentFriendId) return;

  closeEmojiPicker();

  const clientMsgId = 'client_' + Date.now() + '_' + Math.random().toString(36).substring(2, 10);
  const nowIso = new Date().toISOString().replace('T', ' ').substring(0, 19);

  // Optimistic message object
  const optimisticMsg = {
    id: null,
    client_message_id: clientMsgId,
    sender_id: userId,
    receiver_id: currentFriendId,
    message: text,
    sent_at: nowIso,
    status: 'sending',
    is_read: 0,
    is_delivered: 0,
    is_deleted: false,
    reply_to: activeReplyTarget ? {
      id: activeReplyTarget.id,
      author: activeReplyTarget.author,
      snippet: activeReplyTarget.snippet
    } : null
  };

  // Render immediately in chat
  const placeholder = chatBox.querySelector('.muted');
  if (placeholder) placeholder.remove();
  renderMessage(optimisticMsg, false);
  scrollToBottom('smooth');

  const renderedNode = chatBox.querySelector(`.message-row[data-client-msg-id="${clientMsgId}"]`);
  pendingMessagesMap.set(clientMsgId, {
    text: text,
    reply_to_id: activeReplyTarget ? activeReplyTarget.id : null,
    node: renderedNode
  });

  // Clear input and reply preview
  chatInput.value = '';
  adjustTextareaHeight();
  updateSendBtnState();
  cancelReply();

  // Send request
  sendToServer(clientMsgId, text, optimisticMsg.reply_to ? optimisticMsg.reply_to.id : null);
}

function sendToServer(clientMsgId, text, replyToId) {
  const params = new URLSearchParams();
  params.append('receiver_id', currentFriendId);
  params.append('message', text);
  params.append('client_message_id', clientMsgId);
  params.append('csrf_token', csrfToken);
  if (replyToId) params.append('reply_to_id', replyToId);

  fetch('send_message.php', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-CSRF-Token': csrfToken
    },
    body: params.toString()
  })
  .then(async res => {
    const data = await res.json();
    const entry = pendingMessagesMap.get(clientMsgId);
    if (!res.ok || !data.success) {
      throw new Error(data.error || 'Failed to send message.');
    }

    if (entry && entry.node) {
      entry.node.dataset.msgId = data.id;
      const statusHolder = entry.node.querySelector('.msg-status-holder');
      if (statusHolder) {
        const state = data.is_read ? 'read' : (data.is_delivered ? 'delivered' : 'sent');
        statusHolder.innerHTML = getStatusIconHtml(state);
      }
    }
    pendingMessagesMap.delete(clientMsgId);
    stopTyping();
  })
  .catch(err => {
    console.error('Send failed:', err);
    const entry = pendingMessagesMap.get(clientMsgId);
    if (entry && entry.node) {
      const statusHolder = entry.node.querySelector('.msg-status-holder');
      if (statusHolder) {
        statusHolder.innerHTML = getStatusIconHtml('failed');
        const retryBtn = statusHolder.querySelector('.btn-retry');
        if (retryBtn) {
          retryBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            retrySendingMessage(clientMsgId);
          });
        }
      }
    }
  });
}

function retrySendingMessage(clientMsgId) {
  const entry = pendingMessagesMap.get(clientMsgId);
  if (!entry) return;

  if (entry.node) {
    const statusHolder = entry.node.querySelector('.msg-status-holder');
    if (statusHolder) {
      statusHolder.innerHTML = getStatusIconHtml('sending');
    }
  }
  sendToServer(clientMsgId, entry.text, entry.reply_to_id);
}

// --- Reply Logic ---
function initiateReply(msgId, author, text) {
  activeReplyTarget = {
    id: msgId,
    author: author,
    snippet: text.length > 55 ? text.substring(0, 52) + '...' : text
  };
  replyAuthorEl.textContent = `Replying to ${author}`;
  replySnippetEl.textContent = activeReplyTarget.snippet;
  replyPreviewBar.style.display = 'flex';
  chatInput.focus();
}

function cancelReply() {
  activeReplyTarget = null;
  replyPreviewBar.style.display = 'none';
}
replyCancelBtn.addEventListener('click', cancelReply);

// --- Delete Message ---
function executeDeleteMessage(msgId, deleteType, node) {
  if (!msgId || !csrfToken) return;

  const formData = new FormData();
  formData.append('message_id', msgId);
  formData.append('delete_type', deleteType);
  formData.append('csrf_token', csrfToken);

  fetch('delete_message.php', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    body: formData
  })
  .then(res => res.json())
  .then(data => {
    if (data.success) {
      if (deleteType === 'for_me') {
        node.style.transition = 'opacity 0.2s, transform 0.2s';
        node.style.opacity = '0';
        node.style.transform = 'scale(0.9)';
        setTimeout(() => node.remove(), 200);
      } else {
        // Tombstone for everyone
        const p = node.querySelector('p');
        if (p) {
          p.className = 'message-tombstone';
          p.innerHTML = '<i class="fa-solid fa-ban" style="margin-right:6px;"></i>This message was deleted';
        }
        const trig = node.querySelector('.msg-action-trigger');
        if (trig) trig.remove();
        const menu = node.querySelector('.msg-actions-menu');
        if (menu) menu.remove();
      }
      showToast('Message deleted.');
    } else {
      alert(data.error || 'Failed to delete message.');
    }
  })
  .catch(err => console.error('Delete error:', err));
}

// --- Typing Indicator Integration ---
function notifyTyping(isTyping) {
  if (!currentFriendId || !csrfToken) return;

  const formData = new FormData();
  formData.append('friend_id', currentFriendId);
  formData.append('is_typing', isTyping ? '1' : '0');
  formData.append('csrf_token', csrfToken);

  fetch('update_typing.php', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    body: formData
  }).catch(() => {});
}

function handleTypingEvent() {
  if (!isTypingActive) {
    isTypingActive = true;
    notifyTyping(true);
  }

  if (typingStopTimer) clearTimeout(typingStopTimer);
  typingStopTimer = setTimeout(() => {
    stopTyping();
  }, 3000);
}

function stopTyping() {
  if (isTypingActive) {
    isTypingActive = false;
    notifyTyping(false);
  }
  if (typingStopTimer) clearTimeout(typingStopTimer);
}

// --- Textarea Input UX (Auto-growing & Enter to send) ---
function adjustTextareaHeight() {
  chatInput.style.height = 'auto';
  const newHeight = Math.min(chatInput.scrollHeight, 120);
  chatInput.style.height = newHeight + 'px';
}

function updateSendBtnState() {
  const hasText = chatInput.value.trim().length > 0;
  sendBtn.disabled = !hasText || !currentFriendId;
}

chatInput.addEventListener('input', () => {
  adjustTextareaHeight();
  updateSendBtnState();
  if (chatInput.value.trim().length > 0) {
    handleTypingEvent();
  } else {
    stopTyping();
  }
});

chatInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    if (!sendBtn.disabled) {
      doSend();
    }
  }
});

sendBtn.addEventListener('click', doSend);

// --- Friend Selection / Open Conversation ---
friendCards.forEach(card => {
  card.addEventListener('click', () => {
    friendCards.forEach(c => c.classList.remove('active'));
    card.classList.add('active');

    // Stop typing for previous friend
    stopTyping();
    cancelReply();
    closeChatSearch();

    currentFriendId   = card.dataset.id;
    currentFriendName = card.dataset.name || 'Friend';
    lastMessageId     = 0;
    oldestMessageId   = 0;

    const friendImg  = card.dataset.img || '';
    const isOnline   = card.dataset.online === '1';

    chatHeaderName.textContent = currentFriendName;
    chatHeaderName.classList.remove('chat-header-placeholder');
    chatHeaderImg.src  = friendImg;
    chatHeaderImg.style.display = 'block';

    chatHeaderStatus.textContent = isOnline ? 'Active now' : 'Offline';
    chatHeaderStatus.style.color = isOnline ? '#31a24c' : 'var(--text-muted, #888)';
    chatHeaderStatus.style.display = 'block';
    chatHeaderActions.style.display = 'flex';

    chatInput.disabled = false;
    chatInput.placeholder = `Message ${currentFriendName}...`;
    updateSendBtnState();
    if (attachBtn) {
      attachBtn.disabled = false;
      attachBtn.style.opacity = '1';
      attachBtn.style.cursor = 'pointer';
    }

    chatBox.innerHTML = '<p class="muted">Loading messages...</p>';
    loadMessages(currentFriendId, true);
    startPolling();
    chatInput.focus();
  });
});

// --- Polling for Messages, Presence, Typing, Unread Counts ---
function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(pollCycle, 3000);
}

function pollCycle() {
  if (currentFriendId) {
    loadMessages(currentFriendId, false);
  }
  updateMetadata();
}

function updateMetadata() {
  fetch('get_presence.php')
    .then(res => res.json())
    .then(data => {
      if (!data) return;

      // 1. Update presence on cards
      if (data.presence) {
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

      // 2. Update unread badges
      if (data.unread_counts) {
        friendCards.forEach(card => {
          const fid = card.dataset.id;
          const badge = document.getElementById(`badge-${fid}`);
          const count = data.unread_counts[fid] || 0;
          if (badge) {
            if (count > 0 && currentFriendId != fid) {
              badge.textContent = count;
              badge.style.display = 'flex';
            } else if (currentFriendId == fid) {
              badge.style.display = 'none';
            } else {
              badge.style.display = 'none';
            }
          }
        });
      }

      // 3. Update typing indicator in active chat
      if (currentFriendId && data.typing) {
        const isFriendTyping = !!data.typing[currentFriendId];
        if (isFriendTyping) {
          typingText.textContent = `${currentFriendName} is typing...`;
          typingIndicatorBar.style.display = 'flex';
        } else {
          typingIndicatorBar.style.display = 'none';
        }
      } else {
        typingIndicatorBar.style.display = 'none';
      }
    })
    .catch(() => {});
}

// Heartbeat
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
updateMetadata();
setInterval(updateMetadata, 10000);

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') {
    sendHeartbeat();
    updateMetadata();
    if (currentFriendId) loadMessages(currentFriendId, false);
  } else {
    stopTyping();
  }
});

// --- In-Conversation Client Search ---
searchToggleBtn.addEventListener('click', () => {
  if (chatSearchBar.style.display === 'none') {
    chatSearchBar.style.display = 'flex';
    msgSearchInput.focus();
  } else {
    closeChatSearch();
  }
});

searchCloseBtn.addEventListener('click', closeChatSearch);

function closeChatSearch() {
  chatSearchBar.style.display = 'none';
  msgSearchInput.value = '';
  clearSearchHighlights();
  searchMatches = [];
  currentSearchIndex = -1;
  searchMatchCount.textContent = '0/0';
}

function clearSearchHighlights() {
  chatBox.querySelectorAll('mark.search-highlight').forEach(mark => {
    const parent = mark.parentNode;
    parent.replaceChild(document.createTextNode(mark.textContent), mark);
    parent.normalize();
  });
}

msgSearchInput.addEventListener('input', () => {
  const query = msgSearchInput.value.trim().toLowerCase();
  clearSearchHighlights();
  searchMatches = [];
  currentSearchIndex = -1;

  if (!query) {
    searchMatchCount.textContent = '0/0';
    return;
  }

  const rows = chatBox.querySelectorAll('.message-row:not(.message-tombstone)');
  rows.forEach(row => {
    const p = row.querySelector('p');
    if (!p) return;
    const text = p.textContent.toLowerCase();
    if (text.includes(query)) {
      // Highlight occurrences inside paragraph
      highlightTextInElement(p, query);
    }
  });

  searchMatches = Array.from(chatBox.querySelectorAll('mark.search-highlight'));
  if (searchMatches.length > 0) {
    currentSearchIndex = 0;
    updateSearchMatchDisplay();
  } else {
    searchMatchCount.textContent = '0/0';
  }
});

function highlightTextInElement(element, query) {
  const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT, null, false);
  const textNodes = [];
  let node;
  while (node = walker.nextNode()) textNodes.push(node);

  textNodes.forEach(tNode => {
    const val = tNode.nodeValue;
    const lower = val.toLowerCase();
    const idx = lower.indexOf(query);
    if (idx !== -1) {
      const matchText = val.substring(idx, idx + query.length);
      const mark = document.createElement('mark');
      mark.className = 'search-highlight';
      mark.textContent = matchText;

      const after = document.createTextNode(val.substring(idx + query.length));
      tNode.nodeValue = val.substring(0, idx);

      tNode.parentNode.insertBefore(after, tNode.nextSibling);
      tNode.parentNode.insertBefore(mark, after);
    }
  });
}

function updateSearchMatchDisplay() {
  if (searchMatches.length === 0) {
    searchMatchCount.textContent = '0/0';
    return;
  }
  searchMatches.forEach((m, i) => {
    m.classList.toggle('current', i === currentSearchIndex);
  });
  searchMatchCount.textContent = `${currentSearchIndex + 1}/${searchMatches.length}`;
  const cur = searchMatches[currentSearchIndex];
  if (cur) cur.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

searchPrevBtn.addEventListener('click', () => {
  if (searchMatches.length === 0) return;
  currentSearchIndex = (currentSearchIndex - 1 + searchMatches.length) % searchMatches.length;
  updateSearchMatchDisplay();
});

searchNextBtn.addEventListener('click', () => {
  if (searchMatches.length === 0) return;
  currentSearchIndex = (currentSearchIndex + 1) % searchMatches.length;
  updateSearchMatchDisplay();
});

// --- Search Filter on Friend List ---
searchInput.addEventListener('keyup', () => {
  const filter = searchInput.value.toLowerCase();
  friendCards.forEach(card => {
    const name = (card.dataset.name || '').toLowerCase();
    card.style.display = name.includes(filter) ? '' : 'none';
  });
});

// --- Emoji Picker Logic ---
const emojiTrigger       = document.getElementById('emojiTrigger');
const emojiPicker        = document.getElementById('emojiPicker');
const emojiPickerGrid    = document.getElementById('emojiPickerGrid');
const emojiPreviewName   = document.getElementById('emojiPreviewName');
const emojiContainer     = document.getElementById('emojiPickerContainer');

function initEmojiPicker() {
  if (!emojiPickerGrid) return;
  emojiPickerGrid.innerHTML = '';

  Object.entries(emojiLibrary).forEach(([key, item]) => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'emoji-btn';
    btn.dataset.key = key;
    btn.dataset.code = item.shortcode;
    btn.dataset.name = item.name;
    btn.setAttribute('title', item.name);
    btn.setAttribute('aria-label', item.name);
    btn.setAttribute('role', 'gridcell');
    btn.tabIndex = 0;

    const icon = document.createElement('i');
    icon.className = `fa-solid ${item.icon}`;
    btn.appendChild(icon);

    btn.addEventListener('mouseenter', () => {
      if (emojiPreviewName) emojiPreviewName.textContent = item.name;
    });
    btn.addEventListener('mouseleave', () => {
      if (emojiPreviewName) emojiPreviewName.textContent = 'Pick an emoji';
    });

    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      insertEmojiAtCursor(item.shortcode);
    });

    emojiPickerGrid.appendChild(btn);
  });
}

function insertEmojiAtCursor(code) {
  chatInput.focus();
  const val = chatInput.value;
  const start = chatInput.selectionStart !== null ? chatInput.selectionStart : val.length;
  const end = chatInput.selectionEnd !== null ? chatInput.selectionEnd : val.length;

  let insertion = code;
  if (start > 0 && val[start - 1] !== ' ') insertion = ' ' + insertion;
  if (end === val.length || val[end] !== ' ') insertion = insertion + ' ';

  chatInput.value = val.substring(0, start) + insertion + val.substring(end);
  const newPos = start + insertion.length;
  chatInput.setSelectionRange(newPos, newPos);
  adjustTextareaHeight();
  updateSendBtnState();
}

function toggleEmojiPicker(e) {
  if (e) e.stopPropagation();
  const isOpen = emojiPicker && emojiPicker.classList.contains('active');
  if (isOpen) closeEmojiPicker();
  else openEmojiPicker();
}

function openEmojiPicker() {
  if (!emojiPicker) return;
  emojiPicker.classList.add('active');
  emojiPicker.setAttribute('aria-hidden', 'false');
  if (emojiTrigger) emojiTrigger.setAttribute('aria-expanded', 'true');
}

function closeEmojiPicker() {
  if (!emojiPicker) return;
  emojiPicker.classList.remove('active');
  emojiPicker.setAttribute('aria-hidden', 'true');
  if (emojiTrigger) emojiTrigger.setAttribute('aria-expanded', 'false');
  if (emojiPreviewName) emojiPreviewName.textContent = 'Pick an emoji';
}

if (emojiTrigger) emojiTrigger.addEventListener('click', toggleEmojiPicker);

// ══════════════════════════════════════════════════════
// PHASE 2 — MEDIA MESSAGING FRONTEND IMPLEMENTATION
// ══════════════════════════════════════════════════════

function initAttachmentFeatures() {
  if (!attachBtn) return;

  // Toggle attachment menu
  attachBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    if (attachBtn.disabled) return;
    closeEmojiPicker();
    const isActive = attachMenu.classList.toggle('active');
    attachBtn.setAttribute('aria-expanded', isActive ? 'true' : 'false');
  });

  // Photo / Image trigger
  if (attachPhotoBtn) {
    attachPhotoBtn.addEventListener('click', () => {
      closeAttachMenu();
      imageFileInput.click();
    });
  }

  // Video trigger
  if (attachVideoBtn) {
    attachVideoBtn.addEventListener('click', () => {
      closeAttachMenu();
      videoFileInput.click();
    });
  }

  // Document trigger
  if (attachDocBtn) {
    attachDocBtn.addEventListener('click', () => {
      closeAttachMenu();
      docFileInput.click();
    });
  }

  // Voice Note trigger
  if (attachVoiceBtn) {
    attachVoiceBtn.addEventListener('click', () => {
      closeAttachMenu();
      startVoiceRecording();
    });
  }

  // File input change listeners
  if (imageFileInput) {
    imageFileInput.addEventListener('change', (e) => {
      handleFileSelected(e.target.files[0], 'image', 10 * 1024 * 1024);
      imageFileInput.value = '';
    });
  }
  if (videoFileInput) {
    videoFileInput.addEventListener('change', (e) => {
      handleFileSelected(e.target.files[0], 'video', 25 * 1024 * 1024);
      videoFileInput.value = '';
    });
  }
  if (docFileInput) {
    docFileInput.addEventListener('change', (e) => {
      handleFileSelected(e.target.files[0], 'doc', 15 * 1024 * 1024);
      docFileInput.value = '';
    });
  }

  // Modal Cancel / Close buttons
  if (mediaModalCancelBtn) mediaModalCancelBtn.addEventListener('click', closeMediaPreviewModal);
  if (mediaModalCloseBtn) mediaModalCloseBtn.addEventListener('click', closeMediaPreviewModal);

  // Modal Send button
  if (mediaModalSendBtn) mediaModalSendBtn.addEventListener('click', sendMediaAttachment);

  // Voice record controls
  if (voiceCancelBtn) voiceCancelBtn.addEventListener('click', () => stopVoiceRecording(false));
  if (voiceStopBtn) voiceStopBtn.addEventListener('click', () => stopVoiceRecording(true));

  // Lightbox close
  if (lightboxCloseBtn) lightboxCloseBtn.addEventListener('click', closeLightbox);
  if (lightboxModal) {
    lightboxModal.addEventListener('click', (e) => {
      if (e.target === lightboxModal || e.target === lightboxBody) {
        closeLightbox();
      }
    });
  }
}

function closeAttachMenu() {
  if (attachMenu) {
    attachMenu.classList.remove('active');
    if (attachBtn) attachBtn.setAttribute('aria-expanded', 'false');
  }
}

function handleFileSelected(file, type, maxBytes) {
  if (!file) return;
  if (!currentFriendId) {
    showToast('Please select a conversation first.');
    return;
  }

  if (file.size > maxBytes) {
    showToast(`File is too large (${formatBytes(file.size)}). Max allowed is ${formatBytes(maxBytes)}.`);
    return;
  }

  currentMediaFile = file;
  currentMediaType = type;

  // Open Preview Modal
  mediaPreviewContainer.innerHTML = '';
  mediaCaptionInput.value = '';
  uploadProgressWrap.style.display = 'none';
  uploadProgressFill.style.width = '0%';
  uploadProgressPercent.textContent = '0%';
  mediaModalSendBtn.disabled = false;
  mediaModalCancelBtn.disabled = false;
  mediaModalCloseBtn.disabled = false;

  const objectUrl = URL.createObjectURL(file);

  if (type === 'image') {
    mediaModalTitle.textContent = 'Send Photo';
    const img = document.createElement('img');
    img.src = objectUrl;
    img.alt = file.name;
    mediaPreviewContainer.appendChild(img);
  } else if (type === 'video') {
    mediaModalTitle.textContent = 'Send Video';
    const vid = document.createElement('video');
    vid.src = objectUrl;
    vid.controls = true;
    mediaPreviewContainer.appendChild(vid);
  } else if (type === 'audio') {
    mediaModalTitle.textContent = 'Send Voice Note';
    const aud = document.createElement('audio');
    aud.src = objectUrl;
    aud.controls = true;
    aud.style.width = '90%';
    aud.style.margin = '20px auto';
    mediaPreviewContainer.appendChild(aud);
  } else {
    mediaModalTitle.textContent = 'Send Document';
    const docCard = document.createElement('div');
    docCard.className = 'msg-doc-card';
    docCard.style.margin = '20px auto';
    docCard.innerHTML = `
      <div class="doc-icon-wrap"><i class="fa-solid fa-file"></i></div>
      <div class="doc-info">
        <span class="doc-name">${escapeHtml(file.name)}</span>
        <span class="doc-meta">${formatBytes(file.size)}</span>
      </div>
    `;
    mediaPreviewContainer.appendChild(docCard);
  }

  mediaPreviewModal.classList.add('active');
  mediaPreviewModal.setAttribute('aria-hidden', 'false');
  mediaCaptionInput.focus();
}

function closeMediaPreviewModal() {
  mediaPreviewModal.classList.remove('active');
  mediaPreviewModal.setAttribute('aria-hidden', 'true');
  currentMediaFile = null;
  currentMediaType = null;
  mediaPreviewContainer.innerHTML = '';
}

function sendMediaAttachment() {
  if (!currentMediaFile || !currentFriendId) return;

  mediaModalSendBtn.disabled = true;
  mediaModalCancelBtn.disabled = true;
  mediaModalCloseBtn.disabled = true;

  uploadProgressWrap.style.display = 'flex';
  uploadProgressFill.style.width = '0%';
  uploadProgressText.textContent = 'Uploading...';
  uploadProgressPercent.textContent = '0%';

  const formData = new FormData();
  formData.append('receiver_id', currentFriendId);
  formData.append('file', currentMediaFile);
  formData.append('caption', mediaCaptionInput.value.trim());
  formData.append('csrf_token', csrfToken);
  if (activeReplyTarget) {
    formData.append('reply_to_id', activeReplyTarget.id);
  }

  const xhr = new XMLHttpRequest();

  xhr.upload.onprogress = (e) => {
    if (e.lengthComputable) {
      const percent = Math.min(100, Math.round((e.loaded / e.total) * 100));
      uploadProgressFill.style.width = percent + '%';
      uploadProgressPercent.textContent = percent + '%';
      uploadProgressText.textContent = percent === 100 ? 'Processing...' : `Uploading ${percent}%...`;
    }
  };

  xhr.onload = () => {
    let resp = null;
    try {
      resp = JSON.parse(xhr.responseText);
    } catch (err) {}

    if (xhr.status === 200 && resp && resp.success) {
      closeMediaPreviewModal();
      cancelReply();
      loadMessages(currentFriendId, false);
      scrollToBottom('smooth');
      showToast('Media sent successfully!');
    } else {
      const errMsg = (resp && resp.error) ? resp.error : 'Failed to upload media.';
      showToast(errMsg);
      uploadProgressWrap.style.display = 'none';
      mediaModalSendBtn.disabled = false;
      mediaModalCancelBtn.disabled = false;
      mediaModalCloseBtn.disabled = false;
    }
  };

  xhr.onerror = () => {
    showToast('Network error during upload.');
    uploadProgressWrap.style.display = 'none';
    mediaModalSendBtn.disabled = false;
    mediaModalCancelBtn.disabled = false;
    mediaModalCloseBtn.disabled = false;
  };

  xhr.open('POST', 'upload_media.php', true);
  xhr.setRequestHeader('X-CSRF-Token', csrfToken);
  xhr.send(formData);
}

// --- Voice Recording Flow ---
function startVoiceRecording() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    showToast('Microphone recording is not supported in this browser.');
    return;
  }
  if (!currentFriendId) {
    showToast('Please select a conversation first.');
    return;
  }

  navigator.mediaDevices.getUserMedia({ audio: true })
    .then(stream => {
      audioRecordingChunks = [];
      voiceDurationSeconds = 0;
      voiceRecordTimer.textContent = '00:00';
      voiceRecordBar.classList.add('active');

      voiceTimerInterval = setInterval(() => {
        voiceDurationSeconds++;
        const mins = String(Math.floor(voiceDurationSeconds / 60)).padStart(2, '0');
        const secs = String(voiceDurationSeconds % 60).padStart(2, '0');
        voiceRecordTimer.textContent = `${mins}:${secs}`;
      }, 1000);

      const mimeType = (typeof MediaRecorder.isTypeSupported === 'function' && MediaRecorder.isTypeSupported('audio/webm;codecs=opus'))
        ? 'audio/webm;codecs=opus'
        : ((typeof MediaRecorder.isTypeSupported === 'function' && MediaRecorder.isTypeSupported('audio/ogg;codecs=opus')) ? 'audio/ogg;codecs=opus' : '');

      mediaRecorderInstance = mimeType ? new MediaRecorder(stream, { mimeType }) : new MediaRecorder(stream);

      mediaRecorderInstance.ondataavailable = (e) => {
        if (e.data && e.data.size > 0) {
          audioRecordingChunks.push(e.data);
        }
      };

      mediaRecorderInstance.onstop = () => {
        stream.getTracks().forEach(track => track.stop());
      };

      mediaRecorderInstance.start(250);
    })
    .catch(err => {
      console.warn('Microphone error:', err);
      showToast('Unable to access microphone. Please check permissions.');
    });
}

function stopVoiceRecording(save) {
  if (voiceTimerInterval) {
    clearInterval(voiceTimerInterval);
    voiceTimerInterval = null;
  }
  voiceRecordBar.classList.remove('active');

  if (!mediaRecorderInstance) return;

  if (save && voiceDurationSeconds >= 1) {
    mediaRecorderInstance.onstop = () => {
      const mime = mediaRecorderInstance.mimeType || 'audio/webm';
      const ext = mime.includes('ogg') ? 'ogg' : 'webm';
      const blob = new Blob(audioRecordingChunks, { type: mime });
      const voiceFile = new File([blob], `voice_note_${Date.now()}.${ext}`, { type: mime });
      handleFileSelected(voiceFile, 'audio', 10 * 1024 * 1024);
    };
  }

  if (mediaRecorderInstance.state !== 'inactive') {
    mediaRecorderInstance.stop();
  }
}

// --- Lightbox Modal ---
function openLightbox(src, type, title, downloadUrl) {
  lightboxTitle.textContent = title || 'Media';
  lightboxDownloadBtn.href = downloadUrl || src;
  lightboxDownloadBtn.setAttribute('download', title || 'media');
  lightboxBody.innerHTML = '';

  if (type === 'video') {
    const vid = document.createElement('video');
    vid.src = src;
    vid.controls = true;
    vid.autoplay = true;
    vid.playsinline = true;
    lightboxBody.appendChild(vid);
  } else {
    const img = document.createElement('img');
    img.src = src;
    img.alt = title || 'Image';
    lightboxBody.appendChild(img);
  }

  lightboxModal.classList.add('active');
  lightboxModal.setAttribute('aria-hidden', 'false');
}

function closeLightbox() {
  lightboxModal.classList.remove('active');
  lightboxModal.setAttribute('aria-hidden', 'true');
  lightboxBody.innerHTML = '';
}

document.addEventListener('click', (e) => {
  if (emojiPicker && emojiPicker.classList.contains('active')) {
    if (emojiContainer && !emojiContainer.contains(e.target)) closeEmojiPicker();
  }
  if (attachMenu && attachMenu.classList.contains('active')) {
    if (!attachMenu.contains(e.target) && !e.target.closest('#attachBtn')) {
      closeAttachMenu();
    }
  }
  // Close open message action menus
  document.querySelectorAll('.msg-actions-menu.active').forEach(m => {
    if (!m.contains(e.target) && !e.target.closest('.msg-action-trigger')) {
      m.classList.remove('active');
    }
  });
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    if (lightboxModal && lightboxModal.classList.contains('active')) {
      closeLightbox();
    }
    if (mediaPreviewModal && mediaPreviewModal.classList.contains('active')) {
      closeMediaPreviewModal();
    }
    if (attachMenu && attachMenu.classList.contains('active')) {
      closeAttachMenu();
    }
    if (emojiPicker && emojiPicker.classList.contains('active')) {
      closeEmojiPicker();
      chatInput.focus();
    }
    if (chatSearchBar.style.display !== 'none') {
      closeChatSearch();
    }
  }
});

// Auto-open from URL ?friend_id=X
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

initEmojiPicker();
initAttachmentFeatures();
</script>
</body>
</html>
