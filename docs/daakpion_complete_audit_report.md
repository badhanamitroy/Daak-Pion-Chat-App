# DaakPion - Complete Forensic Project Audit Report
Date: 2026-10-03 | Build: Post-Phase-4 Security Remediation

## 1. Project Overview

DaakPion is a Facebook-inspired real-time private chat application (PHP/MySQL). Features: Registration with 2FA, real-time encrypted messaging (AES-256-GCM), friend system, user profiles, edit profile with photo upload, password management. It has undergone 4 documented phases of security remediation. 32+ user profile photos and 28 cover photos exist confirming real user activity.

## 2. Technology Stack

| Layer | Technology |
|-------|-----------|
| Server | Apache (XAMPP) |
| Backend | PHP 8+ strict_types, OOP + procedural |
| Database | MySQL via XAMPP, OOP mysqli, database 'daakpion' |
| Frontend | HTML5, Vanilla CSS, Vanilla JavaScript (Fetch API) |
| Typography | Inter (Google Fonts) |
| Icons | Font Awesome 6.5.0 (cdnjs CDN) |
| Encryption | AES-256-GCM (messages), Argon2id+HMAC-SHA256 pepper (passwords) |
| Session | PHP native sessions hardened via SessionManager |
| Security Namespace | Daakpion\Security\* - 9 OOP classes |
| CSRF | Per-session token, constant-time hash_equals validation |
| Rate Limiting | MySQL-backed atomic sliding-window rate limiter |
| Audit Logging | Dual write: DB table + flat log file |

## 3. Complete File/Folder Structure

Daakpion/ (web root)
  index.html                     - Login/Landing page
  Register.html                  - Registration page
  seepassword.js                 - Password show/hide toggle
  homepage.css                   - Styles for index.html
  Register.css                   - Styles for Register.html + auth sub-pages
  chatboard.css                  - Messenger UI layout
  user-profile.css               - Profile page styles
  edit-user-profile.css          - Edit profile page styles
  frontpage.css                  - DEAD CODE (not referenced by any page)
  friendlist.css                 - Root-level copy (superseded by css/ version)
  shared-header.css              - Root-level copy (superseded by css/ version)
  Styles.css                     - DEAD CODE (unused legacy stylesheet)
  css/
    shared-header.css            - CANONICAL version used by PHP pages
    friendlist.css               - Used by friendlist.php inline + link
    (+ redundant copies of all other CSS files)
  js/
    register.js                  - DEAD CODE: old XHR-based registration, never loaded
  php/
    bootstrap_security.php       - Entry point required by ALL PHP pages
    app_config.php               - Application constants
    security_secrets.php         - Server secrets (web-blocked by .htaccess)
    security_secrets.example.php - Template for secrets file
    config.php                   - DEPRECATED: returns HTTP 403
    db_connect.php               - Active DB connection
    userlogin.php                - Authentication endpoint
    registration.php             - Registration endpoint
    logout.php                   - Logout handler (POST only, CSRF protected)
    verify_2fa.php               - 2FA OTP verification page
    forgot_password.php          - Password reset request page
    reset_password.php           - Password reset completion page
    force_change_password.php    - Mandatory password change for temp credentials
    chatboard.php                - Main messenger page
    friendlist.php               - Friends, requests, and discover-people page
    user-profile.php             - User profile view page
    edit-profile.php             - Profile editing + account security page
    get_messages.php             - API: fetch messages (JSON, paginated)
    send_message.php             - API: send encrypted message
    get_presence.php             - API: friend online/offline status
    heartbeat.php                - API: update user's last_activity_at
    send_request.php             - API: send friend request
    respond_request.php          - API: accept/decline friend request
    migrate_security.php         - CLI-only DB migration script
    Security/
      AuditLogger.php            - Security event logging (DB + flat file)
      CryptoService.php          - Password hashing + AES-256-GCM encryption
      CsrfProtection.php         - CSRF token generation and validation
      Environment.php            - Environment detection (dev/test/production)
      PasswordPolicy.php         - Password strength enforcement
      PasswordResetService.php   - Full password reset flow
      RateLimiter.php            - Atomic MySQL sliding-window rate limiter
      SessionManager.php         - Hardened session lifecycle management
      TwoFactorService.php       - OTP generation, storage, and verification
  ProfilePics/                   - User uploaded profile photos (32 files, real users)
    .htaccess                    - Execution protection for uploads
  Coverpics/                     - User uploaded cover photos (28 files)
    .htaccess                    - Execution protection
  logs/
    security_audit.log           - 176 lines of audit events
  tests/                         - PHP test suite
    .htaccess                    - Deny all web access
    Phase1RemediationTest.php
    Phase2RemediationTest.php
    Phase4RemediationTest.php
    SecurityTestSuite.php
    IntegrationFlowTest.php
  docs/                          - 7 documentation files
    daakpion_analysis_and_plan.md
    SECURITY_AUDIT_AND_REMEDIATION.md      (58KB)
    PHASE2_SECURITY_REMEDIATION_REPORT.md
    PHASE3_ATTACK_MATRIX.md
    PHASE3_DEEP_SECURITY_AUDIT.md          (42KB)
    COMPLETE_SECURITY_WORKFLOW_AND_REMEDIATION_GUIDE.md (37KB)
    daakpion_facebook_redesign_plan.md     (forward-looking plan)
  .htaccess                      - Security headers, deny sensitive files, CSP
  README.md                      - Project README (Badhan Roy Amit)

## 4. Database Architecture

Database: daakpion | Engine: InnoDB | Charset: utf8mb4

TABLE: users (primary user store)
  id INT PK AUTO_INCREMENT
  fname VARCHAR
  lname VARCHAR
  email VARCHAR (unique, used for login)
  password VARCHAR (Argon2id hash with pepper, migrated from bcrypt)
  status VARCHAR ('Active now' / 'Offline')
  dp VARCHAR (path to profile picture: ProfilePics/...)
  coverpic VARCHAR (path to cover photo: Coverpics/...)
  password_version INT DEFAULT 1 (cross-device session invalidation)
  is_temporary_password TINYINT(1) DEFAULT 0
  temp_password_expires_at DATETIME NULL
  two_factor_enabled TINYINT(1) DEFAULT 0
  last_activity_at DATETIME NULL (presence/heartbeat)

TABLE: friends (active bidirectional friendships)
  id INT PK
  user1_id INT FK->users
  user2_id INT FK->users
  friends_since DATETIME
  status ENUM('active', 'blocked')

TABLE: friendrequests (pending/responded requests)
  id INT PK
  sender_id INT FK->users
  receiver_id INT FK->users
  status ENUM('pending', 'accepted', 'rejected')
  sent_at DATETIME
  responded_at DATETIME NULL

TABLE: messages (AES-256-GCM encrypted chat messages)
  id INT PK
  sender_id INT FK->users
  receiver_id INT FK->users
  message TEXT (ciphertext: v2:gcm:iv:tag:ct)
  sent_at DATETIME
  is_read TINYINT(1) (exists but never updated - no read-receipt feature)

TABLE: security_rate_limits (brute force protection)
  rate_key VARCHAR(191) PK (namespaced: rl:action:sha256_id)
  attempts INT
  first_attempt_at INT (Unix timestamp)
  last_attempt_at INT
  blocked_until INT

TABLE: security_audit_logs (security event database records)
  id INT PK
  event_type VARCHAR(64)
  user_id INT NULL
  identifier VARCHAR(191)
  ip_address VARCHAR(45)
  user_agent VARCHAR(255)
  status VARCHAR(20)
  details TEXT (sanitized JSON, secrets redacted)
  created_at DATETIME

TABLE: password_resets (reset token store)
  id INT PK
  user_id INT FK->users
  token_hash VARCHAR(64) (SHA-256 of raw token - never plaintext)
  expires_at DATETIME (15-minute expiry)
  created_at DATETIME
  used_at DATETIME NULL (single-use enforcement)

TABLE: two_factor_otps (OTP store)
  id INT PK
  user_id INT FK->users
  otp_hash VARCHAR(64) (HMAC-SHA256 - never plaintext)
  expires_at DATETIME (5-minute expiry)
  attempts INT DEFAULT 0 (max 5)
  created_at DATETIME
  used_at DATETIME NULL (single-use)

## 5. Complete Feature List (18 Features)

FEATURE 1: User Registration
  Status: FULLY WORKING
  Flow: Register.html -> AJAX Fetch POST -> registration.php
  Security: Rate limit (5/IP/hour), PasswordPolicy (12+ chars), anti-enumeration timing
  DB: users INSERT, security_rate_limits, security_audit_logs

FEATURE 2: User Login
  Status: FULLY WORKING
  Flow: index.html -> AJAX Fetch -> userlogin.php -> Argon2id+pepper verify -> session
  Security: IP+email rate limiting, constant-time enumeration prevention, legacy bcrypt auto-migration
  DB: users SELECT+UPDATE, security_rate_limits, security_audit_logs

FEATURE 3: Two-Factor Authentication (2FA)
  Status: PARTIALLY WORKING - logic correct but NO EMAIL DELIVERY
  Flow: After login -> if 2FA enabled -> OTP issued (HMAC hash stored) -> verify_2fa.php
  Security: Max 5 attempts, 5-minute expiry, resend rate limit 1/minute, OTP never stored plaintext
  Dev mode: OTP shown in green dev-box on page. Production mode: OTP unreachable by user
  DB: two_factor_otps, security_audit_logs

FEATURE 4: Logout
  Status: FULLY WORKING
  Flow: POST form with CSRF token -> logout.php -> SessionManager::destroySession() -> redirect
  Security: POST method enforced, CSRF token required, status set to 'Offline'

FEATURE 5: Real-Time Chat Messaging
  Status: FULLY WORKING
  Flow: chatboard.php -> JS doSend() -> Fetch POST -> send_message.php (encrypt) -> INSERT
       -> 3-second polling: loadMessages() -> get_messages.php (decrypt) -> renderMessage()
  Security: CSRF on send, friendship authorization on both send+receive, XSS-safe p.textContent
  Encryption: AES-256-GCM, 12-byte random nonce, 128-bit auth tag
  Backward Compat: decryptMessage() handles v2:gcm, IV:CBC, and static-IV CBC legacy formats

FEATURE 6: Friend List / People Discovery
  Status: FULLY WORKING
  Flow: friendlist.php -> 3 sections: Your Friends / Friend Requests / People You May Know
  Security: CSRF on add/accept/decline, toast notifications

FEATURE 7: Send Friend Request
  Status: FULLY WORKING
  Security: Self-request blocked, bidirectional duplicate check, blocked relationship check

FEATURE 8: Accept/Decline Friend Request
  Status: FULLY WORKING
  Security: Ownership verified (receiver_id check), DB transaction on accept

FEATURE 9: User Profile View
  Status: FULLY WORKING
  Shows: cover photo, avatar, name, friend count (was broken in Phase 1, now fixed)

FEATURE 10: Edit Profile (Name + Photos)
  Status: FULLY WORKING
  Upload security: MIME type + extension whitelist, 5MB limit, old files deleted on replace

FEATURE 11: Change Password (Authenticated)
  Status: FULLY WORKING
  Security: Rate limit (5/15min), Argon2id+pepper, cross-device session invalidation (password_version++)

FEATURE 12: Toggle 2FA
  Status: FULLY WORKING

FEATURE 13: Forgot Password / Reset Password
  Status: FUNCTIONAL FOR DEVELOPMENT | NOT PRODUCTION-READY
  Security: Anti-enumeration (identical response always), 256-bit random token, SHA-256 hash stored, 15min expiry, single-use
  Gap: No email delivery. Dev mode shows clickable link on page only.

FEATURE 14: Force Password Change (Temporary Credentials)
  Status: FULLY WORKING
  Flow: is_temporary_password=1 -> any page redirects to force_change_password.php
  Security: checkRestrictedAccess() blocks all other pages, clears temp flag on success

FEATURE 15: Online Presence / Heartbeat
  Status: FULLY WORKING
  Flow: chatboard.php sends POST heartbeat every 30s -> UPDATE last_activity_at
       -> presence query uses 120-second TIMESTAMPDIFF threshold
  Security: CSRF on heartbeat, friendship authorization on presence queries

FEATURE 16: Chat Search Filter
  Status: FULLY WORKING
  Client-side only: filters .friend-card elements by name on keyup

FEATURE 17: Auto-Open Chat from URL (?friend_id=X)
  Status: FULLY WORKING
  Used by 'Message' buttons in friendlist.php to jump directly to conversation

FEATURE 18: Security Audit Logging
  Status: FULLY WORKING
  Dual write: security_audit_logs DB table AND logs/security_audit.log file
  Events: LOGIN, REGISTRATION, 2FA, PASSWORD_CHANGE, PASSWORD_RESET, LOGOUT, SESSION_INVALIDATED
  Sanitization: password/token/otp/key fields auto-redacted

## 6. Page / URL Map

URL                                          | Auth Required | Notes
-------------------------------------------------|--------------|------
/Daakpion/index.html                         | No           | Login card, forgot password link
/Daakpion/Register.html                      | No           | Registration form
/Daakpion/php/chatboard.php                  | YES (session) | Main messenger
/Daakpion/php/friendlist.php                 | YES (session) | Friends grid + discover
/Daakpion/php/user-profile.php               | YES (session) | Profile view
/Daakpion/php/edit-profile.php               | YES (not temp) | Edit name/photos/password/2FA
/Daakpion/php/forgot_password.php            | No           | Reset request
/Daakpion/php/reset_password.php             | No (token)   | Token-gated new password form
/Daakpion/php/verify_2fa.php                 | Pre-auth session | OTP input
/Daakpion/php/force_change_password.php      | YES (temp cred) | Mandatory temp->permanent pwd
/Daakpion/php/logout.php                     | POST+CSRF    | Session destroy
/Daakpion/php/get_messages.php               | YES          | JSON messages API
/Daakpion/php/send_message.php               | YES+CSRF     | Send encrypted message
/Daakpion/php/get_presence.php               | YES          | Online status API
/Daakpion/php/heartbeat.php                  | YES+CSRF     | Update last_activity_at
/Daakpion/php/send_request.php               | YES+CSRF     | Send friend request
/Daakpion/php/respond_request.php            | YES+CSRF     | Accept/decline request
/Daakpion/php/migrate_security.php           | CLI only (403 HTTP) | DB migration
/Daakpion/tests/                             | BLOCKED 403  | Test suite
/Daakpion/php/config.php                     | BLOCKED 403  | Deprecated
/Daakpion/php/security_secrets.php           | BLOCKED .htaccess | Server secrets

## 7. Permission Matrix

                          | Guest | Auth User | Temp-Cred User
--------------------------|-------|-----------|---------------
index.html                | YES   | YES       | YES
Register.html             | YES   | YES       | YES
forgot_password.php       | YES   | YES       | YES
reset_password.php        | token | token     | token
chatboard.php             | ->login | FULL    | ->force_change_pwd
friendlist.php            | ->login | FULL    | ->force_change_pwd
user-profile.php          | ->login | FULL    | ->force_change_pwd
edit-profile.php          | ->login | FULL    | ->force_change_pwd
get_messages.php          | 401   | friends only | 403
send_message.php          | 401   | friends+CSRF | 403
send_request.php          | 401   | YES+CSRF  | 403
respond_request.php       | 401   | YES+CSRF  | 403
heartbeat.php             | 401   | POST+CSRF | 403
logout.php                | 405(GET) | POST+CSRF | POST+CSRF
force_change_password.php | ->login | ->chatboard | FULL

Session variables set on login:
  user_id, user_name, user_email, password_version,
  must_change_password, created_at, last_activity, csrf_token

Session timeouts: Idle=30min, Absolute=12h
Cross-device invalidation: password_version mismatch destroys session

## 8. Request/Backend Flows

LOGIN FLOW:
  index.html form -> JS Fetch POST -> userlogin.php
    -> RateLimiter check (IP + email)
    -> users WHERE email=? (prepared stmt)
    -> CryptoService::dummyVerify() if not found (timing protection)
    -> CryptoService::verifyPassword(plain, hash) Argon2id+pepper
    -> Optional legacy bcrypt migration
    -> Check temp password expiry
    -> rateLimiter::clear()
    -> If 2FA: TwoFactorService::issueOtp() -> redirect verify_2fa.php
    -> Else: SessionManager::loginUser()
    -> UPDATE users status='Active now', last_activity_at=NOW()
    -> AuditLogger::log(LOGIN_SUCCESS)
    -> respond {success:true, redirect:'chatboard.php'}
  JS: window.location.href = 'php/chatboard.php'

SEND MESSAGE FLOW:
  chatboard.php JS doSend() -> Fetch POST -> send_message.php
    -> bootstrap_security.php
    -> session check (401 if not logged in)
    -> SessionManager::checkRestrictedAccess() (403 if temp)
    -> CsrfProtection::validateToken(['csrf_token'])
    -> Input validation (receiver_id, message, 2000 char limit)
    -> Self-message check
    -> friends WHERE (bidirectional) AND status='active' (auth check)
    -> CryptoService::encryptMessage() -> AES-256-GCM -> v2:gcm:iv:tag:ct
    -> INSERT INTO messages (sender_id, receiver_id, message, sent_at, is_read=0)
    -> HTTP 200 "Message sent"

POLL MESSAGES (every 3 seconds):
  setInterval -> loadMessages(friendId, false)
  -> Fetch GET -> get_messages.php?friend_id=X&since_id=N
    -> session check + friendship auth
    -> SELECT messages WHERE pair AND id>since_id ORDER ASC LIMIT 50
    -> For each: CryptoService::decryptMessage(ciphertext)
    -> JSON return
  JS: renderMessage() using p.textContent (XSS-safe)

FRIEND REQUEST FLOW:
  'Add Friend' click -> JS Fetch POST -> send_request.php
    -> CSRF validate
    -> Self-request block
    -> friends: check blocked/active relationship
    -> friendrequests: check A->B direction
    -> friendrequests: check B->A direction
    -> INSERT INTO friendrequests (sender, receiver, 'pending', NOW())
    -> echo "Friend request sent!"
  JS: showToast(msg); update button icon to checkmark

## 9. Feature -> File -> Database Dependency Map

Feature             | Frontend          | PHP Handler(s)                      | DB Tables
--------------------|-------------------|-------------------------------------|------------------
Login               | index.html        | userlogin.php                       | users, security_rate_limits, security_audit_logs
Registration        | Register.html     | registration.php                    | users, security_rate_limits, security_audit_logs
2FA Verify          | verify_2fa.php    | verify_2fa.php                      | two_factor_otps, security_audit_logs
Logout              | chatboard.php     | logout.php                          | users
Messaging           | chatboard.php(JS) | send_message.php, get_messages.php  | messages, friends
Presence            | chatboard.php(JS) | heartbeat.php, get_presence.php     | users
Friend List         | friendlist.php    | send_request.php, respond_request.php | friends, friendrequests, users
Profile View        | user-profile.php  | user-profile.php (self-rendering)   | users, friends
Edit Profile        | edit-profile.php  | edit-profile.php (self-rendering)   | users
Forgot Password     | forgot_password.php | forgot_password.php + PasswordResetService | password_resets, users
Reset Password      | reset_password.php  | reset_password.php + PasswordResetService  | password_resets, users
Force Pwd Change    | force_change_password.php | (self-rendering)           | users

## 10. Browser Testing Results

Apache: Running | URL: http://localhost/Daakpion

PAGE TESTS:
  index.html             -> LOADS OK - Facebook dark-mode login card, Inter font, FA 6.5 icons
  Register.html          -> LOADS OK - Two-panel layout, password toggle works
  chatboard.php (no auth) -> REDIRECTS to ../index.html (auth guard working)
  friendlist.php (no auth) -> REDIRECTS to login (auth guard working)
  user-profile.php (no auth) -> REDIRECTS to login (auth guard working)
  forgot_password.php    -> LOADS OK - Dark card, email form, CSRF token present
  verify_2fa.php (no pre-auth) -> REDIRECTS to login (userId<=0 check fires)
  config.php             -> HTTP 403 (correctly disabled)
  tests/                 -> HTTP 403 (correctly blocked)
  Login with wrong creds -> Shows "Invalid email or password." inline (no page reload)

VISUAL STATE:
  Dark mode: YES (background #18191a, cards #242526, blue #1877f2)
  Typography: Inter loaded from Google Fonts
  Icons: Font Awesome 6.5.0 from cdnjs
  Branding: DaakPion logo present on all pages
  Animations: fadeUp keyframe on page containers
  Error div in Register.html: starts empty (BUG-10 from Phase 1 is fixed)

## 11. Current Bugs & Issues

CRITICAL: None (Phase 1-4 remediations resolved all critical issues)

SERIOUS:
  BUG-CURRENT-01: NO EMAIL DELIVERY for 2FA OTP or Password Reset
    - No PHPMailer, no SMTP, no sendmail integrated
    - Production users cannot receive OTPs or reset links
    - verify_2fa.php says "sent to your account" but nothing was sent
    
  BUG-CURRENT-02: CSS DUPLICATION via @readfile() + external <link>
    - chatboard.php, friendlist.php, user-profile.php, edit-profile.php all load CSS
      BOTH as external link AND inline PHP readfile (doubles CSS load)
    
  BUG-CURRENT-03: CSS FILE ORGANIZATIONAL CHAOS
    - Root dir: chatboard.css, Register.css, friendlist.css, shared-header.css
    - css/ subdir: copies of all these
    - PHP files reference both locations inconsistently
    
  BUG-CURRENT-04: UNUSED ROOT-LEVEL CSS FILES
    - Styles.css: not referenced by any page
    - frontpage.css: not referenced by any page
    
  BUG-CURRENT-05: js/register.js IS DEAD CODE
    - Never loaded by Register.html
    - Uses broken selector ".signup form" (no .signup class exists)
    - Uses old XHR instead of Fetch
    
  BUG-CURRENT-06: SECRET_KEY in app_config.php is a placeholder
    - "your-strong-secret-key-change-me-in-production"
    - CryptoService blocks it from being used as MESSAGE_ENCRYPTION_KEY but it remains
    
  BUG-CURRENT-07: 2FA OTP verify_2fa.php says "sent to your account" misleadingly
    - Nothing is actually sent to user in production mode

MINOR:
  M-01: chatboard.php emoji/attach buttons are decorative only (no handlers)
  M-02: user-profile.php "Timeline & Activity" section is "Coming soon" placeholder
  M-03: friendlist.php search only filters "People You May Know", not "Your Friends"
  M-04: No scroll-up / load older messages in chatboard
  M-05: @readfile() uses error suppression @ instead of file_exists() check
  M-06: @unlink() in edit-profile.php silently suppresses old photo deletion errors
  M-07: No "is typing" indicator in chat
  M-08: Message timestamps not shown in chat UI (sent_at exists in API response but never rendered)
  M-09: is_read column in messages never set to 1 - no read receipt system
  M-10: ?v=time() cache-busting disables caching entirely (inefficient in production)
  M-11: No live password strength meter on Register.html (rejection only shown after submit)
  M-12: PasswordPolicy.php sequential check only compares first 8 characters of password

SECURITY STATUS SUMMARY:
  SQL Injection: PROTECTED (prepared statements throughout)
  XSS: PROTECTED (p.textContent + htmlspecialchars on all PHP output)
  CSRF: PROTECTED (hash_equals constant-time validation on all mutating endpoints)
  Password Hashing: STRONG (Argon2id + HMAC-SHA256 pepper, legacy auto-migrated)
  Message Encryption: STRONG (AES-256-GCM with random nonce + auth tag)
  Session Security: HARDENED (HttpOnly, SameSite=Lax, idle/absolute timeout)
  File Upload: PROTECTED (MIME + extension whitelist, size limit, .htaccess execution block)
  Rate Limiting: IMPLEMENTED (login, registration, 2FA, password reset, password change)
  User Enumeration: MITIGATED (constant-time dummyVerify, generic error messages)
  Data Access Auth: PROTECTED (friendship authorization on all message operations)
  Security Headers: IMPLEMENTED (CSP, X-Frame-Options, X-Content-Type-Options via .htaccess)
  Email Delivery: MISSING (OTP/reset tokens not deliverable in production)
  Admin Panel: ABSENT (no admin interface)
  HTTPS: LOCAL ONLY (HTTP in XAMPP dev, session.secure auto-detected)

## 12. Dead/Unused Components

  js/register.js          - Dead code: never loaded, broken selectors
  Styles.css (root)       - Dead code: not referenced anywhere
  frontpage.css (root)    - Dead code: not referenced anywhere
  chatboard.html (root)   - Orphaned static HTML, no active links
  edit-profile.html (root) - Orphaned static HTML
  user-profile.html (root) - Orphaned static HTML
  php/config.php          - Disabled: returns 403 intentionally
  Register.css (root)     - Partially redundant (css/ has canonical copy)
  shared-header.css (root) - Redundant (css/ has canonical copy)
  docs/daakpion_facebook_redesign_plan.md - Forward-looking plan, not yet implemented
  banner.png              - Used only in README.md for GitHub display
  dp.png                  - Standalone test image, not used in any page

## 13. Architecture Diagram

  BROWSER CLIENT
    index.html / Register.html / chatboard.php / friendlist.php
    user-profile.php / edit-profile.php
    verify_2fa.php / forgot_password.php / reset_password.php
    force_change_password.php
          |
          | HTTP/AJAX (Fetch API) + CSRF tokens
          v
  APACHE + PHP (XAMPP)
    bootstrap_security.php [Entry Point for ALL PHP]
      app_config.php + security_secrets.php + db_connect.php
      spl_autoload_register -> Daakpion\Security\*
      SessionManager::startSecureSession()
      SessionManager::validateSessionState()
      HTTP Security Headers (CSP, X-Frame-Options, etc.)
          |
    AUTH ENDPOINTS            API ENDPOINTS
    userlogin.php             get_messages.php
    registration.php          send_message.php
    logout.php                get_presence.php
    verify_2fa.php            heartbeat.php
    forgot_password.php       send_request.php
    reset_password.php        respond_request.php
    force_change_password.php
          |
    Daakpion\Security\* (OOP Classes)
    CryptoService       - Argon2id+pepper hashing, AES-256-GCM encryption
    SessionManager      - Session lifecycle + cross-device invalidation
    CsrfProtection      - Token generation + constant-time validation
    RateLimiter         - MySQL atomic sliding-window rate limiting
    AuditLogger         - DB + flat file dual security logging
    PasswordPolicy      - Password strength validation rules
    TwoFactorService    - OTP lifecycle management
    PasswordResetService- Token generation, hashing, verification, completion
    Environment         - dev/test/production mode detection
          |
          | OOP mysqli prepared statements
          v
  MYSQL / MariaDB (XAMPP) - Database: daakpion
    users                 - Core user data + all security columns
    friends               - Active bidirectional friendships
    friendrequests        - Pending/responded requests
    messages              - AES-256-GCM encrypted chat messages
    security_rate_limits  - Atomic brute-force protection records
    security_audit_logs   - Security event database records
    password_resets       - SHA-256-hashed reset token store
    two_factor_otps       - HMAC-SHA256-hashed OTP store

  EXTERNAL DEPENDENCIES:
    Google Fonts (Inter) -> fonts.googleapis.com
    Font Awesome 6.5.0   -> cdnjs.cloudflare.com

## 14. Recommended Next Steps

PRIORITY 1 - FUNCTIONAL BLOCKERS:
  1. Implement email delivery (PHPMailer + SMTP) for 2FA OTP and password reset tokens
     Without this, app cannot be used in production
  2. Remove/replace orphaned static HTML files (chatboard.html, edit-profile.html, user-profile.html)
     These are confusing and serve no purpose

PRIORITY 2 - CODE CLEANUP (Safe, Non-Breaking):
  3. Remove @readfile() CSS inlining - use external <link> only
  4. Delete dead files: js/register.js, Styles.css, frontpage.css
  5. Fix search scope in friendlist.php to include the 'Your Friends' section
  6. Replace ?v=time() cache-busting with a content hash or version constant
  7. Remove or generate a real SECRET_KEY value in app_config.php

PRIORITY 3 - UX ENHANCEMENTS:
  8. Show message timestamps under chat bubbles (sent_at already in API response)
  9. Implement read receipts using existing is_read column
  10. Add live password strength meter on Register.html
  11. Add "is typing" indicator
  12. Add load-older-messages (scroll-up) pagination

PRIORITY 4 - ARCHITECTURE:
  13. Move security_secrets.php above web root (outside htdocs/)
  14. Replace 3-second polling with WebSockets or Server-Sent Events
  15. Add admin panel for user management and system health
  16. Replace CLI migrate_security.php with a proper migration runner
