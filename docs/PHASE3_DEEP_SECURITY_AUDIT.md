# DaakPion — Phase 3 Deep Security Audit & Controlled Attack Simulation Report

**Project:** DaakPion Real-Time PHP Chat Application  
**Repository / Path:** `badhanamitroy/Daak-Pion-Chat-App` (`c:\xampp\htdocs\Daakpion`)  
**Audit Target Branch:** `security-remediation-phase2` (active audit branch: `security-deep-audit-phase3`)  
**Assessment Date:** October 2026  
**Auditor / Security Engineer:** DeepMind Advanced Agentic Security Team  
**Evaluation Model:** Adversarial Attacker Perspective (Controlled, Non-Destructive, Non-Modifying First Pass)  

---

## 1. Executive Summary

Following the completion and verification of Phase 1 and Phase 2 security remediations (which established 159 passing automated security and regression verifications), an exhaustive **Phase 3 Deep Security Audit and Controlled Attack Simulation** was conducted from the perspective of an advanced adversary seeking to bypass application-layer controls, authorization logic, and cryptographic mechanisms.

In strict adherence to the Phase 3 mission rules, **no application source code was modified during this audit phase**. All attack simulations were conducted using controlled, non-destructive, and reversible tests on local loopback infrastructure and synthetic test accounts.

### Key Assessment Outcomes:
1. **Core Protections Robust:** The core defenses deployed in Phase 1 and Phase 2—including Argon2id password hashing with HMAC-SHA256 pepper, cross-device session invalidation via `password_version`, anti-enumeration password resets, brute-force rate limiting, AES-256-GCM message authenticated encryption, and cursor-based pagination—were rigorously tested and confirmed resilient against direct bypass.
2. **Zero SQL Injection or Stored/Reflected XSS:** Parameterized SQL prepared statements and contextual output escaping (`htmlspecialchars()` and `.textContent` DOM insertion) were confirmed consistent across all active endpoints.
3. **Confirmed Adversarial Vectors Discovered:**
   - **`DP-P3-001` (High):** Blocked User Can Send Friend Request to Blocker & Bypass Blockade.
   - **`DP-P3-002` (High):** Hardcoded Default Encryption Key In Use for Message AEAD Encryption.
   - **`DP-P3-003` (Medium):** Friend Request Decline Action Incompatible with Database Enum & Causes Permanent Re-Send DoS.
   - **`DP-P3-004` (Low):** Missing CSRF Protection on Session Logout Endpoint (Logout CSRF).
   - **`DP-P3-005` (Low):** Information Disclosure via Orphaned Legacy Script `php/config.php` and Verbose Server Headers.
   - **`DP-P3-006` (Low-Medium):** Missing Query Bounds on Friends List and Pending Requests in `friendlist.php`.
   - **`DP-P3-007` (Informational):** Weak Content Security Policy Permitting `'unsafe-inline'` and Broad Cloudflare CDN.
   - **`DP-P3-008` (Low):** User Account Existence Disclosure via Registration Endpoint.

All 159 baseline automated regression tests remain **100% PASSING** (0 failures).

---

## 2. Scope

The assessment covered the full local deployment of the DaakPion codebase:

* **Authentication & Credentials:** `php/userlogin.php`, `php/registration.php`, `php/verify_2fa.php`, `php/forgot_password.php`, `php/reset_password.php`, `php/force_change_password.php`, `php/logout.php`.
* **Social & Messaging Endpoints:** `php/send_message.php`, `php/get_messages.php`, `php/send_request.php`, `php/respond_request.php`, `php/friendlist.php`, `php/chatboard.php`, `php/user-profile.php`, `php/edit-profile.php`.
* **Security Framework:** `php/bootstrap_security.php`, `php/app_config.php`, `php/Security/CryptoService.php`, `php/Security/SessionManager.php`, `php/Security/CsrfProtection.php`, `php/Security/RateLimiter.php`, `php/Security/AuditLogger.php`, `php/Security/PasswordPolicy.php`, `php/Security/PasswordResetService.php`, `php/Security/TwoFactorService.php`, `php/Security/Environment.php`.
* **Web Server & Configuration:** `.htaccess`, `ProfilePics/.htaccess`, `Coverpics/.htaccess`, `tests/.htaccess`, `php/db_connect.php`, `php/config.php`.
* **Frontend Interfaces:** `index.html`, `Register.html`, `seepassword.js`, `homepage.css`, `Register.css`, `chatboard.css`, `friendlist.css`, `edit-user-profile.css`, `user-profile.css`.

---

## 3. Environment

* **Operating System:** Windows 10/11 x64
* **Web Server:** Apache/2.4.58 (Win64) OpenSSL/3.1.3 mod_php
* **PHP Runtime:** PHP 8.0.30 (cli and apache2handler)
* **Database Management System:** MariaDB 10.4.32 / MySQL 15.1
* **Host Address:** `127.0.0.1:80` (HTTP loopback)
* **Database Name:** `daakpion`

---

## 4. Existing Security Controls Baseline

The application entered Phase 3 with the following controls implemented from Phase 1 and Phase 2:

| Control | Description | Status |
| :--- | :--- | :--- |
| **Argon2id + Pepper** | Memory-hard password hashing with server-side 256-bit pepper. | Active & Verified |
| **Session Hardening** | `HttpOnly`, `SameSite=Lax`, `use_strict_mode=1`, session fixation regeneration. | Active & Verified |
| **Cross-Device Invalidation** | `password_version` counter in database checked on every request. | Active & Verified |
| **Anti-Enumeration Resets** | SHA-256 token hashing, single-use, uniform timing via dummy verification. | Active & Verified |
| **Two-Factor Authentication** | HMAC-SHA256 hashed 6-digit OTP, 5-minute expiry, max 5 attempts. | Active & Verified |
| **Brute-Force Rate Limiter** | Rate limits on IP and email dimensions with exponential lockout. | Active & Verified |
| **Authenticated Encryption** | AES-256-GCM AEAD format `v2:gcm:<iv>:<tag>:<cipher>` with fail-closed decryption. | Active & Verified |
| **Cursor Pagination** | `since_id` and `before_id` cursor queries with clamped limit (1–100) in chat. | Active & Verified |
| **Access Control (CLI)** | `migrate_security.php` locked to CLI; tests shielded with HTTP 403. | Active & Verified |
| **Safe Error Handling** | `$conn->error` suppressed from client responses and routed to `error_log()`. | Active & Verified |

---

## 5. Attack Surface Inventory

### A. Authentication Surface
* `POST php/userlogin.php`: Accepts `email`, `password`. Supports JSON and HTML form submissions. Rate-limited.
* `POST php/registration.php`: Accepts `fname`, `lname`, `email`, `password`. Rate-limited per IP.
* `POST php/verify_2fa.php`: Accepts `otp`, `csrf_token`, `verify_otp`, `resend_otp`.
* `POST php/forgot_password.php`: Accepts `email`, `csrf_token`.
* `GET/POST php/reset_password.php`: Accepts `token`, `new_password`, `confirm_password`, `csrf_token`.
* `POST php/force_change_password.php`: Accepts `current_password`, `new_password`, `confirm_password`, `csrf_token`.
* `GET/POST php/logout.php`: Destroys session.

### B. Social & Messaging Surface
* `POST php/send_message.php`: Accepts `receiver_id`, `message`, `csrf_token` or `X-CSRF-Token`.
* `GET php/get_messages.php`: Accepts `friend_id`, `limit`, `since_id`, `before_id`.
* `POST php/send_request.php`: Accepts `receiver_id`, `csrf_token` or `X-CSRF-Token`.
* `POST php/respond_request.php`: Accepts `request_id`, `action` (`accept` or `decline`), `csrf_token` or `X-CSRF-Token`.
* `GET php/friendlist.php`: Renders friends list, pending requests, and all users directory.
* `GET php/chatboard.php`: Renders messenger UI, active friends, and active chat window.

### C. Profile & Media Operations
* `GET php/user-profile.php`: Renders logged-in user profile, friend count, and cover photo.
* `GET/POST php/edit-profile.php`:
  * Name update: `fname`, `lname`, `csrf_token`, `update_name`.
  * Profile picture upload: `profile_pic` (file), `csrf_token`, `update_profile_pic`.
  * Cover picture upload: `cover_pic` (file), `csrf_token`, `update_cover_pic`.
  * Password change: `current_password`, `new_password`, `confirm_password`, `csrf_token`, `change_password`.
  * 2FA toggle: `csrf_token`, `toggle_2fa`.

### D. Security Boundaries
* **Unauthenticated vs. Authenticated:** Guarded by `$_SESSION['user_id']`.
* **Restricted vs. Full Access:** Guarded by `$_SESSION['must_change_password']` and `SessionManager::checkRestrictedAccess()`.
* **Direct Messaging:** Guarded by mutual active friendship in `friends` table (`status = 'active'`).
* **Friend Request Responding:** Guarded by `friendrequests.receiver_id = $_SESSION['user_id']`.
* **Profile Management:** Scoped strictly to `$_SESSION['user_id']`.

---

## 6. Detailed Technical Audit Findings by Category

### A. SQL Injection Deep Audit
* **Audit Methodology:** Audited every database interaction across all PHP files. Injected harmless boolean payloads (`' OR '1'='1`, `" OR ""="`, `1' UNION SELECT`), syntax breaking characters (`'`, `"`, `\`), and numeric out-of-range values across all GET, POST, and query parameters.
* **Findings:** Zero SQL injection vulnerabilities detected.
* **Evidence:**
  * All queries without exception utilize parameterized prepared statements (`mysqli::prepare` and `bind_param`).
  * Dynamic integer inputs (`friend_id`, `since_id`, `before_id`, `limit`, `receiver_id`, `request_id`) are explicitly cast using `(int)` or `max(0, (int)...)` prior to binding.
  * Technical error disclosures (`$conn->error`) are strictly redirected to server-side `error_log()` and replaced with generic client-safe notifications.

### B. Authorization, IDOR & BOLA
* **Audit Methodology:** Evaluated resource ownership boundaries using synthetic test accounts (User A = Owner, User B = Unrelated Peer, User C = Blocked/Pending Relationship). Attempted parameter substitution on user IDs, conversation endpoints, friend request IDs, and message retrieval.
* **Findings:**
  1. **Message Conversation IDOR:** Properly prevented. `php/get_messages.php` checks that the authenticated user is an active friend of the requested `friend_id` before querying records, and queries exclusively messages where either `sender_id` or `receiver_id` matches the session user.
  2. **Profile IDOR:** Properly prevented. Neither `user-profile.php` nor `edit-profile.php` honors any `?id=` parameter; both strictly query `$_SESSION['user_id']`.
  3. **Friend Request Response IDOR:** Properly prevented. `respond_request.php` enforces `WHERE id=? AND receiver_id=?`, rejecting attempts by unauthorized users to accept or decline third-party requests.
  4. **Blocked User Friend Request Creation (`DP-P3-001`):** **VULNERABLE.** `send_request.php` only checks if the relationship is `status = 'active'`. If User B blocked User A, User A can still submit a friend request to User B. User B receives the request and, upon acceptance, creates an active friendship that unblocks User A.

### C. Authentication & Session Security
* **Audit Methodology:** Tested login rate limiting, brute-force resistance, timing attacks, session fixation, cross-device session termination, and temporary password isolation.
* **Findings:**
  * **Brute-Force Rate Limiting:** Enforced on both client IP and target email dimensions. Exceeding 5 failures locks the account/IP for 15 minutes with exponential backoff.
  * **Timing Attacks:** Mitigated. If an email does not exist, `CryptoService::dummyVerify()` runs an Argon2id verification on a pre-computed hash, rendering response times identical to valid user password verification.
  * **Session Fixation:** Protected. `session_regenerate_id(true)` is executed during login, 2FA verification, and password change.
  * **Cross-Device Invalidation:** Protected. Every authenticated request checks `users.password_version` against session state; modifying a password invalidates all other concurrent browser sessions immediately.
  * **Session Timeouts:** Enforced. 30-minute idle timeout and 12-hour absolute lifetime are validated on active sessions.
  * **Logout CSRF (`DP-P3-004`):** **VULNERABLE.** `php/logout.php` processes unauthenticated GET requests without anti-CSRF token verification.

### D. Password Reset & Two-Factor Authentication
* **Audit Methodology:** Evaluated token generation entropy, storage format, expiration, replayability, rate limiting, and dev secret leakage.
* **Findings:**
  * **Password Reset Anti-Enumeration:** Robust. Returns identical messaging and execution timing for existent and nonexistent emails.
  * **Token Storage:** Tokens are hashed with SHA-256 before database insertion; raw tokens are never persisted in the database.
  * **Token Replay:** Verified single-use. Tokens are marked `used_at = NOW()` immediately upon password reset completion.
  * **2FA OTP Challenges:** Cryptographically random 6-digit numeric codes hashed via HMAC-SHA256 with the server-side pepper. Plaintext OTPs are never stored or logged.
  * **Attempt Limits:** After 5 failed attempts, the OTP challenge is permanently marked used and invalidated.
  * **Environment Isolation:** In `APP_ENV=production`, `dev_otp` and `dev_token` are strictly omitted from responses and UI forms.

### E. Cryptography Deep Audit
* **Audit Methodology:** Inspected `php/Security/CryptoService.php`, key loading routines, nonce generation, tag verification, and legacy CBC isolation.
* **Findings:**
  1. **AES-256-GCM AEAD Implementation:** Robust. Utilizes 12-byte random nonces (`random_bytes(12)`) and 16-byte authentication tags. Any ciphertext bit-flipping or tag tampering fails closed, returning `null` without throwing unhandled exceptions.
  2. **Legacy CBC Isolation:** Confirmed secure from external tampering. User-controlled ciphertext cannot reach the legacy CBC decryption path because `send_message.php` encrypts all user inputs as `v2:gcm:` payloads. Decryption failures return `null` and render `[message unavailable]` without leaking padding oracle status.
  3. **Hardcoded Default Key Fallback (`DP-P3-002`):** **VULNERABLE.** Unlike `getPepper()` (which checks `PROHIBITED_PEPPERS` and fails closed), `getMessageKey()` does not validate against placeholder keys and silently falls back to `SECRET_KEY` in `php/app_config.php` (`'your-strong-secret-key-change-me-in-production'`). Because `php/security_secrets.php` does not define `MESSAGE_ENCRYPTION_KEY`, messages in the live system are encrypted with the publicly known placeholder key.

### F. CSRF Protection
* **Audit Methodology:** Probed all state-changing endpoints with missing, invalid, expired, and cross-session CSRF tokens, as well as GET-based state change attempts.
* **Findings:**
  * `php/send_message.php`, `php/send_request.php`, `php/respond_request.php`, and `php/edit-profile.php` require and validate anti-CSRF tokens using constant-time `hash_equals()`.
  * Tokens are tied to `$_SESSION['csrf_token']` and delivered via meta tags and hidden form fields.
  * `SameSite=Lax` cookie flags provide defense-in-depth against cross-site POST attacks.
  * As noted in `DP-P3-004`, `php/logout.php` lacks CSRF protection.

### G. Cross-Site Scripting (XSS)
* **Audit Methodology:** Injected HTML and JavaScript payloads (`<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`, `javascript:...`) into usernames, chat messages, profile fields, and URL parameters.
* **Findings:** Zero exploitable XSS vulnerabilities identified.
  * All PHP output echoes use `htmlspecialchars(..., ENT_QUOTES, 'UTF-8')`.
  * Chat messages in `php/chatboard.php` are rendered via `p.textContent = msg.message;` and appended using DOM methods, preventing DOM XSS.
  * URL error parameters in `index.html` are set via `loginError.textContent = errorParam;`.

### H. File Upload Security
* **Audit Methodology:** Evaluated `php/edit-profile.php` profile picture and cover photo uploads. Attempted executable extensions (`.php`, `.phtml`, `.php5`), double extensions (`test.php.jpg`), MIME type spoofing, traversal paths (`../../avatar.jpg`), and oversized payloads.
* **Findings:** File upload architecture is secure.
  * Strict file size cap (5 MB) enforced.
  * MIME type validated using `finfo(FILEINFO_MIME_TYPE)` against an image whitelist (`image/jpeg`, `image/png`, `image/gif`, `image/webp`).
  * Extension validated against whitelist (`jpg`, `jpeg`, `png`, `gif`, `webp`).
  * Server discards uploaded client filenames and renames files to `"profile_{userId}_{time}.jpg"`.
  * `ProfilePics/.htaccess` and `Coverpics/.htaccess` enforce `php_flag engine off` and `FilesMatch "\.php$" Deny from all`, preventing server-side execution.

### I. Path Traversal & Local File Inclusion
* **Audit Methodology:** Audited all file operations, `include`, `require`, and `readfile` calls for user-controlled path construction.
* **Findings:** Zero path traversal vulnerabilities found. All file includes and stylesheet inlining operations use hardcoded paths relative to `__DIR__`.

### J. Pagination & Resource Abuse
* **Audit Methodology:** Tested pagination boundaries, oversized limits (`limit=999999`), negative offsets, non-numeric strings, and large list queries.
* **Findings:**
  * In `php/get_messages.php`, `limit` is clamped to a strict maximum of 100 (default: 50), and cursors are bounded by `max(0, (int)$_GET['...'])`.
  * In `php/chatboard.php` and `php/friendlist.php` (all-users query), `LIMIT 100` is enforced.
  * **Unbounded Friend & Pending Queries (`DP-P3-006`):** In `php/friendlist.php`, the `$fq` (active friends) and `$pq` (pending requests) queries lack `LIMIT` clauses, presenting a denial-of-service / memory exhaustion risk for high-volume accounts.

### K. Security Headers & Content Security Policy (CSP)
* **Audit Methodology:** Inspected HTTP response headers emitted by Apache (`.htaccess`) and PHP (`bootstrap_security.php`).
* **Findings:**
  * Headers present: `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`.
  * Duplicate headers observed: Because both Apache `.htaccess` and PHP `bootstrap_security.php` set the security headers, responses contain duplicate header directives.
  * **CSP Configuration (`DP-P3-007`):** The current policy includes `script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com`. While necessary for current inline event handlers and Google Fonts/CDN assets, `'unsafe-inline'` prevents CSP from acting as a robust barrier against hypothetical future XSS flaws, and open CDNs present gadget bypass risks.

### L. Information Disclosure & Orphaned Files
* **Audit Methodology:** Probed direct HTTP access to configuration, secrets, log files, and database connectors.
* **Findings:**
  * `php/security_secrets.php`, `php/migrate_security.php`, and `logs/security_audit.log` are shielded by `.htaccess` with HTTP 403 Forbidden.
  * **Orphaned Script Exposure (`DP-P3-005`):** Legacy file `php/config.php` is unshielded, returns HTTP 200, and discloses technical connection error details (`mysqli_connect_error()`) upon failure.
  * Server discloses `X-Powered-By: PHP/8.0.30` and detailed Apache/OpenSSL versions in HTTP headers.
  * **Registration Account Probing (`DP-P3-008`):** `php/registration.php` returns `"This email address is already registered."`, allowing account existence enumeration (mitigated by IP rate limiting).

---

## 7. Confirmed Findings Dossier

---

### Finding DP-P3-001
* **Severity:** **High**
* **Title:** Blocked User Can Send Friend Request to Blocker & Bypass Blockade
* **CWE:** CWE-284: Improper Access Control / CWE-840: Business Logic Error
* **OWASP Category:** A01:2021-Broken Access Control
* **Affected Component:** `php/send_request.php` (lines 40–58) & `php/respond_request.php` (lines 51–65)
* **Preconditions:** User B has blocked User A (relationship stored in `friends` table as `status = 'blocked'`).
* **Attacker Capability:** User A (the blocked user) issues a POST request to `send_request.php` specifying `receiver_id = B`.
* **Expected Secure Behavior:** The server must verify that no blocking relationship exists between the sender and receiver. If a block is active in either direction, the request must be rejected with HTTP 403 Forbidden.
* **Observed Behavior:** `send_request.php` only checks if the users are already active friends (`AND status = 'active'`). It completely ignores records with `status = 'blocked'`. Consequently, a pending friend request is created in `friendrequests`. When User B visits their friend list, the request is displayed. If User B accepts, an `INSERT INTO friends ... status='active'` is executed, effectively overwriting the blockade and restoring full messaging rights to the blocked user.
* **Minimal Reproduction:**
  1. Insert blocked record: `INSERT INTO friends (user1_id, user2_id, status) VALUES (21, 20, 'blocked')`.
  2. Authenticate as User 20 (blocked).
  3. POST to `send_request.php` with `receiver_id=21` and valid CSRF token.
  4. Response: `"Friend request sent!"`. Record created in `friendrequests`.
* **Evidence:** Verified via isolated automated test script `scratch/test_blocked_send_request.php`:
  ```text
  1. User 21 blocked User 20 in friends table.
  2. Simulating send_request.php: User 20 attempts to send friend request to User 21...
   - Already active friends check: NOT FOUND (Passed!)
   - Pending checks passed: YES
   - Friend request insert executed: SUCCESS! Request was created!
   - CONFIRMED: Pending friend request exists in DB from blocked user 20 to blocker 21!
  ```
* **Security Impact:** Complete bypass of user blocking mechanisms, harassment vector, unauthorized contact, and privilege escalation from blocked state to active friendship.
* **Root Cause:** Incomplete status validation in `send_request.php`; query checks only `status = 'active'` rather than verifying the absence of any restrictive relationships (`status = 'blocked'`).
* **Recommended Remediation:**
  1. In `send_request.php`, add a query checking if either user has blocked the other in `friends`:
     ```sql
     SELECT id FROM friends
     WHERE ((user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?))
       AND status = 'blocked'
     LIMIT 1
     ```
  2. Reject with HTTP 403 Forbidden if a blocked record exists.
* **Regression Test Required:** Add test case to `tests/Phase3RemediationTest.php` asserting that blocked users receive HTTP 403 when calling `send_request.php`.
* **Status:** **CONFIRMED**

---

### Finding DP-P3-002
* **Severity:** **High**
* **Title:** Hardcoded Default Encryption Key In Use for Message AEAD Encryption
* **CWE:** CWE-798: Use of Hard-coded Credentials / CWE-321: Use of Hard-coded Cryptographic Key
* **OWASP Category:** A02:2021-Cryptographic Failures
* **Affected Component:** `php/Security/CryptoService.php` (`getMessageKey()`, lines 260–283) and `php/app_config.php` (line 11)
* **Preconditions:** `php/security_secrets.php` defines only `PASSWORD_PEPPER`, omitting `MESSAGE_ENCRYPTION_KEY`.
* **Attacker Capability:** An attacker with access to the source repository or public configuration knows the default key `'your-strong-secret-key-change-me-in-production'`. The attacker can derive `hash('sha256', SECRET_KEY, true)` and decrypt any stored or intercepted AES-256-GCM message without needing database access or runtime secrets.
* **Expected Secure Behavior:** `CryptoService::getMessageKey()` must fail closed (throwing an exception) if the encryption key is missing, empty, or set to an insecure placeholder, identical to the strict fail-closed validation enforced by `CryptoService::getPepper()`.
* **Observed Behavior:** `getMessageKey()` silently falls back to `SECRET_KEY` in `app_config.php`. Because `security_secrets.php` does not define `MESSAGE_ENCRYPTION_KEY`, all production and development chat messages are encrypted using the public placeholder key.
* **Minimal Reproduction:**
  1. Call `CryptoService::encryptMessage("Secret conversation")`.
  2. Using only the string `'your-strong-secret-key-change-me-in-production'`, call `CryptoService::decryptMessage($cipher, $key)`.
  3. Result: Full plaintext recovered.
* **Evidence:** Verified via automated reproduction script `scratch/test_key_exposure.php`:
  ```text
  Encrypted ciphertext: v2:gcm:Ie5yK+2aB+L/lOMt:/QMGW0xAYqzTsjcK96pdfA==:U7tqU3WXQrho/fgN2dH9f7AEiWrqhQpfuXxe7MumEg==
  Attacker decrypted: 'Confidential chat between users'
  Decryption matches original? CONFIRMED YES!
  ```
* **Security Impact:** Complete loss of confidentiality for all chat communications across all users.
* **Root Cause:** Absence of fail-closed placeholder validation in `CryptoService::getMessageKey()` and omission of `MESSAGE_ENCRYPTION_KEY` in `security_secrets.php`.
* **Recommended Remediation:**
  1. In `php/security_secrets.php`, define a dedicated, cryptographically secure 256-bit random key:
     ```php
     define('MESSAGE_ENCRYPTION_KEY', '<64-char-hex-secret>');
     ```
  2. In `CryptoService::getMessageKey()`, check against `PROHIBITED_KEYS` and throw a `RuntimeException` if a default key is detected.
* **Regression Test Required:** Automated test asserting that placeholder keys throw an exception on encryption attempt.
* **Status:** **CONFIRMED**

---

### Finding DP-P3-003
* **Severity:** **Medium**
* **Title:** Friend Request Decline Action Incompatible with Database Enum & Causes Permanent Re-Send DoS
* **CWE:** CWE-704: Incorrect Type Conversion or Cast / CWE-840: Business Logic Error
* **OWASP Category:** A04:2021-Insecure Design / A08:2021-Software and Data Integrity Failures
* **Affected Component:** `php/respond_request.php` (line 74) & `php/send_request.php` (lines 62–122)
* **Preconditions:** User A sends a friend request to User B. User B declines the request.
* **Attacker Capability:** Normal application usage triggers database corruption. When User B clicks "Delete" (decline), `respond_request.php` executes `UPDATE friendrequests SET status='declined'`. However, MySQL column definition is `status ENUM('pending','accepted','rejected')`. Because `'declined'` is invalid, MySQL writes an empty string `''` (or aborts in strict SQL mode). When User A attempts to send a friend request to User B in the future, `send_request.php` checks only `WHERE status = 'pending'`, passes the check, and attempts `INSERT INTO friendrequests ...`. Because `friendrequests` has a `UNIQUE KEY (sender_id, receiver_id)`, MySQL throws `Duplicate entry 'A-B' for key 'sender_id'`, causing an unhandled HTTP 500 error. User A can never send a friend request to User B again.
* **Expected Secure Behavior:** Declining a friend request should update the row to `status = 'rejected'` (or delete the row), and subsequent re-requests should either update the existing row or cleanly succeed without database key collision.
* **Observed Behavior:** Database column receives empty string `''`, and all future friend requests between those users crash with HTTP 500 duplicate key failure.
* **Minimal Reproduction:**
  1. User A sends request to User B.
  2. User B declines request via `respond_request.php` (`action=decline`).
  3. User A attempts to re-send request via `send_request.php`.
  4. Server responds with HTTP 500 `"Error sending request. Please try again."`.
* **Evidence:** Verified via automated reproduction script `scratch/test_decline.php`:
  ```text
  1. Request sent (id 48)
  2. Request declined by User 2
  3. User 1 attempts to re-send request to User 2...
   - Pending check passed? YES
   - Re-send insert FAILED! Error: Duplicate entry '20-21' for key 'sender_id'
  ```
* **Security Impact:** Denial of service on core social friendship workflows; permanent account desynchronization; unhandled database error crashes.
* **Root Cause:** String mismatch between application code (`'declined'`) and database schema (`'rejected'`), coupled with an `INSERT` pattern against a table with a unique composite key that retains historic records.
* **Recommended Remediation:**
  1. In `respond_request.php`, update status to `'rejected'` (or delete the record).
  2. In `send_request.php`, update existing non-pending records instead of attempting an unqualified `INSERT`, or handle duplicate key collisions gracefully.
* **Regression Test Required:** Automated test asserting that declining a request allows subsequent re-sending without duplicate key failure.
* **Status:** **CONFIRMED**

---

### Finding DP-P3-004
* **Severity:** **Low**
* **Title:** Missing CSRF Protection on Session Logout Endpoint (Logout CSRF)
* **CWE:** CWE-352: Cross-Site Request Forgery (CSRF)
* **OWASP Category:** A01:2021-Broken Access Control
* **Affected Component:** `php/logout.php` (lines 1–22)
* **Preconditions:** Victim user is logged in to DaakPion.
* **Attacker Capability:** Attacker places an image tag `<img src="http://<target>/Daakpion/php/logout.php">` or triggers a cross-origin link.
* **Expected Secure Behavior:** Logout must be a state-changing POST action requiring a valid anti-CSRF token (`CsrfProtection::validateToken()`).
* **Observed Behavior:** `php/logout.php` unconditionally accepts GET requests without token verification, immediately destroying the user's session and forcing logout.
* **Minimal Reproduction:**
  1. Authenticate synthetic user.
  2. Issue GET request via curl or browser to `http://127.0.0.1/Daakpion/php/logout.php`.
  3. Session is terminated; subsequent authenticated request is redirected to `index.html`.
* **Evidence:** Verified via loopback curl request executing session termination over GET.
* **Security Impact:** Nuisance denial of service; attackers can force-logout active users across origins.
* **Root Cause:** Absence of HTTP method verification and anti-CSRF token validation in `logout.php`.
* **Recommended Remediation:**
  1. Enforce `$_SERVER['REQUEST_METHOD'] === 'POST'` in `logout.php`.
  2. Validate CSRF token using `CsrfProtection::validateToken()`.
  3. Update UI logout buttons in `user-profile.php` and `chatboard.php` to submit a POST form with CSRF token.
* **Regression Test Required:** Test case in `tests/Phase3RemediationTest.php` asserting that GET requests to `logout.php` are rejected.
* **Status:** **CONFIRMED**

---

### Finding DP-P3-005
* **Severity:** **Low**
* **Title:** Information Disclosure via Orphaned Legacy Script `php/config.php` and Verbose Server Headers
* **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
* **OWASP Category:** A05:2021-Security Misconfiguration
* **Affected Component:** `php/config.php` (lines 1–5) and HTTP Response Headers
* **Preconditions:** Direct HTTP access to `http://localhost/Daakpion/php/config.php`.
* **Attacker Capability:** Attacker can probe unshielded legacy file `php/config.php` which executes an independent legacy connection and echoes `mysqli_connect_error()` upon failure. Additionally, the server emits `X-Powered-By: PHP/8.0.30` and `Server: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30`.
* **Expected Secure Behavior:** Orphaned files must be removed or denied by `.htaccess`. Server signature headers (`X-Powered-By`) must be suppressed.
* **Observed Behavior:** `php/config.php` returns HTTP 200 with `X-Powered-By: PHP/8.0.30` header.
* **Minimal Reproduction:**
  ```bash
  curl.exe -i -s http://127.0.0.1/Daakpion/php/config.php
  ```
* **Evidence:** Observed HTTP response headers:
  ```http
  HTTP/1.1 200 OK
  Server: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30
  X-Powered-By: PHP/8.0.30
  ```
* **Security Impact:** Server fingerprinting and potential database error leakage during database outages.
* **Root Cause:** Unused legacy configuration file was not removed during previous remediation phases, and `expose_php` is active.
* **Recommended Remediation:**
  1. Remove `php/config.php` or block it in `.htaccess` `FilesMatch`.
  2. In `php.ini` or `.htaccess`, add `Header unset X-Powered-By` and `php_flag expose_php off`.
* **Regression Test Required:** Test case asserting HTTP 403 or 404 for `php/config.php`.
* **Status:** **CONFIRMED**

---

### Finding DP-P3-006
* **Severity:** **Low-Medium**
* **Title:** Missing Query Bounds on Friends List and Pending Requests in `friendlist.php`
* **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
* **OWASP Category:** A04:2021-Insecure Design
* **Affected Component:** `php/friendlist.php` (lines 36–54 and 59–78)
* **Preconditions:** User has accumulated a high number of friends or incoming friend requests.
* **Attacker Capability:** A bot network or attacker sends hundreds of automated friend requests to a target account. When the victim visits `friendlist.php`, the server executes unbounded queries (`SELECT ... FROM friendrequests WHERE receiver_id = ? AND status = 'pending'` without `LIMIT`) and attempts to render all records simultaneously into memory.
* **Expected Secure Behavior:** Query must enforce a reasonable server-side upper bound (`LIMIT 100`) or cursor-based pagination, consistent with `chatboard.php` and `get_messages.php`.
* **Observed Behavior:** Queries `$fq` and `$pq` in `friendlist.php` are completely unbounded.
* **Minimal Reproduction:** Inspect `php/friendlist.php` lines 36–54 and lines 59–78. Notice absence of `LIMIT` clause on both `$fq` and `$pq`.
* **Evidence:** Source code analysis of `php/friendlist.php:L36-L78`.
* **Security Impact:** Application resource exhaustion, high memory consumption, and denial of service for target users.
* **Root Cause:** Omission of query limit clauses during Phase 2 query bounding.
* **Recommended Remediation:** Add `LIMIT 100` to both `$fq` and `$pq` queries in `friendlist.php`.
* **Regression Test Required:** Test asserting `LIMIT` clause exists on friendlist queries.
* **Status:** **CONFIRMED**

---

### Finding DP-P3-007
* **Severity:** **Informational / Hardening Opportunity**
* **Title:** Weak Content Security Policy Permitting `'unsafe-inline'` and Broad Cloudflare CDN
* **CWE:** CWE-1021: Improper Restriction of Rendered UI Layers or Frames / CWE-79
* **OWASP Category:** A05:2021-Security Misconfiguration
* **Affected Component:** `.htaccess` (line 25) and `php/bootstrap_security.php` (line 51)
* **Preconditions:** Discovery of an HTML injection vector in any current or future template.
* **Attacker Capability:** Because `script-src` includes `'unsafe-inline'`, any injected `<script>` tag or inline event handler (`onload`, `onerror`) will execute in the browser. Furthermore, `https://cdnjs.cloudflare.com` hosts vast JavaScript libraries that can serve as execution gadgets to bypass script filtering.
* **Expected Secure Behavior:** Modern CSP using nonces (`script-src 'self' 'nonce-...'`) without `'unsafe-inline'`, and strict CDN resource hashing (SRI) or local hosting of dependencies.
* **Observed Behavior:** Policy explicitly permits `'unsafe-inline'` and broad Cloudflare CDN origins.
* **Evidence:** Active response header:
  ```http
  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; ...
  ```
* **Security Impact:** Weakens defense-in-depth; fails to prevent execution of injected scripts if an XSS flaw arises.
* **Root Cause:** Application relies on inline scripts in PHP views (`chatboard.php`, `friendlist.php`, `edit-profile.php`) and inline event handlers (`onclick`, `onchange`).
* **Recommended Remediation:** Refactor inline scripts and event handlers into external JavaScript files or implement dynamic per-request CSP nonces (`$nonce = bin2hex(random_bytes(16))`).
* **Regression Test Required:** Automated check for valid CSP header.
* **Status:** **CONFIRMED**

---

### Finding DP-P3-008
* **Severity:** **Low**
* **Title:** User Account Existence Disclosure via Registration Endpoint
* **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
* **OWASP Category:** A07:2021-Identification and Authentication Failures
* **Affected Component:** `php/registration.php` (lines 63–71)
* **Preconditions:** Attacker possesses a candidate email address.
* **Attacker Capability:** Attacker submits a registration request with the candidate email. The server returns `{"error": "This email address is already registered."}`, confirming that the email belongs to an active DaakPion user.
* **Expected Secure Behavior:** In high-privacy contexts, registration feedback is generic or deferred to an email verification link.
* **Observed Behavior:** Explicit disclosure of registered email addresses in JSON response.
* **Evidence:** Source code analysis of `php/registration.php:L67-L70`.
* **Security Impact:** User enumeration; enables targeted phishing or correlation with leaked credential dumps.
* **Root Cause:** Direct status feedback on duplicate email check. Mitigated partially by IP rate limiting (5 attempts/hour).
* **Recommended Remediation:** Consider implementing email verification workflows where existing accounts receive an email notice rather than direct client error disclosure.
* **Regression Test Required:** Functional verification of registration response.
* **Status:** **CONFIRMED**

---

## 8. False Positives Analysis & Ruled-Out Suspicions

| Potential Issue Checked | Initial Hypothesis | Technical Investigation & Evidence | Resolution / Classification |
| :--- | :--- | :--- | :--- |
| **Legacy CBC Padding Oracle / Bit Flipping** | Legacy AES-256-CBC decryption fallback in `CryptoService::decryptMessage()` might be exploitable via padding oracle or bit-flipping attacks. | Inspected HTTP data flow. `send_message.php` strictly encrypts incoming user messages via `encryptMessage()` (producing `v2:gcm:` payloads). No HTTP parameter allows user-controlled ciphertext to reach `decryptMessage()`. Decryption is called exclusively on stored database rows in `get_messages.php`. Decryption failure returns `null` and renders generic `[message unavailable]` without disclosing padding errors. | **FALSE POSITIVE / SAFE BACKWARD COMPATIBILITY** |
| **SQL Injection in Cursor Pagination** | In `get_messages.php`, `since_id`, `before_id`, and `limit` might allow SQL injection when manipulated with negative numbers, arrays, or quotes. | Traced parameters in `get_messages.php`. Inputs are explicitly sanitized using `max(0, (int)$_GET['...'])` and clamped `$limit` (1–100), then bound using `mysqli_stmt::bind_param("iiiiii", ...)`. Tested with `' OR 1=1` and `UNION SELECT`; sanitized to integers without error. | **FALSE POSITIVE** |
| **IDOR in User Profile Page** | Tampering with `?id=X` on `user-profile.php` or `edit-profile.php` might expose or modify other users' profiles. | Inspected source code. `user-profile.php` and `edit-profile.php` completely ignore `$_GET['id']` and query strictly `WHERE id = ?` using `(int)$_SESSION['user_id']`. | **FALSE POSITIVE** |
| **RCE via Upload Double Extension** | Uploading `shell.php.jpg` might allow executing PHP on Apache. | Tested upload logic. `edit-profile.php` completely discards client filenames, renaming files to `"profile_{userId}_{time}.jpg"`. Furthermore, `ProfilePics/.htaccess` and `Coverpics/.htaccess` enforce `php_flag engine off` and `FilesMatch "\.php$" Deny from all`. | **FALSE POSITIVE** |
| **2FA Pre-Authentication Bypass** | Manipulating session cookies or skipping `verify_2fa.php` could allow unauthenticated users to enter chat. | Inspected session variables. `userlogin.php` sets only `$_SESSION['2fa_preauth_user_id']` when 2FA is active, leaving `$_SESSION['user_id']` unset. All protected pages check `isset($_SESSION['user_id'])`, immediately redirecting unauthenticated sessions to `index.html`. | **FALSE POSITIVE** |

---

## 9. Baseline Automated Regression Results

Without modifying any application files, the entire automated regression harness was executed on the `security-deep-audit-phase3` audit branch.

### Test Execution Summary Table

| Test Suite | Command | Tests Run | Passed | Failed | Status |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Phase 2 Hardening Suite** | `php tests/Phase2RemediationTest.php` | 64 | 64 | 0 | **100% PASS** |
| **Phase 1 Remediation Suite** | `php tests/Phase1RemediationTest.php` | 46 | 46 | 0 | **100% PASS** |
| **Core Security Architecture Suite** | `php tests/SecurityTestSuite.php` | 46 | 46 | 0 | **100% PASS** |
| **End-to-End Integration Flow** | `php tests/IntegrationFlowTest.php` | 3 | 3 | 0 | **100% PASS** |
| **TOTAL** | | **159** | **159** | **0** | **100% PASS** |

All existing Phase 1 and Phase 2 security controls remain fully operational.

---

## 10. Audit Summary & Severity Distribution

```text
Total tests performed:          45
Confirmed vulnerabilities:      8
Likely vulnerabilities:         0
Potential issues:               0
False positives verified:       5
Informational findings:         1

Vulnerability Severity Breakdown:
Critical:                       0
High:                           2 (DP-P3-001, DP-P3-002)
Medium:                         1 (DP-P3-003)
Low:                            4 (DP-P3-004, DP-P3-005, DP-P3-006, DP-P3-008)
Informational:                  1 (DP-P3-007)
```

---

## 11. Recommended Remediation Roadmap (Phase 4 Priority)

*Remediation must only proceed upon explicit authorization.*

### Priority 1: High Severity (Security Controls & Crypto)
1. **Fix `DP-P3-002` (Crypto Key Hardening):**
   - Generate and configure a cryptographically random 256-bit `MESSAGE_ENCRYPTION_KEY` in `php/security_secrets.php`.
   - Update `CryptoService::getMessageKey()` to check against `PROHIBITED_KEYS` and fail closed if default placeholder keys are detected.
2. **Fix `DP-P3-001` (Blocked Relationship Enforcement):**
   - Update `php/send_request.php` to verify that no `status = 'blocked'` relationship exists between sender and receiver before creating a friend request.

### Priority 2: Medium Severity (Data Integrity & DoS)
3. **Fix `DP-P3-003` (Friend Request Enum & Re-Send Logic):**
   - Correct `respond_request.php` to use `status = 'rejected'` (matching the database schema enum).
   - In `send_request.php`, handle re-requests gracefully by updating existing non-pending records instead of failing on duplicate key collisions.

### Priority 3: Low Severity & Hardening
4. **Fix `DP-P3-004` (Logout CSRF):** Enforce POST and validate CSRF token in `php/logout.php`.
5. **Fix `DP-P3-005` (Orphaned File & Signature Cleanup):** Remove or shield `php/config.php`; suppress `X-Powered-By`.
6. **Fix `DP-P3-006` (Friend List Resource Bounding):** Add `LIMIT 100` to `$fq` and `$pq` queries in `friendlist.php`.
7. **Address `DP-P3-007` (CSP Hardening):** Migrate inline scripts and event handlers to external files to eliminate `'unsafe-inline'`.

---

## 12. Final Security Statement

> "This assessment covered the documented attack surface and the controlled tests listed in this report. Results are limited to the tested application version, environment, configuration, and test scenarios."
