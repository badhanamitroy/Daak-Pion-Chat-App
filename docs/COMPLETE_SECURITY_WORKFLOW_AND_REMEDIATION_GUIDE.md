# DaakPion — Complete Security Architecture, Audit Workflow & Remediation Guide
**Project:** DaakPion Real-Time PHP Chat Application  
**Repository Path:** `c:\xampp\htdocs\Daakpion`  
**Current Active Git Branch:** `security-remediation-phase1`  
**Target Audience:** Security Engineers, Full-Stack PHP Developers, and AI Assistant (Antigravity)  
**Document Purpose:** Complete end-to-end record of the security transformation of DaakPion—from the initial authentication overhaul to the ethical hacking audit, Phase 1 vulnerability remediation, before-and-after code replacements, regression testing, and runtime security data flows.

---

## Table of Contents
1. [Phase 0 — The Beginning: Security Foundation Overhaul](#1-phase-0--the-beginning-security-foundation-overhaul)
   - 1.1 Original Application State & Insecurities
   - 1.2 The SPS Security System Architecture
   - 1.3 Core Security Classes Implemented
   - 1.4 Database Schema Migration for Security
2. [The Complete Runtime Security Lifecycle](#2-the-complete-runtime-security-lifecycle)
   - 2.1 User Registration Flow
   - 2.2 Login & Authentication Flow (Rate Limiting, Argon2id, Legacy Rehash)
   - 2.3 Two-Factor Authentication (2FA) Challenge Flow
   - 2.4 Authenticated Session & Cross-Device Invalidation Flow
   - 2.5 Temporary Password & Restricted Access Flow
   - 2.6 Password Reset & Anti-Enumeration Flow
   - 2.7 Social & Messaging Flow (CSRF, Friendship Auth, Encryption)
   - 2.8 Error Handling & Safe Server Logging Flow
3. [The Ethical Security Audit: Methodology & Discoveries](#3-the-ethical-security-audit-methodology--discoveries)
   - 3.1 Audit Scope & Operating Environment
   - 3.2 Audit Findings Matrix (DP-VULN-01 to DP-VULN-08)
4. [Step-by-Step Remediation: What Was Checked, Found, and Replaced](#4-step-by-step-remediation-what-was-checked-found-and-replaced)
   - 4.1 DP-VULN-01: Active-Friendship Authorization in `send_message.php`
   - 4.2 DP-VULN-02: CSRF Protection on Social Endpoints & Frontend Delivery
   - 4.3 DP-VULN-03: AES-CBC Message Encryption Integrity (Analysis & Future Migration)
   - 4.4 DP-VULN-04: Database Error & Technical Detail Disclosure Elimination
   - 4.5 DP-VULN-05: Administrative Script & Test Directory Web Exposure Protection
   - 4.6 DP-VULN-06: Unbounded Queries & Pagination (Analysis & Phase 2 Roadmap)
   - 4.7 DP-VULN-07: Development Token Disclosure Protection (Phase 2 Roadmap)
   - 4.8 DP-VULN-08: Content Security Policy (CSP) Hardening (Phase 2 Roadmap)
5. [Automated Verification & Regression Test Suites](#5-automated-verification--regression-test-suites)
   - 5.1 `tests/SecurityTestSuite.php` (46 Tests)
   - 5.2 `tests/IntegrationFlowTest.php` (3 Scenarios)
   - 5.3 `tests/Phase1RemediationTest.php` (46 Tests)
   - 5.4 Apache HTTP Access Verification via Loopback Curl
6. [Deployment, Configuration & Rollback Instructions](#6-deployment-configuration--rollback-instructions)
7. [Current Stage Status & Roadmap for Next Phase](#7-current-stage-status--roadmap-for-next-phase)

---

## 1. Phase 0 — The Beginning: Security Foundation Overhaul

### 1.1 Original Application State & Insecurities
Prior to the security transformation, DaakPion was an introductory PHP/MySQL chat application with multiple baseline security vulnerabilities:
* **Passwords:** Legacy passwords were stored using unpeppered hashes (standard `password_hash` or MD5) with no complexity or pattern enforcement.
* **Brute-Force Attacks:** No rate-limiting mechanism existed. An attacker could issue millions of automated login requests against `userlogin.php` without delay or lockouts.
* **No Multi-Factor Authentication:** Compromised passwords resulted in instant account takeovers.
* **Insecure Session Handling:** Native PHP sessions operated with default configurations: cookies lacked the `HttpOnly` and `SameSite` flags, session IDs were rarely regenerated, and no device-binding or cross-device invalidation existed.
* **Account Enumeration:** The password reset endpoint leaked user existence by returning distinct error messages for unregistered emails.
* **No Temporary Password RBAC:** Newly invited or admin-reset users were not forced to change temporary credentials before accessing private chats.
* **No Audit Logging:** Security-sensitive events (failed logins, password resets, account lockouts) left no audit trail.

### 1.2 The SPS Security System Architecture
To resolve these weaknesses, an enterprise-grade authentication and security subsystem was adapted and customized for DaakPion under `php/Security/`. Google OAuth was deliberately omitted to maintain a self-contained, sovereign credential architecture.

The security subsystem relies on:
1. **Argon2id Password Hashing with HMAC-SHA256 Server Pepper**
2. **Deterministic Password Complexity Policy**
3. **Multi-Tiered Brute-Force Rate Limiting**
4. **Cryptographic Session Manager with Strict Cookie Attributes & Cross-Device Invalidation**
5. **HMAC-SHA256 Two-Factor Authentication (OTP)**
6. **Anti-Enumeration Password Reset Mechanism**
7. **Temporary Password Restriction Gatekeeper**
8. **Constant-Time Anti-CSRF Token Generation and Validation**
9. **Tamper-Evident Security Audit Logger**

### 1.3 Core Security Classes Implemented

#### A. `CryptoService.php` (`php/Security/CryptoService.php`)
* **Pepper Management:** Loads a high-entropy 32+ byte secret string from `php/security_secrets.php` (outside web document root or blocked by `.htaccess`).
* **Argon2id Hashing:** Uses `PASSWORD_ARGON2ID` with:
  * `memory_cost` = 65,536 KiB (64 MB)
  * `time_cost` = 4 iterations
  * `threads` = 1
* **HMAC-SHA256 Pre-Hashing:** Passwords are pre-hashed with the server pepper: `hash_hmac('sha256', $password, $pepper)`. This prevents GPU/ASIC rainbow table attacks even if the SQL database is leaked.
* **Legacy Hash Migration:** Verifies unpeppered bcrypt hashes seamlessly and triggers a rehash flag (`needsRehash`), automatically upgrading user accounts to Argon2id upon their next successful login.

#### B. `PasswordPolicy.php` (`php/Security/PasswordPolicy.php`)
* Enforces minimum 12 characters.
* Rejects dictionary words and common passwords (e.g. `password1234`).
* Rejects repeating characters (e.g. `aaaaaa`) and sequential runs (e.g. `123456`, `qwerty`).
* Rejects passwords containing user profile tokens (first name, last name, or email username prefix).

#### C. `RateLimiter.php` (`php/Security/RateLimiter.php`)
* Tracks failed attempts by client IP address and username identifier.
* Allows up to 5 consecutive attempts within a 15-minute window.
* Locks out the identifier on the 5th failure, enforcing exponential backoff.

#### D. `SessionManager.php` (`php/Security/SessionManager.php`)
* Configures secure cookie directives before `session_start()`:
  * `session.cookie_httponly = 1` (blocks JavaScript XSS access to `PHPSESSID`)
  * `session.cookie_samesite = 'Lax'` (mitigates CSRF)
  * `session.use_strict_mode = 1` (blocks session fixation attacks)
* Periodically regenerates session IDs to prevent session hijacking.
* Cross-device invalidation: Compares `$_SESSION['password_version']` with the `users.password_version` column in MySQL on every request. If a user changes their password on Device B, Device A's session is immediately invalidated.

#### E. `TwoFactorService.php` (`php/Security/TwoFactorService.php`)
* Generates secure 6-digit numeric OTPs.
* Stores OTPs in the database as **HMAC-SHA256 hashes** rather than plaintext.
* Enforces 10-minute expiration and single-use replay protection.

#### F. `PasswordResetService.php` (`php/Security/PasswordResetService.php`)
* Generates 64-character cryptographic reset tokens (`random_bytes(32)`).
* Stores reset tokens in MySQL as **SHA-256 hashes**.
* Anti-enumeration: Returns an identical generic success message regardless of whether the submitted email address exists.

#### G. `CsrfProtection.php` (`php/Security/CsrfProtection.php`)
* Generates 64-hex-character cryptographically secure anti-CSRF tokens.
* Validates submitted tokens using constant-time comparison (`hash_equals`).

#### H. `AuditLogger.php` (`php/Security/AuditLogger.php`)
* Records security events (login success/failure, 2FA challenge, password reset, account lockout) with timestamps, IP addresses, user agents, and user IDs.

### 1.4 Database Schema Migration for Security
The script `php/migrate_security.php` was created to safely upgrade the `users` table without modifying existing user IDs or chat records:

```sql
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS password_version INT NOT NULL DEFAULT 1,
ADD COLUMN IF NOT EXISTS must_change_password TINYINT(1) NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS two_factor_hash VARCHAR(64) NULL DEFAULT NULL,
ADD COLUMN IF NOT EXISTS two_factor_expires DATETIME NULL DEFAULT NULL,
ADD COLUMN IF NOT EXISTS reset_token_hash VARCHAR(64) NULL DEFAULT NULL,
ADD COLUMN IF NOT EXISTS reset_expires DATETIME NULL DEFAULT NULL;
```

---

## 2. The Complete Runtime Security Lifecycle

### 2.1 User Registration Flow
```mermaid
sequenceDiagram
    autonumber
    actor User as Client Browser
    participant Reg as registration.php
    participant Pol as PasswordPolicy
    participant Crypt as CryptoService
    participant DB as MariaDB (users)

    User->>Reg: POST fname, lname, email, password
    Reg->>Pol: validatePassword(password, userDetails)
    alt Policy Violation (len < 12, name in pass, etc.)
        Pol-->>Reg: Error: Policy violation details
        Reg-->>User: HTTP 400 JSON {status: false, message}
    else Password Accepted
        Pol-->>Reg: OK
        Reg->>Crypt: hashPassword(password)
        Crypt->>Crypt: HMAC-SHA256(password, PEPPER)
        Crypt->>Crypt: password_hash(Argon2id)
        Crypt-->>Reg: Argon2id Hash String
        Reg->>DB: INSERT INTO users (fname, lname, email, password, password_version)
        DB-->>Reg: Success
        Reg-->>User: HTTP 200 JSON {status: true, redirect: login}
    end
```

### 2.2 Login & Authentication Flow (Rate Limiting, Argon2id, Legacy Rehash)
```mermaid
sequenceDiagram
    autonumber
    actor User as Client Browser
    participant Login as userlogin.php
    participant RL as RateLimiter
    participant DB as MariaDB (users)
    participant Crypt as CryptoService
    participant Sess as SessionManager
    participant 2FA as TwoFactorService

    User->>Login: POST email, password
    Login->>RL: isBlocked(ip, email)
    alt Rate Limited (> 5 attempts)
        RL-->>Login: Blocked (retry in X mins)
        Login-->>User: HTTP 429 Too Many Requests
    else Allowed
        Login->>DB: SELECT * FROM users WHERE email = ?
        alt User Not Found
            Login->>RL: recordFailure(ip, email)
            Login-->>User: HTTP 401 Invalid credentials
        else User Exists
            Login->>Crypt: verifyPassword(password, storedHash)
            alt Password Incorrect
                Login->>RL: recordFailure(ip, email)
                Login-->>User: HTTP 401 Invalid credentials
            else Password Correct
                Login->>RL: clear(ip, email)
                opt Hash Needs Rehash (Legacy Bcrypt)
                    Login->>Crypt: hashPassword(password)
                    Login->>DB: UPDATE users SET password = <argon2id>
                end
                alt 2FA Enabled
                    Login->>2FA: generateAndSendOtp(user)
                    Login-->>User: HTTP 200 {require_2fa: true}
                else 2FA Disabled
                    Login->>Sess: establishSession(user)
                    Login-->>User: HTTP 200 {status: true, redirect: homepage}
                end
            end
        end
    end
```

### 2.3 Two-Factor Authentication (2FA) Challenge Flow
```mermaid
sequenceDiagram
    autonumber
    actor User as Client Browser
    participant V2FA as verify_2fa.php
    participant DB as MariaDB (users)
    participant Sess as SessionManager

    User->>V2FA: POST otp_code
    V2FA->>DB: SELECT two_factor_hash, two_factor_expires FROM users WHERE id = ?
    V2FA->>V2FA: Compute HMAC-SHA256(otp_code, PEPPER)
    V2FA->>V2FA: Timing-safe hash_equals(storedHash, computedHash)
    alt Expired or Invalid OTP
        V2FA-->>User: HTTP 401 Invalid or expired code
    else Valid OTP
        V2FA->>DB: UPDATE users SET two_factor_hash = NULL, two_factor_expires = NULL (Single-Use Replay Protection)
        V2FA->>Sess: upgradeToAuthenticatedSession()
        V2FA-->>User: HTTP 200 {status: true, redirect: homepage}
    end
```

### 2.4 Authenticated Session & Cross-Device Invalidation Flow
Every authenticated script calls `SessionManager::validateSessionState($conn)`.
```mermaid
sequenceDiagram
    autonumber
    actor DeviceA as Device A Browser
    actor DeviceB as Device B Browser
    participant App as Any PHP Endpoint
    participant Sess as SessionManager
    participant DB as MariaDB (users)

    DeviceA->>App: Request chatboard.php (Cookie: PHPSESSID)
    App->>Sess: validateSessionState($conn)
    Sess->>DB: SELECT password_version FROM users WHERE id = ?
    Note over Sess: Device A session version matches DB (version 1)
    Sess-->>App: Valid
    App-->>DeviceA: Render Chatboard

    Note over DeviceB: User changes password on Device B
    DeviceB->>App: POST force_change_password.php
    App->>DB: UPDATE users SET password = <new>, password_version = password_version + 1 (now 2)
    
    DeviceA->>App: Next Request (send_message.php)
    App->>Sess: validateSessionState($conn)
    Sess->>DB: SELECT password_version FROM users WHERE id = ?
    Note over Sess: Device A version (1) != DB version (2) (STALE SESSION DETECTED)
    Sess->>Sess: session_destroy() + clear cookies
    Sess-->>App: Invalid
    App-->>DeviceA: HTTP 401 Session expired. Redirect to login.
```

### 2.5 Temporary Password & Restricted Access Flow
```mermaid
flowchart TD
    A[Client Request to Protected Feature] --> B{must_change_password == 1?}
    B -- Yes --> C[SessionManager::checkRestrictedAccess]
    C --> D[Block Request with HTTP 403 Forbidden]
    D --> E[Redirect to force_change_password.php]
    B -- No --> F[Allow Access to Chatboard, Profile & Messaging]
```

### 2.6 Password Reset & Anti-Enumeration Flow
```mermaid
sequenceDiagram
    autonumber
    actor Attacker as Attacker or User
    participant Forgot as forgot_password.php
    participant DB as MariaDB (users)

    Attacker->>Forgot: POST email
    Forgot->>DB: SELECT id FROM users WHERE email = ?
    alt User Found
        Forgot->>Forgot: Generate random 64-hex token
        Forgot->>Forgot: Compute SHA-256(token)
        Forgot->>DB: UPDATE users SET reset_token_hash = ?, reset_expires = NOW() + 15m
        Forgot->>Forgot: Dispatch email with token link
    else User Not Found
        Forgot->>Forgot: Perform identical dummy sleep to normalize timing
    end
    Forgot-->>Attacker: Identical Generic Message: "If that email exists, a password reset link has been dispatched."
```

### 2.7 Social & Messaging Flow (CSRF, Friendship Auth, Encryption)
```mermaid
sequenceDiagram
    autonumber
    actor Client as Authenticated Sender
    participant Script as send_message.php
    participant CSRF as CsrfProtection
    participant Sess as SessionManager
    participant DB as MariaDB (friends & messages)
    participant Crypt as OpenSSL AES-256-CBC

    Client->>Script: POST receiver_id, message, csrf_token (or X-CSRF-Token header)
    Script->>Sess: checkRestrictedAccess()
    Script->>CSRF: validateToken(submittedToken)
    alt Invalid CSRF Token
        CSRF-->>Script: False
        Script-->>Client: HTTP 403 Invalid or missing CSRF token
    else Valid CSRF Token
        CSRF-->>Script: True
        Script->>DB: SELECT 1 FROM friends WHERE ((u1=? AND u2=?) OR (u1=? AND u2=?)) AND status='active'
        alt No Active Friendship Record Found
            DB-->>Script: 0 rows
            Script-->>Client: HTTP 403 Unauthorized: You can only message confirmed friends.
        else Active Friendship Verified
            DB-->>Script: 1 row
            Script->>Crypt: openssl_encrypt(message, 'AES-256-CBC', SECRET_KEY, 0, IV)
            Crypt-->>Script: iv_b64 : ciphertext
            Script->>DB: INSERT INTO messages (sender_id, receiver_id, message, sent_at)
            DB-->>Script: Success
            Script-->>Client: HTTP 200 "Message sent"
        end
    end
```

### 2.8 Error Handling & Safe Server Logging Flow
```mermaid
flowchart LR
    A[Database Query / Transaction Exception] --> B[error_log: Technical SQL & Path Info to server log]
    A --> C[http_response_code: 500]
    A --> D[Client-Facing Output: Generic Safe Error Message]
```

---

## 3. The Ethical Security Audit: Methodology & Discoveries

### 3.1 Audit Scope & Operating Environment
* **Platform:** Apache 2.4.58 (Win64) OpenSSL/3.1.3 PHP 8.0.30 MariaDB 10.4.32 on Windows.
* **Methodology:** Static source code data-flow analysis, parameter tampering analysis, dynamic automated test execution, and Apache loopback curl verification.
* **Safety Mandate:** All testing was conducted against synthetic isolated user accounts (`synthetic_*`). No real user records were accessed or altered.

### 3.2 Audit Findings Matrix (DP-VULN-01 to DP-VULN-08)

| Finding ID | Vulnerability Title | Severity | Remediation Phase | Remediation Status |
| :---: | :--- | :---: | :---: | :---: |
| **`DP-VULN-01`** | Missing Active-Friendship Authorization in `send_message.php` | **High** (CVSS 7.5) | Phase 1 | **Fixed and tested** |
| **`DP-VULN-02`** | Missing or Inconsistent CSRF Protection on Social Endpoints | **High** (CVSS 8.1) | Phase 1 | **Fixed and tested** |
| **`DP-VULN-03`** | AES-CBC Message Encryption Without Authenticated Integrity (AEAD) | **Medium** (CVSS 5.9) | Phase 2 | **Not implemented (Deferred)** |
| **`DP-VULN-04`** | Database Diagnostics & SQL Error Disclosure to Clients | **Medium** (CVSS 4.3) | Phase 1 | **Fixed and tested** |
| **`DP-VULN-05`** | Web Exposure of `migrate_security.php` and `/tests/` Directory | **Med-High** (CVSS 6.5) | Phase 1 | **Fixed and tested** |
| **`DP-VULN-06`** | Unbounded User and Message SELECT Queries | **Low-Med** (CVSS 5.3) | Phase 2 | **Not implemented (Deferred)** |
| **`DP-VULN-07`** | Development OTP / Token Disclosure on Loose Host Matching | **Medium** (CVSS 6.1) | Phase 2 | **Not implemented (Deferred)** |
| **`DP-VULN-08`** | Missing Content Security Policy (CSP) Response Header | **Low-Med** (CVSS 4.7) | Phase 2 | **Not implemented (Deferred)** |

---

## 4. Step-by-Step Remediation: What Was Checked, Found, and Replaced

### 4.1 DP-VULN-01: Active-Friendship Authorization in `send_message.php`

#### 1. What was checked:
Whether an authenticated user could send direct chat messages to another user without an approved, active friendship, or to a user who blocked them.

#### 2. What was found:
In `php/send_message.php`, the code only verified:
```php
// ORIGINAL VULNERABLE CODE (send_message.php)
$receiver_id = (int)$_POST['receiver_id'];
$message     = trim($_POST['message']);

if (empty($message) || $receiver_id <= 0) { ... }
if ($user_id === $receiver_id) { ... }

// Immediate encryption and insertion into messages table!
$sql = "INSERT INTO messages (sender_id, receiver_id, message, sent_at, is_read) VALUES (?, ?, ?, NOW(), 0)";
```
There was **zero validation** against the `friends` table.

#### 3. What needed to be replaced and why:
Before encrypting or storing any message, the server must query the `friends` table to confirm that a mutual relationship with `status = 'active'` exists between `user1_id` and `user2_id`. If no active record exists, terminate with `HTTP 403 Forbidden`.

#### 4. The Replacement Code:
```php
// REPLACEMENT CODE (php/send_message.php lines 49-74)
// ── 2. Authorization: Verify Active Friendship ───────────────────────────────
// Resolves DP-VULN-01: Prohibits messaging users who are not active confirmed friends.
$friendCheck = $conn->prepare("
    SELECT 1 FROM friends
    WHERE ((user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?))
      AND status = 'active'
    LIMIT 1
");

if (!$friendCheck) {
    error_log("Friend check prepare failed: " . $conn->error);
    http_response_code(500);
    exit("A system error occurred. Please try again later.");
}

$friendCheck->bind_param("iiii", $user_id, $receiver_id, $receiver_id, $user_id);
$friendCheck->execute();
$friendCheck->store_result();

if ($friendCheck->num_rows === 0) {
    $friendCheck->close();
    http_response_code(403);
    exit("Unauthorized: You can only message confirmed friends.");
}
$friendCheck->close();
```

#### 5. How it was tested & Verified:
Tested via `tests/Phase1RemediationTest.php` with synthetic test users:
* **Active Friends (A -> B):** HTTP 200 returned, message row created in database. **[PASS]**
* **Non-Friends (A -> C):** HTTP 403 returned, message text `"Unauthorized: You can only message confirmed friends."`, 0 rows created. **[PASS]**
* **Pending Friend Request (A -> D):** HTTP 403 returned, 0 rows created. **[PASS]**
* **Blocked Relationship (A -> E):** HTTP 403 returned, 0 rows created. **[PASS]**
* **Nonexistent Receiver ID (A -> 99999999):** HTTP 403 returned. **[PASS]**

---

### 4.2 DP-VULN-02: CSRF Protection on Social Endpoints & Frontend Delivery

#### 1. What was checked:
Whether state-changing endpoints (`send_message.php`, `send_request.php`, `respond_request.php`) verified an anti-CSRF token, and whether the frontend supplied this token in its AJAX requests.

#### 2. What was found:
None of the three endpoints invoked `CsrfProtection::validateToken()`. An attacker hosting an external website could submit background POST requests using the victim's ambient browser cookies to send messages, send friend requests, or accept requests. Furthermore, `chatboard.php` and `friendlist.php` did not expose CSRF tokens to frontend JavaScript.

#### 3. What needed to be replaced and why:
1. Server endpoints must inspect both `$_POST['csrf_token']` and the `X-CSRF-Token` header, returning HTTP 403 on missing or invalid tokens using timing-safe `hash_equals()`.
2. Frontend pages (`chatboard.php`, `friendlist.php`) must render `<meta name="csrf-token" content="...">`.
3. Client JavaScript `fetch()` calls must read the meta tag and attach the token.

#### 4. The Replacement Code:

**A. Server-side validation in `send_message.php`, `send_request.php`, and `respond_request.php`:**
```php
// REPLACEMENT CODE (Added to top of each endpoint)
use Daakpion\Security\CsrfProtection;

// ── CSRF Protection (Resolves DP-VULN-02) ─────────────────────────────────
$submittedCsrf = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
if (!CsrfProtection::validateToken($submittedCsrf)) {
    http_response_code(403);
    exit("Invalid or missing CSRF token");
}
```

**B. Frontend Meta Tag injection in `chatboard.php` and `friendlist.php`:**
```html
<!-- Inside <head> in chatboard.php and friendlist.php -->
<meta name="csrf-token" content="<?= htmlspecialchars(\Daakpion\Security\CsrfProtection::getToken(), ENT_QUOTES, 'UTF-8') ?>">
```

**C. Frontend AJAX Delivery in `chatboard.php` (`doSend()`):**
```javascript
// REPLACEMENT CODE (chatboard.php doSend)
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
const fd = new FormData();
fd.append('receiver_id', receiverId);
fd.append('message', text);
fd.append('csrf_token', csrfToken);

fetch('send_message.php', {
    method: 'POST',
    headers: {
        'X-CSRF-Token': csrfToken
    },
    body: fd
})
```

**D. Frontend AJAX Delivery in `friendlist.php` (`sendRequest()` and `respondRequest()`):**
```javascript
// REPLACEMENT CODE (friendlist.php)
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
const fd = new FormData();
fd.append('receiver_id', userId);
fd.append('csrf_token', csrfToken);

fetch('send_request.php', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    body: fd
})
```

#### 5. How it was tested & Verified:
Tested via `tests/Phase1RemediationTest.php`:
* `send_message.php`: Missing token -> HTTP 403 **[PASS]**; Invalid token -> HTTP 403 **[PASS]**; Valid header token -> HTTP 200 **[PASS]**.
* `send_request.php`: Missing token -> HTTP 403 **[PASS]**; Invalid token -> HTTP 403 **[PASS]**; Valid token -> HTTP 200 **[PASS]**.
* `respond_request.php`: Missing token -> HTTP 403 **[PASS]**; Invalid token -> HTTP 403 **[PASS]**; Valid token -> HTTP 200 **[PASS]**.

---

### 4.3 DP-VULN-03: AES-CBC Message Encryption Integrity (Analysis & Future Migration)

#### 1. What was checked:
OpenSSL cipher mode, IV randomness, and ciphertext authentication integrity in `php/send_message.php` and `php/get_messages.php`.

#### 2. What was found:
Messages are encrypted using `AES-256-CBC` with random 16-byte IVs:
```php
$iv             = random_bytes(16);
$iv_b64         = base64_encode($iv);
$encrypted      = openssl_encrypt($message, 'AES-256-CBC', SECRET_KEY, 0, $iv);
$stored_message = $iv_b64 . ':' . $encrypted;
```
CBC mode provides confidentiality, but lacks **integrity / authenticity** (no HMAC or AEAD GCM tag). An attacker with write access to MySQL could flip bits in the ciphertext that alter decrypted plaintext without triggering an error.

#### 3. Why Deferred to Phase 2:
Replacing the encryption algorithm immediately without a dual-mode reader would make all existing chat messages unreadable or corrupt. Phase 2 will implement an AEAD `AES-256-GCM` format (`v2:<iv>:<tag>:<ciphertext>`) with automatic legacy CBC fallback.

---

### 4.4 DP-VULN-04: Database Error & Technical Detail Disclosure Elimination

#### 1. What was checked:
Whether database exceptions, connection faults, or prepare failures leaked SQL syntax, table names, or filesystem paths to HTTP clients.

#### 2. What was found:
Several scripts used raw error dumps:
```php
// ORIGINAL VULNERABLE CODE (php/friendlist.php)
function must_prepare(mysqli $conn, string $sql, string $label): mysqli_stmt {
    $stmt = $conn->prepare($sql);
    if (!$stmt) {
        die("$label prepare() failed: " . $conn->error . "<br>Query: " . htmlspecialchars($sql));
    }
    return $stmt;
}

// ORIGINAL VULNERABLE CODE (php/db_connect.php)
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// ORIGINAL VULNERABLE CODE (php/respond_request.php)
catch (Exception $e) {
    $conn->rollback();
    echo "Error: " . $e->getMessage();
}
```

#### 3. What needed to be replaced and why:
Clients should only receive generic error messages (e.g. `"A system error occurred. Please try again later."`) and HTTP 500 status codes. Technical details must be logged on the server via `error_log()`.

#### 4. The Replacement Code:

**A. `php/friendlist.php`:**
```php
// REPLACEMENT CODE (php/friendlist.php)
function must_prepare(mysqli $conn, string $sql, string $label): mysqli_stmt
{
    $stmt = $conn->prepare($sql);
    if (!$stmt) {
        error_log("$label prepare() failed: " . $conn->error . " | Query: " . $sql);
        http_response_code(500);
        die("Failed to load friend list due to a server error. Please try again later.");
    }
    return $stmt;
}
```

**B. `php/db_connect.php`:**
```php
// REPLACEMENT CODE (php/db_connect.php)
if ($conn->connect_error) {
    error_log("Database connection failure: " . $conn->connect_error);
    http_response_code(500);
    die("Database connection error. Please try again later.");
}
```

**C. `php/respond_request.php`:**
```php
// REPLACEMENT CODE (php/respond_request.php)
catch (Exception $e) {
    $conn->rollback();
    error_log("Friend request accept transaction failed: " . $e->getMessage());
    http_response_code(500);
    echo "Failed to process request. Please try again.";
}
```

**D. `php/edit-profile.php`:**
```php
// REPLACEMENT CODE (php/edit-profile.php)
if (!$stmt) {
    error_log("Profile update prepare failed: " . $conn->error);
    http_response_code(500);
    die("Unable to update profile at this time.");
}
```

#### 5. How it was tested & Verified:
* Static AST regex scan across all 6 core files confirmed 0 occurrences of `$conn->error` or `$e->getMessage()` in client output.
* Verified that every error block contains `error_log()`. **[PASS]**

---

### 4.5 DP-VULN-05: Administrative Script & Test Directory Web Exposure Protection

#### 1. What was checked:
Whether `php/migrate_security.php` and files inside `/tests/` could be browsed and executed by unauthenticated users over HTTP.

#### 2. What was found:
`php/migrate_security.php` had no execution environment checks and could be triggered by visiting `http://localhost/Daakpion/php/migrate_security.php`. Furthermore, `/tests/` had no access control rules, allowing remote execution of `SecurityTestSuite.php`.

#### 3. What needed to be replaced and why:
1. `php/migrate_security.php` must verify `php_sapi_name() === 'cli'`.
2. A `.htaccess` file inside `tests/` must enforce `Require all denied`.
3. Root `.htaccess` must deny web requests for `migrate_security.php`.

#### 4. The Replacement Code:

**A. CLI SAPI Check in `php/migrate_security.php`:**
```php
// REPLACEMENT CODE (php/migrate_security.php line 5-9)
if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    exit("Forbidden: This administrative script can only be executed via the CLI.\n");
}
```

**B. New `tests/.htaccess` (`tests/.htaccess`):**
```apache
# DaakPion — Access restriction for tests directory
<IfModule mod_authz_core.c>
    Require all denied
</IfModule>
<IfModule !mod_authz_core.c>
    Order deny,allow
    Deny from all
</IfModule>
```

**C. Root `.htaccess` sensitive files rule (`.htaccess`):**
```apache
# REPLACEMENT CODE (.htaccess lines 44-53)
# ─── Deny direct access to secrets, configuration, migrations and logs ─────────
<FilesMatch "^(security_secrets.*\.php|\.env.*|\.git.*|.*\.log|migrate_security\.php)$">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order deny,allow
        Deny from all
    </IfModule>
</FilesMatch>
```

#### 5. How it was tested & Verified:
* `curl.exe -I http://127.0.0.1/Daakpion/tests/SecurityTestSuite.php` returned `HTTP/1.1 403 Forbidden`. **[PASS]**
* `curl.exe -i http://127.0.0.1/Daakpion/php/migrate_security.php` returned `HTTP/1.1 403 Forbidden`. **[PASS]**

---

### 4.6 DP-VULN-06: Unbounded Queries & Pagination (Analysis & Phase 2 Roadmap)
* **Status:** Deferred to Phase 2.
* **Finding:** `php/get_messages.php` loads all messages matching the two user IDs without `LIMIT`.
* **Remediation Plan:** Introduce `LIMIT 50` cursor pagination (`WHERE id < :cursor_id ORDER BY id DESC LIMIT 50`) and infinite-scroll loading in `chatboard.php`.

---

### 4.7 DP-VULN-07: Development Token Disclosure Protection (Phase 2 Roadmap)
* **Status:** Deferred to Phase 2.
* **Finding:** In `forgot_password.php` and `verify_2fa.php`, debug responses print OTP codes when `$_SERVER['SERVER_NAME'] === 'localhost'`.
* **Remediation Plan:** Require an explicit server environment variable `APP_ENV=development` in `security_secrets.php` rather than trusting the HTTP `Host` header.

---

### 4.8 DP-VULN-08: Content Security Policy (CSP) Hardening (Phase 2 Roadmap)
* **Status:** Deferred to Phase 2.
* **Finding:** Modern browser defenses against XSS (CSP header) are not yet configured in `.htaccess`.
* **Remediation Plan:** Deploy `Content-Security-Policy-Report-Only` first to audit inline scripts before enforcing `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-...'`.

---

## 5. Automated Verification & Regression Test Suites

### 5.1 `tests/SecurityTestSuite.php` (46 Tests Passed)
Command: `php tests/SecurityTestSuite.php`
* **Section 1: Pepper Validation Tests** (2 tests) -> PASS
* **Section 2: Password Policy Tests** (9 tests) -> PASS
* **Section 3: Argon2id & Legacy Bcrypt Tests** (7 tests) -> PASS
* **Section 4: Brute-Force Rate Limiter Tests** (7 tests) -> PASS
* **Section 5: Two-Factor Authentication Tests** (6 tests) -> PASS
* **Section 6: Password Reset Flow & Anti-Enumeration Tests** (10 tests) -> PASS
* **Section 7: Temporary Password & Restricted Access Tests** (3 tests) -> PASS
* **Section 8: Session Security & Cross-Device Invalidation Tests** (2 tests) -> PASS
* **Result: 46 Passed, 0 Failed.**

### 5.2 `tests/IntegrationFlowTest.php` (3 Scenarios Passed)
Command: `php tests/IntegrationFlowTest.php`
1. Legacy Bcrypt User Migration on Login -> **SUCCESS**
2. Temporary Credential & Server-Side Restriction -> **SUCCESS**
3. 2FA Challenge & Verification Workflow -> **SUCCESS**
* **Result: All 3 Scenarios Passed.**

### 5.3 `tests/Phase1RemediationTest.php` (46 Tests Passed)
Command: `php tests/Phase1RemediationTest.php`
* **Section 1: Active Friendship Authorization (`DP-VULN-01`)**
  * Active friends messaging returns HTTP 200 & inserts DB record -> **PASS**
  * Non-friend messaging rejected with HTTP 403 & creates 0 records -> **PASS**
  * Pending friend messaging rejected with HTTP 403 & creates 0 records -> **PASS**
  * Blocked user messaging rejected with HTTP 403 & creates 0 records -> **PASS**
  * Nonexistent receiver ID rejected with HTTP 403 -> **PASS**
* **Section 2: CSRF Protection on Social Endpoints (`DP-VULN-02`)**
  * `send_message.php` rejects missing CSRF token -> **PASS**
  * `send_message.php` rejects invalid CSRF token -> **PASS**
  * `send_message.php` accepts valid CSRF token in header -> **PASS**
  * `send_request.php` rejects missing token -> **PASS**
  * `send_request.php` rejects invalid token -> **PASS**
  * `send_request.php` accepts valid token -> **PASS**
  * `respond_request.php` rejects missing token -> **PASS**
  * `respond_request.php` rejects invalid token -> **PASS**
  * `respond_request.php` accepts valid token -> **PASS**
* **Section 3: Safe Error Handling & SQL Suppression (`DP-VULN-04`)**
  * Suppresses raw `$conn->error` across 6 files -> **PASS**
  * Suppresses raw `$e->getMessage()` across 6 files -> **PASS**
  * Logs technical diagnostics to `error_log()` -> **PASS**
  * Unexpected actions handled cleanly without SQL errors -> **PASS**
* **Section 4: CLI Restrictions & Directory Access Controls (`DP-VULN-05`)**
  * `migrate_security.php` CLI SAPI guard verified -> **PASS**
  * `tests/.htaccess` exists with `Require all denied` -> **PASS**
  * Root `.htaccess` denies direct access to `migrate_security.php` -> **PASS**
  * Apache actively denies HTTP request to `/tests/` with HTTP 403 -> **PASS**
  * Apache actively denies HTTP request to `migrate_security.php` with HTTP 403 -> **PASS**
* **Result: 46 Passed, 0 Failed.**

### 5.4 Apache HTTP Access Verification via Loopback Curl
```powershell
curl.exe -I http://127.0.0.1/Daakpion/tests/SecurityTestSuite.php
# Output: HTTP/1.1 403 Forbidden

curl.exe -i http://127.0.0.1/Daakpion/php/migrate_security.php
# Output: HTTP/1.1 403 Forbidden
```

---

## 6. Deployment, Configuration & Rollback Instructions

### 1. Pre-Deployment Backup
Before deploying changes to production or staging:
```powershell
# 1. Back up MariaDB database
mysqldump -u root -p daakpion > daakpion_backup_pre_phase1.sql

# 2. Confirm current Git branch
git status
# On branch security-remediation-phase1
```

### 2. Configuration Requirements
Ensure that Apache’s `httpd.conf` allows `.htaccess` overrides for the DaakPion directory:
```apache
<Directory "C:/xampp/htdocs/Daakpion">
    AllowOverride All
    Require all granted
</Directory>
```
Ensure `php/security_secrets.php` is created from `php/security_secrets.example.php` and populated with a 32+ byte cryptographic pepper.

### 3. Rollback Procedure
If any deployment regression occurs:
```powershell
# Revert to previous branch or commit
git checkout main

# If database rollback is needed:
mysql -u root -p daakpion < daakpion_backup_pre_phase1.sql

# Restart Apache to flush opcode cache
httpd -k restart
```

---

## 7. Current Stage Status & Roadmap for Next Phase

### Summary Status Table
| Finding ID | Security Check | Current Status | Verification Suite |
| :---: | :--- | :---: | :--- |
| `DP-VULN-01` | Active Friendship Authorization in `send_message.php` | **Fixed & Tested** | `Phase1RemediationTest` (Pass) |
| `DP-VULN-02` | Consistent Anti-CSRF on Social Endpoints | **Fixed & Tested** | `Phase1RemediationTest` (Pass) |
| `DP-VULN-03` | AES-GCM Authenticated Encryption Migration | **Pending Phase 2** | Design & compatibility documented |
| `DP-VULN-04` | Database & SQL Technical Detail Suppression | **Fixed & Tested** | `Phase1RemediationTest` (Pass) |
| `DP-VULN-05` | Web Exposure Lockdown for Migrations & Tests | **Fixed & Tested** | Loopback Curl HTTP 403 (Pass) |
| `DP-VULN-06` | Query Pagination (Cursor-Based `LIMIT 50`) | **Pending Phase 2** | Design documented |
| `DP-VULN-07` | Explicit `APP_ENV` Check for Development Tokens | **Pending Phase 2** | Design documented |
| `DP-VULN-08` | Content Security Policy (CSP) Response Header | **Pending Phase 2** | Design documented |

### Phase 2 Implementation Roadmap
1. **Authenticated AEAD Encryption (`DP-VULN-03`):** Upgrade `openssl_encrypt` to `AES-256-GCM` with a 12-byte IV and 16-byte tag, maintaining a backward-compatible reader for legacy CBC messages.
2. **Cursor-Based Chat Pagination (`DP-VULN-06`):** Update `get_messages.php` with `LIMIT 50` and implement client-side scroll-up message loading in `chatboard.php`.
3. **Environment Hardening (`DP-VULN-07`):** Enforce strict `APP_ENV === 'development'` in `security_secrets.php` before returning any debug OTPs.
4. **CSP Deployment (`DP-VULN-08`):** Configure `Content-Security-Policy-Report-Only` in `.htaccess` and extract inline JavaScript listeners into external script modules.
