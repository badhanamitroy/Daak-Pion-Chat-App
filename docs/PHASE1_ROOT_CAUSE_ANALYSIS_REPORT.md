# Phase 1: Audit and Root-Cause Analysis Report
**Application:** DaakPion Real-Time Chat App  
**Target:** Login Responsiveness (Issue 1) and Persistent Authentication (Issue 2)  
**Date:** 2026-10-04  

---

## 1. Complete Login and Authentication Flow

### Existing Flow
1. **User Input:** User enters email and password into `index.html` form `#loginForm`.
2. **Event Capture:** `index.html` JavaScript catches `submit` event, calls `e.preventDefault()`, sets button text to `"Logging in…"`, and sets `loginBtn.disabled = true`.
3. **HTTP Fetch:** Asynchronous `fetch('php/userlogin.php', { method: 'POST', body: formData, headers: { 'Accept': 'application/json' } })` is dispatched.
4. **Backend Processing (`php/userlogin.php`):**
   - Resolves `$isAjax = true`.
   - Enforces rate limiting on IP and email dimensions via `RateLimiter`.
   - Validates email syntax and retrieves user row from `users` table via prepared statement.
   - Verifies Argon2id password hash using `CryptoService::verifyPassword()`. Migrates legacy bcrypt hashes if necessary.
   - Generates 6-digit OTP using `TwoFactorService->issueOtp()`.
   - Stores pre-authentication state in session: `$_SESSION['2fa_preauth_user_id']`, `$_SESSION['2fa_preauth_email']`.
   - Dispatches SMTP email synchronously using `MailService->sendTwoFactorOtp()`.
   - Responds with JSON: `{"success": true, "message": "Two-factor verification required.", "redirect": "verify_2fa.php"}`.
5. **Frontend Handling:**
   - `res.json()` parses response.
   - `window.location.href` redirects to `php/verify_2fa.php`.
   - If an error/exception occurs in `fetch()` or `res.json()`, `catch (err)` runs `loginForm.submit()`, causing an unmanaged secondary form submission.
6. **Two-Factor Challenge (`php/verify_2fa.php`):**
   - User inputs 6-digit OTP.
   - `verify_2fa.php` verifies OTP hash and expiration.
   - Upon success, calls `SessionManager::loginUser($user)` and redirects to `chatboard.php`.
7. **Session Termination (`php/logout.php`):**
   - Validates POST method and CSRF token.
   - Calls `SessionManager::destroySession($conn)` which deletes session data and sets session cookie to past timestamp.
   - Redirects to `index.html`.

---

## 2. Exact Files, Functions, and Database Components Involved

| Component | Files Involved | Functions / Methods / Endpoints |
|---|---|---|
| **Frontend UI & Event Handling** | `index.html`, `homepage.css`, `seepassword.js` | `#loginForm` event listener, `fetch('php/userlogin.php')`, `#login-btn` DOM state |
| **Authentication Controller** | `php/userlogin.php` | `respond()`, `CryptoService::verifyPassword()`, `TwoFactorService::issueOtp()`, `RateLimiter::isBlocked()` |
| **Two-Factor Authentication** | `php/verify_2fa.php`, `php/Security/TwoFactorService.php` | `TwoFactorService::verifyOtp()`, `MailService::sendTwoFactorOtp()` |
| **Session & Lifecycle** | `php/bootstrap_security.php`, `php/Security/SessionManager.php` | `SessionManager::startSecureSession()`, `SessionManager::loginUser()`, `SessionManager::validateSessionState()`, `SessionManager::destroySession()` |
| **Logout Handler** | `php/logout.php` | `CsrfProtection::validateToken()`, `SessionManager::destroySession()` |
| **Destination Pages** | `php/user-profile.php`, `php/chatboard.php` | `SessionManager::checkRestrictedAccess()`, session guard check `isset($_SESSION['user_id'])` |
| **Database Tables** | MySQL `daakpion` database | `users`, `two_factor_otps`, `security_rate_limits`, `security_audit_logs` |

---

## 3. Root Cause Analysis — Issue 1: Login Requires Clicking More Than Once

### Code-Level Evidence
1. **Unsafe Fallback `loginForm.submit()` in Catch Block (`index.html:122–125`):**
   ```javascript
   } catch (err) {
       // If JSON parse or network fails, fallback to traditional submit
       loginForm.submit();
   }
   ```
   When the asynchronous fetch encounters any network hiccup, connection delay, or abort, the script enters `catch (err)`. Instead of reporting an error and restoring the button state, it calls `loginForm.submit()`. This causes an uncoordinated secondary full-page form submission while the button is still in a disabled `"Logging in…"` state.
2. **Synchronous Blocking Network Operation During Login (`php/userlogin.php:154`):**
   `$mailService->sendTwoFactorOtp()` connects synchronously to Gmail SMTP (`smtp.gmail.com:587`) with TLS handshake and authentication. In standard conditions, this network connection consumes 6 to 10+ seconds. Because `fetch()` has no timeout signal (`AbortController`), the browser request remains pending for up to 10+ seconds. The user perceives the page as hung with the button displaying `"Logging in…"`.
3. **Absence of UI Timeout, Loading State Reset, and Debounce Guard (`index.html:96–126`):**
   - There is no timeout threshold on `fetch()`.
   - If an error occurs, `loginBtn.disabled` is not reset to `false`, and `loginBtn.textContent` is not restored to `"Log In"`.
   - Rapid double-clicks are not protected by an explicit in-flight state guard (`isSubmitting`).
4. **Deleted Non-2FA Fast Path in Working Tree (`php/userlogin.php:142–161`):**
   The uncommitted working tree modifications made 2FA unconditional for all accounts, removing the direct login path (`SessionManager::loginUser`) and forcing every login through external SMTP dispatch even when not applicable.

---

## 4. Root Cause Analysis — Issue 2: Authentication Lost After Closing Browser

### Code-Level Evidence
1. **Browser-Session-Only Cookie Lifetime (`php/Security/SessionManager.php:34–41`):**
   ```php
   session_set_cookie_params([
       'lifetime' => 0, // Until browser closes
       'path'     => '/',
       'domain'   => '',
       'secure'   => $isSecure,
       'httponly' => true,
       'samesite' => 'Lax',
   ]);
   ```
   The PHP session cookie (`PHPSESSID`) is configured with `'lifetime' => 0`. Under RFC 6265, browsers discard session cookies when the browser window or application process is closed.
2. **Complete Absence of Persistent Credential Mechanism:**
   - The database contains no table to store persistent login tokens.
   - `bootstrap_security.php` checks only `isset($_SESSION['user_id'])`. When the browser restarts, `PHPSESSID` is missing and `$_SESSION` is empty.
   - There is no selector/validator token resolution to securely re-authenticate the user without prompting for credentials and OTP.
   - `index.html` has no persistent session check and presents the blank login form to already-authenticated returning users.

---

## 5. Security & Architectural Considerations

1. **Token Security:** Persistent credentials must never store raw session IDs, passwords, or plain OTPs. We will use the cryptographically secure **Selector + Validator** architecture:
   - `selector`: 16 random bytes (hex-encoded, 32 chars) — indexed lookup key.
   - `validator`: 32 random bytes (hex-encoded, 64 chars) — authenticating secret.
   - Database stores `hash('sha256', $validator)` — preventing token exposure in event of a database read leak.
2. **Cookie Security Attributes:**
   - `HttpOnly`: true (mitigates XSS token theft).
   - `Secure`: true over HTTPS.
   - `SameSite`: `'Lax'` (CSRF defense).
   - Lifetime: 30 days (`2592000` seconds).
3. **Session Fixation & Token Rotation:**
   - Restoring a persistent login must regenerate the PHP session ID (`session_regenerate_id(true)`).
   - Upon each restoration, the validator must be rotated (generate new validator, store new hash, issue fresh cookie).
4. **Explicit Logout Revocation:**
   - `logout.php` must delete the persistent token from the database and wipe the cookie.
5. **Account Status Verification:**
   - Restoring a persistent login must verify that the user account still exists, is not disabled/restricted, and matches `password_version`.

---

## 6. Proposed Solutions

1. **Issue 1 Fix (Frontend & Backend Login Responsiveness):**
   - **Frontend (`index.html`):**
     - Add `isSubmitting` flag to block duplicate clicks.
     - Implement `AbortController` with an 8-second timeout.
     - Remove the unsafe `loginForm.submit()` fallback in `catch (err)`.
     - Properly display error messages and always reset the button state (`disabled = false`, text = `"Log In"`) on failure or timeout.
     - Automatically redirect to `php/user-profile.php` upon successful authentication.
     - Add a "Remember me on this device" checkbox.
     - Check for existing authentication or valid persistent token on `index.html` and redirect to `php/user-profile.php` immediately.
   - **Backend (`php/userlogin.php` & `php/verify_2fa.php`):**
     - Restore proper conditional 2FA: if `two_factor_enabled` is 0/empty, directly authenticate user via `SessionManager::loginUser()` and redirect to `user-profile.php`.
     - When authentication completes, establish persistent login credential if remember-me was requested.
     - Update post-login redirects from `chatboard.php` to `user-profile.php` as required.
2. **Issue 2 Fix (Secure Persistent Authentication):**
   - **Database Migration:** Create `persistent_logins` table with `user_id`, `selector`, `validator_hash`, `expires_at`, `ip_address`, `user_agent`.
   - **New Service (`php/Security/PersistentAuthService.php`):**
     - `createToken(int $userId, bool $rememberMe = true)`: Generates selector and validator, saves SHA-256 hash in DB, sets secure cookie.
     - `validateAndRestore(mysqli $db)`: Reads cookie, verifies selector/validator hash, checks account status, calls `SessionManager::loginUser()`, regenerates session ID, rotates validator, and logs audit event.
     - `revokeToken(mysqli $db)`: Invalidates the token in DB and clears the cookie.
     - `revokeAllForUser(int $userId, mysqli $db)`: Revokes all persistent tokens on password change or security events.
   - **Integration in `php/bootstrap_security.php`:**
     - If `!isset($_SESSION['user_id'])`, attempt `PersistentAuthService::validateAndRestore($conn)`.
   - **Integration in `php/logout.php`:**
     - Call `PersistentAuthService::revokeToken($conn)` on explicit logout.
