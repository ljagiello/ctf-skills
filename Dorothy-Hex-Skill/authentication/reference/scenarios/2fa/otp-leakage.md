# 2FA — OTP Leakage Through Side Channels

## When this applies

- The OTP code is exposed in places it shouldn't be: HTTP responses, logs, headers, error messages, URL parameters.
- The Referer header leaks OTPs from URL parameters to third-party sites.
- Server logs contain the code (debug logging).

## Technique

OTPs are supposed to be ephemeral and only known to the legitimate user. Any path where the OTP appears outside the user's intended channel (email, SMS, authenticator) is a leak. Find these and you bypass 2FA without ever guessing.

## Steps

### 1. Response body leakage

Some apps echo the OTP in the response (debug feature accidentally left enabled):

```python
r = requests.post('https://target.com/request-otp', json={'username':'test'})
print(r.text)
# Look for 6-digit code pattern
import re
match = re.search(r'\b\d{6}\b', r.text)
if match:
    print(f"[!] OTP leaked in response: {match.group()}")
```

### 2. Response header leakage

```python
print(r.headers)
# Custom headers like X-OTP, X-Verification-Code, X-Debug
```

### 3. Cookie leakage

```python
print(r.cookies)
# Some apps set the OTP as a cookie for client-side validation (very bad)
```

### 4. JavaScript bundle leakage

Modern SPAs sometimes include OTP-related secrets / API responses in initial bundle:

```bash
curl https://target.com/_next/static/chunks/main.*.js | grep -iE 'otp|verification_code|2fa_code'
```

### 5. URL parameter leakage

Some apps put the OTP in the URL during verification flow:
```
https://target.com/verify-2fa?code=123456
```

This URL appears in:
- Browser history.
- Server access logs.
- Referer header on the next click.
- Browser extension monitoring.

Test referer leakage:

```javascript
// Navigate to OTP URL, then click external link
await page.goto('/verify-2fa?code=123456');
await page.click('a[href^="http"]');
// External request includes Referer: https://target.com/verify-2fa?code=123456
```

### 6. Log file leakage

If you have any access to server logs (file inclusion, error pages exposing logs):

```
2024-01-01 10:00:00 INFO User test requested OTP, code: 123456
```

Combine with Path Traversal / LFI scenarios to reach logs.

### 7. Email subject line leakage

Some apps put the OTP in the email subject line. If the email aggregator (Gmail web preview, mobile lock screen notifications) displays the subject, the OTP is visible without opening the email. Test:
- Email subject: `Your code: 123456` ← LEAKED
- Email subject: `Your verification code` ← OK

### 8. SMS preview leakage

Same principle for SMS — lock-screen previews show the first ~80 characters. Apps that put the OTP at the start of the SMS (`123456 is your code`) leak via lock screen.

### 9. Error message leakage

Send malformed verification request and read the error:

```python
r = requests.post('/verify-2fa', json={'username':'test'})
# "Code 123456 expected but received nothing"
```

### 10. Search engine leakage

Some servers cache OTP-containing URLs that get indexed:
```
site:target.com inurl:code=
site:target.com inurl:otp=
```

### 11. Open redirect chain to capture Referer

When app uses URL parameters for OTP and an open redirect exists:

```html
<a href="https://target.com/verify-2fa?code=USER_OTP">Click for prize</a>
```

If user clicks an attacker-controlled link AFTER visiting the OTP URL, Referer leaks the OTP.

### 12. Network monitoring (lab / engagement)

```bash
# Capture live traffic to find OTPs in plaintext
tcpdump -i eth0 -A 'tcp port 80'
# Or use mitmproxy for HTTPS (with cert installed on victim)
```

## Verifying success

- OTP found in response/logs/header BEFORE entering it via the legitimate channel.
- Referer header on subsequent navigation contains the OTP.
- Reproducible across multiple users (not a fluke).

## Common pitfalls

- Most modern apps don't leak OTPs — this is mostly a misconfiguration / debug-leftover bug.
- HTTPS prevents network sniffing; need root cert + proxy for mobile / desktop apps.
- Some "leaks" are actually log scrubbed values or hashes that look like OTPs.
- Reporting leakage requires a working PoC; show how an attacker reaches the leak.

## Tools

- Burp Suite (response inspection).
- Browser DevTools (Network tab, Storage tab).
- mitmproxy / Wireshark for traffic capture.
- Custom regex sweeps over response bodies.
- Google dorking for indexed leaks.
