# DOM Vulnerabilities — Prevention Best Practices

## When this applies

You're advising on remediation, hardening client-side code, or writing the defensive section of a pentest report. Covers input validation, output encoding, safe APIs, CSP, sanitization libraries, framework-specific patterns, prototype-pollution prevention, DOM-clobbering hardening, and postMessage origin validation.

## Technique

Layered defense: (1) input validation (allowlist), (2) context-aware output encoding, (3) safe-API substitutes for dangerous sinks, (4) Content Security Policy, (5) sanitization libraries, (6) framework-native escaping, (7) preventing prototype pollution / DOM clobbering / postMessage misuse.

## Steps

### Input Validation

**Whitelist approach:**
```javascript
// Good - whitelist allowed values
const allowedValues = ['option1', 'option2', 'option3'];
if (allowedValues.includes(userInput)) {
    // Safe to use
}

// Bad - blacklist (easy to bypass)
if (!userInput.includes('<script>')) {
    // Still vulnerable!
}
```

**Type validation:**
```javascript
// Ensure input is expected type
let page = parseInt(userInput);
if (isNaN(page) || page < 1 || page > 100) {
    throw new Error('Invalid page number');
}
```

### Output Encoding

**HTML context:**
```javascript
function htmlEncode(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Usage
element.textContent = userInput; // Automatically encoded
element.innerHTML = htmlEncode(userInput); // Manual encoding
```

**JavaScript context:**
```javascript
function jsEncode(str) {
    return String(str)
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r');
}
```

**URL context:**
```javascript
let safe = encodeURIComponent(userInput);
```

### Use Safe APIs

**Instead of dangerous sinks:**
```javascript
// Bad
element.innerHTML = userInput;
document.write(userInput);
eval(userInput);

// Good
element.textContent = userInput;
element.innerText = userInput;
// Or use DOMPurify for rich content
element.innerHTML = DOMPurify.sanitize(userInput);
```

**Safe jQuery methods:**
```javascript
// Bad
$(userInput);
$element.html(userInput);

// Good
$element.text(userInput);
```

### Content Security Policy (CSP)

**Strict CSP:**
```http
Content-Security-Policy:
    default-src 'none';
    script-src 'nonce-{random}' 'strict-dynamic';
    style-src 'nonce-{random}';
    img-src 'self';
    connect-src 'self';
    base-uri 'none';
    object-src 'none';
```

**Key directives:**
- `script-src` - Controls script sources
- `object-src 'none'` - Prevents Flash/plugin exploits
- `base-uri 'none'` - Prevents base tag injection
- `'strict-dynamic'` - Allows nonce-approved scripts to load others

**Nonce example:**
```html
<script nonce="r4nd0m">
    // Trusted script
</script>
```

### Sanitization Libraries

**DOMPurify:**
```javascript
import DOMPurify from 'dompurify';

let clean = DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong'],
    ALLOWED_ATTR: ['href']
});
element.innerHTML = clean;
```

**Configuration options:**
```javascript
DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ['b', 'i', 'em'],
    ALLOWED_ATTR: ['href', 'title'],
    FORBID_TAGS: ['script', 'style'],
    FORBID_ATTR: ['onclick', 'onerror'],
    ALLOW_DATA_ATTR: false,
    SANITIZE_DOM: true
});
```

### Framework-Specific Protections

**React:**
```jsx
// Automatically escapes
<div>{userInput}</div>

// Dangerous (avoid)
<div dangerouslySetInnerHTML={{__html: userInput}} />

// Safe alternative
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />
```

**Vue:**
```vue
<!-- Automatically escaped -->
<div>{{ userInput }}</div>

<!-- Dangerous (avoid) -->
<div v-html="userInput"></div>

<!-- Safe alternative -->
<div v-html="$sanitize(userInput)"></div>
```

**Angular:**
```typescript
// Automatically sanitized
template: '<div>{{userInput}}</div>'

// For trusted HTML
import { DomSanitizer } from '@angular/platform-browser';

constructor(private sanitizer: DomSanitizer) {}

getTrustedHtml() {
    return this.sanitizer.sanitize(SecurityContext.HTML, userInput);
}
```

### Preventing Prototype Pollution

**1. Freeze Object.prototype:**
```javascript
Object.freeze(Object.prototype);
```

**2. Use Map instead of objects:**
```javascript
// Instead of
let obj = {};
obj[userKey] = userValue;

// Use
let map = new Map();
map.set(userKey, userValue);
```

**3. Validate keys:**
```javascript
function safeMerge(target, source) {
    for (let key in source) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue; // Skip dangerous keys
        }
        target[key] = source[key];
    }
}
```

**4. Use Object.create(null):**
```javascript
let obj = Object.create(null); // No prototype
obj.toString // undefined (safe)
```

### Preventing DOM Clobbering

**1. Check property type:**
```javascript
// Bad
if (window.config) { /* ... */ }

// Good
if (typeof window.config === 'object' && window.config.constructor === Object) {
    // Ensure it's a plain object, not HTML element
}
```

**2. Use strict checks:**
```javascript
// Bad
let value = window.value || default;

// Good
let value = (typeof window.value === 'string') ? window.value : default;
```

**3. Avoid global namespace:**
```javascript
// Bad
let config = window.config || {};

// Good
let config = (function() {
    try {
        return JSON.parse(localStorage.getItem('config')) || {};
    } catch {
        return {};
    }
})();
```

### Preventing Web Message Vulnerabilities

**Always validate origin:**
```javascript
window.addEventListener('message', function(e) {
    // Validate origin
    if (e.origin !== 'https://trusted.com') {
        return; // Reject messages from untrusted origins
    }

    // Validate message format
    let data;
    try {
        data = JSON.parse(e.data);
    } catch {
        return; // Invalid JSON
    }

    // Sanitize before use
    if (data.action === 'updateContent') {
        element.textContent = data.content; // Use textContent, not innerHTML
    }
});
```

**Whitelist target origin when sending:**
```javascript
// Bad
targetWindow.postMessage(message, '*');

// Good
targetWindow.postMessage(message, 'https://trusted.com');
```

## Verifying success

- Static scan passes (`npm run lint`, Semgrep, ESLint security) without DOM-XSS warnings.
- Manual review: every source-to-sink path goes through encoding/sanitization.
- CSP report-uri receives no inline-script violations during normal use.
- Penetration test (re-run after remediation) cannot reproduce previously confirmed XSS.

## Common pitfalls

1. **Sanitization runs on the wrong layer** — server sanitizes but client re-uses raw user input.
2. **DOMPurify default config too permissive** — `<a href="javascript:">` blocked, but `cid:` and `data:` may slip; tighten with custom hooks.
3. **CSP `'unsafe-inline'`** — completely defeats `script-src` strictness. Audit existing CSPs.
4. **Framework auto-escape bypassed** — `dangerouslySetInnerHTML`, `v-html`, `[innerHTML]` opt out. Treat them like `eval`.
5. **Encoding context mismatch** — HTML-encoded data inside a JS string does NOT prevent XSS. Encode for the actual destination context.

## Tools

- **DOMPurify** — XSS sanitization library
- **Trusted Types polyfill** — runtime DOM XSS prevention
- **CSP Evaluator (Google)** — score CSP strictness
- **`secure-json-parse`** — defends against `__proto__` in JSON
- **`ajv` / `zod` / `joi`** — schema validation; reject unexpected keys

## Related

- `detection-methodology.md` — find sinks/sources before remediating
