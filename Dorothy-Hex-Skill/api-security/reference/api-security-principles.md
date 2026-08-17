# API Security Principles

This file is the entry point for API security testing. It contains decision logic, sequencing, and cross-cutting gotchas. Specific techniques live under `scenarios/<area>/<scenario>.md`. Use `INDEX.md` to pick a scenario by trigger.

## Decision tree

| Fingerprint | Family | Where to start |
|---|---|---|
| `/graphql`, `/api/graphql`, GraphiQL UI | `scenarios/graphql/` | `endpoint-discovery.md` → `introspection-and-bypass.md` |
| GraphQL introspection works | `scenarios/graphql/` | `idor-and-mass-enumeration.md`, `auth-bypass-and-injection.md` |
| GraphQL introspection blocked | `scenarios/graphql/schema-reconstruction.md` | Clairvoyance + field suggestions |
| Per-request rate limit on GraphQL | `scenarios/graphql/rate-limit-bypass.md` | Aliases (100+ in one HTTP request) |
| GraphQL accepts urlencoded | `scenarios/graphql/csrf-and-content-type.md` | Cross-site form submission |
| Schema cycles + no depth limit | `scenarios/graphql/dos-and-batching.md` | Deep nesting |
| REST endpoint returns admin doc UI | `scenarios/rest/exposed-documentation.md` | Walk back to `/api`, browse Swagger |
| Endpoint UI uses one verb only | `scenarios/rest/options-method-enumeration.md` | OPTIONS reveals PATCH/PUT |
| Update endpoint, JSON body | `scenarios/rest/mass-assignment.md` | Inject hidden privileged fields |
| Internal API behind frontend, error leaks | `scenarios/rest/sspp-query-string.md` or `sspp-rest-path.md` | `%26field=...%23` / `..%2f` |
| Object-by-ID without ownership check | `scenarios/rest/owasp-bola-bopla.md` | Enumerate IDs, escalate properties |
| WAF blocks JSON injection | `scenarios/rest/content-type-confusion-xxe.md` | Switch Content-Type, try XXE |
| WAF blocks payloads | `scenarios/rest/waf-bypass-techniques.md` | Encoding, HPP, header injection |
| Initial recon | `scenarios/rest/api-recon-and-discovery.md` | Passive + active enumeration |
| LLM chat / assistant endpoint | `scenarios/web-llm/prompt-injection-direct.md` | Jailbreak, enumerate tools |
| LLM consumes user-controlled content (review/email/doc) | `scenarios/web-llm/prompt-injection-indirect.md` | Plant instructions in content |
| LLM has SQL tool | `scenarios/web-llm/sqli-via-llm.md` | Excessive agency |
| LLM has shell-like tool / subscribe / email | `scenarios/web-llm/os-command-injection-via-llm.md` | $() / backticks |
| LLM output rendered as HTML | `scenarios/web-llm/insecure-output-xss.md` | XSS via LLM response |
| WebSocket endpoint identified | `scenarios/websocket/discovery-and-handshake.md` | Map handshake / message format |
| Cookie-only WS auth, no CSRF token | `scenarios/websocket/cswsh.md` | Cross-site WebSocket hijacking |
| WS messages reach DB / shell / DOM | `scenarios/websocket/message-injection.md` | XSS / SQLi / Cmd / XXE / wildcard |
| Spoofable handshake headers (Origin, X-FF) | `scenarios/websocket/auth-bypass-and-handshake-tricks.md` | Forge headers, test admin actions |

## OWASP coverage obligation

The fingerprint tree above says where to START once a symptom appears; it does NOT define DONE. DONE is defined by `skills/coordination/reference/coverage-matrix.md`: every applicable class in `OUTPUT_DIR/coverage.json` must reach `covered` or justified-`NA`. Classes that emit no fingerprint until actively probed — CORS, unauth webhook oracle, existence oracles, verbose errors, transport downgrade, security headers, TLS posture — WILL be missed by symptom-driven routing; the coverage gate forces them. Use `owasp-api-top10-coverage.md` to map each pending class to its scenario file and exact probe.

## Sequencing principles

1. **Recon before payloads.** Map endpoints, methods, and authentication before sending injection. Misdirected payloads waste cycles and trip rate limits.
2. **Read source / docs first.** Swagger / OpenAPI / GraphQL introspection reveal the internal model — much faster than blind brute-force.
3. **Test method coverage.** OPTIONS reveals hidden verbs; many privesc paths live on PATCH or DELETE not visible in the UI.
4. **GraphQL aliases are a force multiplier.** 100 aliases in one HTTP request bypass naive rate limits AND speed up enumeration.
5. **WebSocket frames carry classic injection.** Don't forget XSS / SQLi / Cmd / XXE / NoSQL on WebSocket — same payload library, different transport.
6. **CSRF surfaces in three transports.** REST (form-urlencoded), GraphQL (form-urlencoded), WebSocket (handshake without CSRF token). Test each.
7. **Mass assignment is universal.** Compare GET response fields with POST submission — inject any unmatched + privileged-looking field.
8. **LLMs are confused-deputy substrates.** Their tools have system-level authority; prompt injection inherits that authority. Test prompt injection BEFORE testing direct API auth.
9. **Single source of truth wins.** Use Burp Repeater / curl / Python — pick one channel and document. Mixing breaks reproducibility.
10. **Check responses for state changes too.** A 200 may hide a privilege escalation that's only visible on the next GET.

## Cross-cutting gotchas

- **GraphQL introspection bypass**: whitespace and URL-encoded whitespace (`%0A`, `%09`) often work against naive `__schema\{` regex filters.
- **GraphQL aliases bypass per-request rate limits** but NOT operation-level limits (Apollo plugin) — detect via `"Too many operations"` error.
- **REST OPTIONS may lie** — the server may list verbs it doesn't actually support. Test each anyway.
- **Mass-assign field names are language-specific:** `is_admin` (Python), `isAdmin` (Node), `IsAdmin` (.NET), `admin` / `role` (Rails). Try all.
- **SSPP requires `%26` (`&`) and `%23` (`#`)** to truncate the trailing internal-only parameters. Without `%23`, the trailing context corrupts your injection.
- **Content-Type swap can bypass WAF rules** that only inspect JSON — but only if the server actually accepts the alternate content type.
- **WebSocket CSWSH defeated by SameSite=Lax cookies** in modern browsers — only effective on `SameSite=None` or older browsers.
- **LLM guardrails reject "ignore previous instructions"** in plain text — use role-play, fake boundaries, or technical context wrappers.
- **Indirect prompt injection** can hide in HTML comments, white-on-white text, microscopic fonts — the LLM consumes the raw HTML.
- **WebSocket wildcard injection (`*`, `null`)** often returns more rows than ownership permits — try this on real-time dashboards and notifications.
- **GraphQL CSRF needs application/x-www-form-urlencoded acceptance** — modern Apollo Server v3+ blocks this by default unless misconfigured.
- **PHP loose-comparison + parameter pollution** makes type-juggling on `role=0`, `admin=null` viable across many APIs.
- **Path traversal in REST SSPP** requires the right number of `..%2f` levels — start at 4, adjust to reach `openapi.json`.
- **Client-side rate limiters** (browser-side) are useless — always test from curl / Python directly.
