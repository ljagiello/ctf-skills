# API Security — Scenario Index

Read `api-security-principles.md` first for the decision tree and sequencing principles. This index maps environment fingerprints to scenario files.

Proactive class coverage → `owasp-api-top10-coverage.md` (the no-fingerprint classes below WILL be missed by symptom routing).

## GraphQL

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Need to find GraphQL endpoint | `scenarios/graphql/endpoint-discovery.md` | Probe `/graphql` and variants with `{__typename}` |
| Schema enumeration | `scenarios/graphql/introspection-and-bypass.md` | Full introspection + whitespace/URL-encoded bypasses |
| Introspection fully blocked | `scenarios/graphql/schema-reconstruction.md` | Clairvoyance + field suggestions |
| BOLA / data exfiltration | `scenarios/graphql/idor-and-mass-enumeration.md` | Aliases for batch ID enumeration |
| Brute-force passwords / 2FA / promo | `scenarios/graphql/rate-limit-bypass.md` | 100+ aliases per request |
| Login / sensitive mutations | `scenarios/graphql/auth-bypass-and-injection.md` | SQLi / NoSQLi / JWT manipulation |
| State-change mutations cross-site | `scenarios/graphql/csrf-and-content-type.md` | application/x-www-form-urlencoded form |
| Schema cycles, no depth limit | `scenarios/graphql/dos-and-batching.md` | Deep nesting + mass aliases |

## REST

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Initial API recon | `scenarios/rest/api-recon-and-discovery.md` | Passive + active enumeration |
| `/api` parent walk-back | `scenarios/rest/exposed-documentation.md` | Swagger / OpenAPI without auth |
| UI uses one verb but Allow: lists more | `scenarios/rest/options-method-enumeration.md` | OPTIONS reveals hidden methods |
| GET response fields > POST input fields | `scenarios/rest/mass-assignment.md` | Inject privileged hidden fields |
| Frontend → internal-API URL build | `scenarios/rest/sspp-query-string.md` | `%26field=...%23` injection |
| Path-based internal API | `scenarios/rest/sspp-rest-path.md` | `..%2f` traversal to internal endpoints |
| BOLA / BOPLA / function-level authz | `scenarios/rest/owasp-bola-bopla.md` | Cross-user IDs, privilege fields |
| WAF blocks JSON | `scenarios/rest/content-type-confusion-xxe.md` | Switch to XML, try XXE |
| WAF blocks payloads (general) | `scenarios/rest/waf-bypass-techniques.md` | Encoding, HPP, headers |
| CORS reflected/null/creds on API origin | `scenarios/rest/cors-misconfiguration.md` | Probe ACAO reflection + ACAC:true |
| Unauth webhook/ingress endpoint | `scenarios/rest/unauthenticated-webhook-oracle.md` | No-auth POST state oracle |
| https→http redirect / missing HSTS | `scenarios/rest/https-downgrade-redirect-hsts.md` | curl -I transport-security probe |
| Org/object existence side channel | `scenarios/rest/unauth-existence-oracle.md` | Bad-key error-ordering discriminates existence |
| Malformed body leaks schema/stack | `scenarios/rest/verbose-error-schema-disclosure.md` | Framework validation/error disclosure |
| Proactive class coverage | `owasp-api-top10-coverage.md` | OWASP API Top-10 matrix → coverage.json |

## WebSocket

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Realtime feature, find endpoint | `scenarios/websocket/discovery-and-handshake.md` | DevTools/Burp WS history |
| Cookie-only handshake auth | `scenarios/websocket/cswsh.md` | Cross-site WebSocket hijacking |
| Messages reach DB/shell/DOM | `scenarios/websocket/message-injection.md` | XSS/SQLi/Cmd/XXE/wildcard |
| Spoofable handshake headers | `scenarios/websocket/auth-bypass-and-handshake-tricks.md` | Forge Origin/X-FF/Cookie |

## MCP / Dev tooling

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| MCP Inspector / MCPJam / `/api/mcp/*` UI, or `/tools/list`+`/tools/call` API | `scenarios/mcp/inspector-stdio-rce.md` | Unauth stdio `connect` → RCE; call hidden tools past the allowlist |

## Web LLM

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| LLM chat / assistant | `scenarios/web-llm/prompt-injection-direct.md` | Jailbreak + tool enumeration |
| LLM ingests user content | `scenarios/web-llm/prompt-injection-indirect.md` | Plant instructions in review/email/doc |
| LLM has SQL tool | `scenarios/web-llm/sqli-via-llm.md` | Run privileged SQL via LLM |
| LLM has shell-like tool | `scenarios/web-llm/os-command-injection-via-llm.md` | `$()`/backticks in arguments |
| LLM response rendered as HTML | `scenarios/web-llm/insecure-output-xss.md` | XSS via LLM output |
