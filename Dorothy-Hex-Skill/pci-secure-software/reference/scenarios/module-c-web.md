---
name: module-c-web
description: Assessment playbook for PCI SSS v2.0 Module C (publicly-accessible / web software) covering C1 HTTP security headers, C2 input protection, C3 session management, and C4 user authentication via public interfaces.
---

# Module C - Publicly-accessible / Web Software (C1, C2, C3, C4)

Module C applies only when the software exposes a public-network interface
(`public_network_interface == true`). It requires the public surface to set
HTTP security headers safely (C1), defend every input against
injection/deserialization/parser/upload/resource abuse (C2), manage sessions
securely (C3), and authenticate users reaching the software through public
interfaces (C4). If no HTTP server / route registration / public listener
exists, every C-row is NOT_APPLICABLE — cite the absence as
`applicability_evidence`.

## Where to find evidence

- **C1 headers** — middleware / response-filter config: `helmet()`, `secure_headers`,
  `SecurityHeadersMiddleware`, `add_header` (nginx), `Header set` (Apache),
  `<httpProtocol><customHeaders>` (web.config), Spring `HttpSecurity.headers()`.
  Grep keys: `Content-Security-Policy`, `Strict-Transport-Security`,
  `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`,
  `Cross-Origin-*`, and CORS `Access-Control-Allow-Origin`. For C1-2, hunt
  vulnerable/leaky headers: `Server`, `X-Powered-By`, `X-AspNet-Version`,
  `Access-Control-Allow-Origin: *` paired with `Allow-Credentials: true`,
  reflected/`null` origin, over-broad CSP (`unsafe-inline`, `*`).
- **C2 input** — request-handler entry points and the sink calls:
  - C2-1 injection: raw string concatenation into SQL (`execute(f"... {x}")`),
    `eval`/`exec`, `os.system`/`subprocess(..., shell=True)`, template render with
    user data (SSTI), `lxml`/`SAXParser` with entities enabled (XXE), LDAP/XPath
    filter building. Confirm parameterized queries / ORM bind params instead.
  - C2-2 deserialization: `pickle.loads`, `yaml.load` (no `SafeLoader`),
    `ObjectInputStream.readObject`, `BinaryFormatter`, `unserialize()`,
    `Marshal.load`, `JsonConvert` with `TypeNameHandling`.
  - C2-3 parser/interpreter config: XML/JSON/CSV/ZIP parser flags —
    external-entity resolution, DTD, billion-laughs limits, archive expansion caps.
  - C2-4 upload handling: `multipart` handlers, `MultipartFile`,
    `request.files`, extension/MIME allowlists, content-type sniffing, stored
    path, executable-dir writes.
  - C2-5 resource starvation: rate limiters (`@limiter`, `express-rate-limit`,
    `RateLimitingFilter`), body-size caps (`client_max_body_size`,
    `MaxRequestBodySize`), timeouts, pagination/regex-DoS guards.
- **C3 session** — token generation (`secrets.token_*`, `SecureRandom`,
  session-store config), cookie attributes (`Secure`, `HttpOnly`, `SameSite`,
  domain/path), idle/absolute timeout settings, logout / `session.invalidate()`
  / rotation on login (fixation), concurrency caps.
- **C4 auth** — public-route guards: `@login_required`, auth middleware,
  `[Authorize]`, route-table → handler auth checks, the login/credential-verify
  path for externally reachable endpoints.
- **Docs** — architecture/threat-model, security-headers policy, API spec
  (OpenAPI/GraphQL SDL) enumerating the public routes, session-management and
  authentication design sections.

## Reused sub-skills

- [skills/client-side/SKILL.md](../../../client-side/SKILL.md) — C1 HTTP security
  headers, CSP/HSTS/X-Frame-Options, CORS misconfiguration, XSS and clickjacking
  exposure tied to missing/weak headers.
- [skills/injection/SKILL.md](../../../injection/SKILL.md) — C2-1 SQL/NoSQL/OS-command/
  SSTI/XXE/LDAP/XPath sink identification and the negative bypass test.
- [skills/server-side/SKILL.md](../../../server-side/SKILL.md) — C2-2 insecure
  deserialization, C2-3 parser config (XXE), C2-4 file-upload handling.
- [skills/authentication/SKILL.md](../../../authentication/SKILL.md) — C4 user
  authentication via public interfaces and C3 session-token attacks (fixation,
  JWT, weak token entropy).
- [skills/api-security/SKILL.md](../../../api-security/SKILL.md) — REST/GraphQL
  public-surface enumeration so C2/C4 cover every reachable route.
- [skills/web-app-logic/SKILL.md](../../../web-app-logic/SKILL.md) — C3 session
  lifecycle (timeout/termination/concurrency) and C2-5 resource-starvation logic.

## Assessing each requirement

For every row, evidence = `source_file:source_lineno` + a **verbatim**
`quoted_text` snippet (schema §4). Dynamic rows (a bypass attempt, polarity
`negative`, or a Perform/Test method) that you did not actually execute ⇒
`REQUIRES_MANUAL_REVIEW`, never MET (schema §3 invariants).

- **C1-1 (headers used securely)** — MET: the response pipeline sets the required
  headers with safe values on public responses (cite the config line). NOT_MET:
  header absent, or present but weak (CSP with `unsafe-inline`, HSTS without
  `max-age`/`includeSubDomains`). Negative move: request a public route and read
  back the live response headers.
- **C1-2 (vulnerable headers avoided)** — MET: no version-disclosing or
  permissive headers; `Server`/`X-Powered-By` suppressed, CORS not `*`+credentials.
  NOT_MET: leaky/over-permissive header present. Negative move: observe the served
  headers and a cross-origin preflight.
- **C2-1 injection** — MET: user input reaches every interpreter only via
  parameterized queries / safe APIs / context-aware encoding. NOT_MET: a tainted
  sink (cite the concatenation line). Negative move: send a probe payload to that
  parameter and confirm it is neutralized.
- **C2-2 deserialization** — MET: untrusted data is never deserialized into
  arbitrary types (allowlist/safe loader). NOT_MET: an unsafe `*.loads`/`readObject`
  on request data. Negative move: craft a benign typed/object payload and confirm
  rejection.
- **C2-3 parser/interpreter config** — MET: parsers disable external entities/DTD
  and cap expansion (cite the flag). NOT_MET: default/unsafe parser on public input.
  Negative move: submit an entity/expansion probe.
- **C2-4 upload handling** — MET: server-side type/extension allowlist, size cap,
  non-executable storage, no path control. NOT_MET: client-only or missing checks.
  Negative move: attempt an unexpected-type / oversized / traversal upload.
- **C2-5 resource starvation** — MET: rate limits, body-size caps, timeouts, and
  pagination guard the public surface. NOT_MET: an unbounded endpoint. Negative
  move: confirm the limiter trips (small, reversible burst — do not DoS).
- **C3-1.x session** — token exchange over TLS only; high-entropy tokens; `Secure`+
  `HttpOnly`+`SameSite` cookies; idle+absolute timeouts; logout invalidation;
  rotation on privilege change; concurrency control. MET: each attribute cited in
  config/code. NOT_MET: predictable token, missing cookie flag, no expiry, no
  server-side invalidation, or fixation (token unchanged across login). Negative
  move: log in twice and diff the token; reuse a logged-out token.
- **C4 user authentication** — MET: every public, non-public-by-design route is
  behind an auth guard and credentials are verified securely (cite the guard).
  NOT_MET: an unauthenticated reachable route exposing protected function. Negative
  move: call the route with no/expired credential and confirm rejection.

## Remediation themes

- Centralize C1 headers in one middleware with a deny-by-default CSP and HSTS;
  strip `Server`/`X-Powered-By`; scope CORS to explicit origins, never `*`+creds.
- Replace string-built queries/commands with parameterized APIs and context-aware
  output encoding; route uploads through an allowlist + sandboxed storage.
- Use safe deserializers / type allowlists; harden parsers (no external entities,
  expansion caps).
- Add per-route rate limits, body-size caps, and timeouts at the edge.
- Generate session tokens with a CSPRNG; set all cookie security flags; enforce
  idle + absolute timeouts, rotate on login, invalidate on logout.
- Put an auth guard on every public route; default routes to authenticated.

## Anti-Patterns

- Marking a **dynamic** C-row (C1 live headers, C2 bypass, C3 token diff, C4 guard
  test) MET from a static reading of docs or code — if the bypass/observation did
  not run, the verdict is `REQUIRES_MANUAL_REVIEW`.
- Treating a library **import** (`helmet`, an ORM, a rate-limiter package) as proof
  the control is used — the import must be wired into the public response/handler
  path, with a cited call site.
- Asserting MET from the security-headers *policy doc* without confirming the
  header is set on an actual public response.
- Inventing requirement IDs (only C1-1, C1-2, C2-1..C2-5, C3-1.x, C4 here) or
  citing a parameterized-query helper that is bypassed on one tainted sink.
- Calling a row NOT_APPLICABLE without an `applicability_evidence` search showing
  no public-network interface exists.

## See also

- [../core/schema.md](../core/schema.md) — verdict, evidence, and status invariants.
- [../catalog/INDEX.md](../catalog/INDEX.md) — the Module C catalog rows and counts.
