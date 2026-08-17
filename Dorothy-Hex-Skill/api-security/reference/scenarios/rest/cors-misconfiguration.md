# REST CORS Misconfiguration (Reflected Origin / null / Credentials)

## When this applies

- Any browser-reachable API origin (cookie-, bearer-, or API-key-authenticated).
- The API serves cross-origin reads (SPA on a different host/subdomain than the API).
- No fingerprint appears in normal traffic — CORS posture is invisible until you send an `Origin` header. This is a proactive `XC-CORS` coverage class, not a symptom-driven one.

## Technique

CORS is a server-side allowlist decision returned in response headers. Probe it from curl with a forged `Origin` (browsers cannot spoof `Origin`, curl can). The dangerous combination is a **reflected or `null` origin together with `Access-Control-Allow-Credentials: true`** — that lets attacker-controlled JS read authenticated responses cross-origin. Map which origins the server reflects, then find the loosest reflection rule (suffix/prefix/substring regex) an attacker can register or control.

## Steps

### 1. Baseline probe — does the server reflect arbitrary origins?

```bash
curl -s -I -H "Origin: https://attacker.example" https://api.target.tld/v1/me \
  | grep -i 'access-control-'
```

Read the response headers:

```
Access-Control-Allow-Origin: https://attacker.example   ← reflected = bad
Access-Control-Allow-Credentials: true                  ← critical amplifier
Vary: Origin                                            ← cache key (see step 5)
```

Reflected ACAO + `ACAC: true` → cross-origin credentialed read is possible. `ACAO: *` **without** credentials is usually low-impact (no cookie/bearer leakage); note it but do not over-rate.

### 2. `Origin: null` acceptance (sandboxed-iframe angle)

Sandboxed iframes, `data:`/`file:` documents, and some redirects send `Origin: null`. A server that allowlists `null` is exploitable from a sandboxed iframe an attacker plants on any page.

```bash
curl -s -I -H "Origin: null" https://api.target.tld/v1/me | grep -i 'access-control-allow-origin'
# Access-Control-Allow-Origin: null  ← exploitable via <iframe sandbox>
```

### 3. Allowlist regex bypasses

Servers often build the allowlist with a loose match. Test each class of sloppy matcher:

```bash
# Suffix match (endsWith) — attacker registers a domain ending in the trusted apex
curl -sI -H "Origin: https://attacker-target.tld"  https://api.target.tld/v1/me | grep -i allow-origin
# Prefix match (startsWith) — attacker hosts trusted prefix on their own domain
curl -sI -H "Origin: https://target.tld.attacker.example" https://api.target.tld/v1/me | grep -i allow-origin
# Unescaped dot in regex — any char where a literal '.' was intended
curl -sI -H "Origin: https://targetXtld" https://api.target.tld/v1/me | grep -i allow-origin
# Arbitrary subdomain trust — useful if any subdomain has an XSS/takeover
curl -sI -H "Origin: https://anything.target.tld" https://api.target.tld/v1/me | grep -i allow-origin
```

Any payload that comes back reflected in `ACAO` (with `ACAC: true`) is a registrable/controllable bypass.

### 4. Pre-flight (non-simple request) coverage

Methods beyond GET/POST and custom headers trigger an `OPTIONS` pre-flight. Confirm the write paths are also reachable cross-origin:

```bash
curl -s -X OPTIONS https://api.target.tld/v1/account \
  -H "Origin: https://attacker.example" \
  -H "Access-Control-Request-Method: PATCH" \
  -H "Access-Control-Request-Headers: authorization,content-type" -I \
  | grep -i 'access-control-'
# Allow-Methods / Allow-Headers reflected + ACAC:true → cross-origin state change
```

### 5. `Vary: Origin` cache-poisoning angle

If the server reflects the origin but **omits** `Vary: Origin`, a shared/CDN cache can store one origin's permissive `ACAO` and serve it to a different origin. Confirm the header is missing and that the endpoint is cacheable (`Cache-Control: public` / no `no-store`), then flag the cache-key gap.

## Verifying success

- A forged `Origin` is echoed verbatim in `Access-Control-Allow-Origin` **and** `Access-Control-Allow-Credentials: true` is present.
- The affected endpoint returns authenticated/sensitive data (`/me`, `/account`, tokens, PII), so a cross-origin read has real impact.
- For full weaponization (proof-of-concept page that exfiltrates the response in a browser), use the client-side CORS references — do NOT re-derive the JS here: `skills/client-side/reference/cors-quickstart.md` and `skills/client-side/reference/cors-cheat-sheet.md`.

## Common pitfalls

- `ACAO: *` is reflected by some servers regardless of `Origin` — that alone is not credentialed-exploitable; only `ACAC: true` makes it serious.
- Browsers ignore `ACAC: true` when `ACAO: *` — the server must reflect the *specific* origin for credentialed reads.
- Test the **authenticated** endpoint with a real session/key; an unauthenticated endpoint reflecting your origin leaks nothing.
- Some WAFs strip or rewrite `Origin` — confirm your header reached the origin server (vary the value and watch the reflection track it).
- Probe each subdomain/origin separately; CORS posture differs per host even behind one gateway.

## Tools

- curl (forged `Origin`, `OPTIONS` pre-flight)
- Burp Suite + CORS* extensions, `corsy`
- Client-side weaponization: `skills/client-side/reference/cors-cheat-sheet.md`
