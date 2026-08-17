# HTTPS Downgrade Redirect & Missing HSTS / Security Headers

## When this applies

- Any host with an HTTP (port 80) listener, or any API/web origin in scope.
- Covers two proactive coverage classes that emit no fingerprint in normal HTTPS traffic: `XC-TRANSPORT-DOWNGRADE` (cleartext redirect + missing HSTS) and `XC-SECURITY-HEADERS` (the full response-header set). Both must be probed deliberately — symptom-driven routing skips them.

## Technique

Send `curl -I` to the http and https schemes of every origin. Two transport faults to catch:

1. **Downgrade redirect** — a `30x` whose `Location` uses an `http://` scheme (or a framework trailing-slash redirect that drops to cleartext). The very first request travels in the clear, and any credential/cookie sent on it is exposed to a network MITM before the redirect to HTTPS happens.
2. **Missing HSTS** — no `Strict-Transport-Security` header means a browser will keep trying http:// first, leaving an SSL-strip window on every visit. Audit `max-age`, `includeSubDomains`, and `preload`.

Then audit the **whole security-header set** on the API origin AND on **each web origin separately** — posture differs per host even behind one gateway.

## Steps

### 1. Transport probe — http and https

```bash
curl -sI http://api.target.tld/    # cleartext listener present?
curl -sI https://api.target.tld/
```

Inspect the http response for a downgrade or a cleartext redirect target:

```
HTTP/1.1 301 Moved Permanently
Location: http://api.target.tld/v1/    ← downgrade: redirect stays on http (often a
                                          framework trailing-slash default), or points
                                          to http:// instead of https://
```

A redirect to `https://` is correct; a redirect to `http://`, or a 200 served over plain http, is the finding.

### 2. HSTS audit (on the HTTPS response)

```bash
curl -sI https://api.target.tld/ | grep -i strict-transport-security
# Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

Flag: header absent; short `max-age` (< 15552000 ≈ 6 months); missing `includeSubDomains` (subdomains remain strippable); missing `preload` (first-ever visit still strippable). HSTS only protects after the first successful HTTPS visit — pair this with the downgrade finding for the full MITM window.

### 3. Full security-header set — per origin

Run on the API origin and **each** web origin independently:

```bash
for origin in api.target.tld app.target.tld www.target.tld; do
  echo "== $origin =="
  curl -sI "https://$origin/" | grep -iE \
    'strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|cross-origin-opener-policy'
done
```

| Header | Absence means |
|--------|---------------|
| `Strict-Transport-Security` | SSL-strip / downgrade window |
| `Content-Security-Policy` | no defense-in-depth vs injected scripts |
| `X-Frame-Options` / CSP `frame-ancestors` | clickjacking exposure |
| `X-Content-Type-Options: nosniff` | MIME-sniffing of responses |
| `Referrer-Policy` | URL/token leakage in `Referer` |
| `Permissions-Policy` | unrestricted powerful browser features |
| `Cross-Origin-Opener-Policy` | cross-origin window tampering (XS-Leaks) |

### 4. Characterize the MITM / cleartext-credential window

State concretely: on the first http request (no HSTS yet, or after `max-age` expiry), an on-path attacker reads/rewrites the cleartext request — including any `Authorization` header or `Cookie` the client attaches before the redirect lands. Note whether the redirect happens *before* or *after* the credential is sent (a 301 with no body received the request line + headers already).

## Verifying success

- `curl -sI http://host/` returns a body over cleartext, or a `30x` whose `Location` scheme is `http://`.
- `Strict-Transport-Security` is absent on the HTTPS response, or its directives are weak (short `max-age`, no `includeSubDomains`).
- A per-origin table shows ≥1 missing security header on the API and/or on at least one web origin (each audited separately, not assumed identical).

## Common pitfalls

- Don't assume the API and the SPA share posture — audit `api.`, `app.`, `www.` independently; one missing-HSTS origin undoes the rest.
- A `308`/`307` preserves method+body; a downgrade on these is worse than on a `301` GET — note the code.
- HSTS is ignored on the very first visit unless the host is on the browser preload list — `preload` matters, flag its absence.
- `X-Frame-Options` is superseded by CSP `frame-ancestors`; presence of either covers clickjacking — don't double-count.
- Headers can be added at a CDN/edge and stripped at origin (or vice-versa) — probe the same hostname the client actually reaches.

## Tools

- curl (`-I` on http and https, per origin)
- `testssl.sh`, `sslscan` for TLS posture (companion `XC-TLS-POSTURE`)
- securityheaders.io / Mozilla Observatory for cross-check
