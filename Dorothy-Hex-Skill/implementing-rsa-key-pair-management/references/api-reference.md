# API Reference: RSA Key Pair Lifecycle Management

## Libraries Used

| Library | Purpose |
|---------|---------|
| `cryptography` | RSA key generation, signing, verification, serialization |
| `os` | Secure random bytes, file permissions |
| `datetime` | Certificate validity periods and key rotation schedules |
| `json` | Export key metadata and audit reports |

## Installation

```bash
pip install cryptography
```

## Key Generation

### Generate RSA Key Pair
```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

def generate_rsa_keypair(key_size=4096):
    """Generate an RSA key pair. Use 2048 minimum, 4096 recommended."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    return private_key
```

### Serialize Private Key (PEM, encrypted)
```python
def save_private_key(private_key, filepath, passphrase):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            passphrase.encode()
        ),
    )
    with open(filepath, "wb") as f:
        f.write(pem)
    os.chmod(filepath, 0o600)  # Restrict permissions
```

### Serialize Public Key
```python
def save_public_key(private_key, filepath):
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(filepath, "wb") as f:
        f.write(pem)
```

### Load Existing Key
```python
def load_private_key(filepath, passphrase=None):
    with open(filepath, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=passphrase.encode() if passphrase else None,
        )
    return private_key

def load_public_key(filepath):
    with open(filepath, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return public_key
```

## Signing and Verification

### Sign Data
```python
def sign_data(private_key, data):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature
```

### Verify Signature
```python
from cryptography.exceptions import InvalidSignature

def verify_signature(public_key, data, signature):
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
```

## Encryption and Decryption

### Encrypt with RSA-OAEP
```python
def encrypt_data(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext
```

### Decrypt with RSA-OAEP
```python
def decrypt_data(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext
```

## Key Audit and Rotation

### Inspect Key Properties
```python
def audit_key(filepath, passphrase=None):
    key = load_private_key(filepath, passphrase)
    pub = key.public_key()
    numbers = pub.public_numbers()
    return {
        "key_size": key.key_size,
        "compliant": key.key_size >= 2048,
        "recommended": key.key_size >= 4096,
        "public_exponent": numbers.e,
        "modulus_bits": numbers.n.bit_length(),
        "format": "PKCS8-PEM",
        "encrypted": passphrase is not None,
    }
```

### Check Key Strength
```python
def check_key_strength(key_path, passphrase=None):
    key = load_private_key(key_path, passphrase)
    findings = []
    if key.key_size < 2048:
        findings.append({
            "issue": f"Key size {key.key_size} bits is below minimum (2048)",
            "severity": "critical",
        })
    elif key.key_size < 4096:
        findings.append({
            "issue": f"Key size {key.key_size} bits — 4096 recommended",
            "severity": "low",
        })
    return {"key_size": key.key_size, "findings": findings}
```

## Self-Signed Certificate Generation

```python
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone

def create_self_signed_cert(private_key, common_name, days_valid=365):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Security Audit"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=days_valid))
        .sign(private_key, hashes.SHA256())
    )
    return cert
```

## Output Format

```json
{
  "key_path": "/etc/pki/private/server.key",
  "key_size": 4096,
  "public_exponent": 65537,
  "compliant": true,
  "encrypted": true,
  "certificate": {
    "common_name": "server.example.com",
    "not_before": "2025-01-15T00:00:00Z",
    "not_after": "2026-01-15T00:00:00Z",
    "serial_number": "ABC123..."
  },
  "findings": []
}
```
