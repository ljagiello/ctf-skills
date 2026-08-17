# API Reference: Post-Quantum Cryptography Migration

## NIST PQC Standards Summary

### FIPS 203 -- ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)

Formerly CRYSTALS-Kyber. Primary standard for key exchange and encryption.

**Security Levels:**

| Parameter Set | NIST Level | Public Key | Ciphertext | Shared Secret |
|---------------|-----------|------------|------------|---------------|
| ML-KEM-512 | Level 1 | 800 B | 768 B | 32 B |
| ML-KEM-768 | Level 3 | 1,184 B | 1,088 B | 32 B |
| ML-KEM-1024 | Level 5 | 1,568 B | 1,568 B | 32 B |

**Operations:**
- `KeyGen() -> (ek, dk)` -- Generate encapsulation/decapsulation key pair
- `Encaps(ek) -> (K, c)` -- Encapsulate: produce shared secret K and ciphertext c
- `Decaps(dk, c) -> K` -- Decapsulate: recover shared secret K from ciphertext

**Python (mlkem library):**
```python
from mlkem.ml_kem import ML_KEM

ml_kem = ML_KEM(768)  # ML-KEM-768
ek, dk = ml_kem.key_gen()
shared_secret, ciphertext = ml_kem.encaps(ek)
recovered_secret = ml_kem.decaps(dk, ciphertext)
assert shared_secret == recovered_secret
```

**OpenSSL 3.5+ (native):**
```bash
# Generate ML-KEM-768 key pair
openssl genpkey -algorithm mlkem768 -out mlkem768_key.pem

# Display key details
openssl pkey -in mlkem768_key.pem -text -noout

# Extract public key
openssl pkey -in mlkem768_key.pem -pubout -out mlkem768_pub.pem
```

### FIPS 204 -- ML-DSA (Module-Lattice-Based Digital Signature Algorithm)

Formerly CRYSTALS-Dilithium. Primary standard for digital signatures.

**Security Levels:**

| Parameter Set | NIST Level | Public Key | Secret Key | Signature |
|---------------|-----------|------------|------------|-----------|
| ML-DSA-44 | Level 2 | 1,312 B | 2,560 B | 2,420 B |
| ML-DSA-65 | Level 3 | 1,952 B | 4,032 B | 3,293 B |
| ML-DSA-87 | Level 5 | 2,592 B | 4,896 B | 4,595 B |

**Operations:**
- `KeyGen() -> (pk, sk)` -- Generate signing/verification key pair
- `Sign(sk, M) -> sigma` -- Sign message M with secret key
- `Verify(pk, M, sigma) -> bool` -- Verify signature on message

**OpenSSL 3.5+ (native):**
```bash
# Generate ML-DSA-65 key pair
openssl genpkey -algorithm mldsa65 -out mldsa65_key.pem

# Extract public key
openssl pkey -in mldsa65_key.pem -pubout -out mldsa65_pub.pem

# Sign a file
openssl dgst -sign mldsa65_key.pem -out signature.bin message.txt

# Verify signature
openssl dgst -verify mldsa65_pub.pem -signature signature.bin message.txt
```

### FIPS 205 -- SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)

Formerly SPHINCS+. Backup signature standard using conservative hash-based approach.

**Parameter Sets (SHA2 variants):**

| Parameter Set | NIST Level | Public Key | Signature (fast) | Signature (small) |
|---------------|-----------|------------|------------------|-------------------|
| SLH-DSA-128 | Level 1 | 32 B | 17,088 B | 7,856 B |
| SLH-DSA-192 | Level 3 | 48 B | 35,664 B | 16,224 B |
| SLH-DSA-256 | Level 5 | 64 B | 49,856 B | 29,792 B |

**Variants:** Each level has fast (f) and small (s) variants with SHA2 or SHAKE hash.

## Hybrid TLS Configuration

### X25519MLKEM768 Key Exchange

The hybrid key exchange combines classical X25519 ECDH with ML-KEM-768 post-quantum
KEM. Both must be broken for the handshake to be compromised.

**Apache httpd:**
```apache
# httpd.conf or ssl.conf
SSLEngine on
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLOpenSSLConfCmd Curves X25519MLKEM768:X25519:prime256v1
SSLCertificateFile /etc/ssl/certs/server.crt
SSLCertificateKeyFile /etc/ssl/private/server.key
```

**NGINX:**
```nginx
server {
    listen 443 ssl;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;
    ssl_prefer_server_ciphers on;
    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;
}
```

**Verification:**
```bash
# Test hybrid TLS connection
openssl s_client -connect server.example.com:443 -groups X25519MLKEM768

# Verify negotiated group
# Look for "Server Temp Key: X25519MLKEM768" in output
```

## oqs-provider for OpenSSL 3.0+

### Installation

```bash
# Clone and build oqs-provider
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(nproc)
sudo make install
```

### Configuration

```ini
# /etc/ssl/openssl-oqs.cnf
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
ssl_conf = ssl_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
module = /usr/lib/oqs-provider/oqsprovider.so

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
Groups = x25519_mlkem768:X25519:P-256:P-384
MinProtocol = TLSv1.2
```

### Usage

```bash
# Set environment variable
export OPENSSL_CONF=/etc/ssl/openssl-oqs.cnf

# List available PQC algorithms
openssl list -kem-algorithms | grep -i ml
openssl list -signature-algorithms | grep -i ml

# Generate PQC key pair
openssl genpkey -algorithm mlkem768 -out key.pem

# Test hybrid TLS
openssl s_client -connect server:443 -groups x25519_mlkem768
```

## Cryptographic Inventory Scanning

### NIST SP 1800-38 Discovery Architecture

```
+------------------+     +------------------+     +------------------+
| Source Code Scan | --> |                  | --> | Risk Assessment  |
+------------------+    | Central Analysis |     +------------------+
+------------------+    |     Engine       |            |
| Binary Analysis  | -->|  (Normalization  |     +------------------+
+------------------+    |  & Correlation)  |     | Migration        |
+------------------+    |                  |     | Prioritization   |
| Network Traffic  | -->|                  |     +------------------+
+------------------+    +------------------+
+------------------+
| Certificate Scan | -->
+------------------+
```

### Discovery Domains

| Domain | What to Scan | Tools |
|--------|-------------|-------|
| CI/CD Pipeline | Source code, build configs, dependencies | SCA tools, Semgrep |
| Operational Systems | Running services, installed libraries, key stores | NIST SP 1800-38B tools |
| Network Services | TLS endpoints, VPN configs, IPsec tunnels | This agent, sslyze, testssl |
| Certificates | CA chains, code signing certs, TLS certificates | cert-manager, openssl |

## Quantum-Vulnerable Algorithm Reference

| Algorithm | NIST Status (IR 8547) | Quantum Threat | Replacement |
|-----------|-----------------------|----------------|-------------|
| RSA (all sizes) | Deprecated 2030, removed 2035 | Shor's algorithm | ML-KEM (encryption), ML-DSA (signing) |
| ECDH / ECDHE | Deprecated 2030, removed 2035 | Shor's algorithm | ML-KEM / X25519MLKEM768 hybrid |
| ECDSA | Deprecated 2030, removed 2035 | Shor's algorithm | ML-DSA |
| DSA | Already deprecated | Shor's algorithm | ML-DSA |
| DH / DHE | Deprecated 2030, removed 2035 | Shor's algorithm | ML-KEM |
| AES-128 | Acceptable with caveat | Grover's halves to 64-bit | AES-256 |
| AES-256 | Quantum-safe | Grover's reduces to 128-bit | No change needed |
| SHA-256 | Quantum-safe | Grover's reduces to 128-bit | No change needed |
| SHA-3 | Quantum-safe | Grover's reduces to 128-bit | No change needed |

## MITRE ATT&CK Relevance

| Technique | ID | PQC Relevance |
|-----------|----|---------------|
| Adversary-in-the-Middle | T1557 | Quantum computers can break key exchange in recorded sessions |
| Encrypted Channel | T1573 | Harvest-now-decrypt-later targets encrypted C2 traffic |
| Steal Application Access Token | T1528 | Quantum computers can forge digital signatures |
| Forge Web Credentials | T1606 | Quantum computers can break certificate private keys |

## References

- NIST PQC Project: https://csrc.nist.gov/projects/post-quantum-cryptography
- FIPS 203 Final: https://csrc.nist.gov/pubs/fips/203/final
- FIPS 204 Final: https://csrc.nist.gov/pubs/fips/204/final
- FIPS 205 Final: https://csrc.nist.gov/pubs/fips/205/final
- NIST IR 8547 (Transition Timeline): https://csrc.nist.gov/pubs/ir/8547/ipd
- NIST SP 1800-38 (Migration Guide): https://www.nccoe.nist.gov/crypto-agility-considerations-migrating-post-quantum-cryptographic-algorithms
- CISA PQC Strategy: https://www.cisa.gov/sites/default/files/2024-09/Strategy-for-Migrating-to-Automated-PQC-Discovery-and-Inventory-Tools.pdf
- Open Quantum Safe: https://openquantumsafe.org/
- oqs-provider GitHub: https://github.com/open-quantum-safe/oqs-provider
- OQS TLS Applications: https://openquantumsafe.org/applications/tls.html
- IETF Hybrid Design Draft: https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/
- kyber-py (Python ML-KEM): https://github.com/GiacomoPope/kyber-py
- ml-kem (Python FIPS 203): https://github.com/AntonKueltz/ml-kem
- CycloneDX Crypto BOM: https://cyclonedx.org/use-cases/cryptographic-key/
