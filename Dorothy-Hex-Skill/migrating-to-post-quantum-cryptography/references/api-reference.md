# OpenSSL PQC Command Reference

## Discovery

| Task | Command |
|------|---------|
| OpenSSL version (need 3.5+) | `openssl version` |
| List quantum-safe KEMs | `openssl list -kem-algorithms \| grep -i mlkem` |
| List quantum-safe signatures | `openssl list -signature-algorithms \| grep -Ei 'mldsa\|slhdsa'` |
| List TLS groups | `openssl list -tls-groups \| grep -i mlkem` |
| Inspect cert algorithm | `openssl x509 -in server.crt -noout -text \| grep -E 'Signature Algorithm\|Public Key'` |

## Key generation

| Task | Command (OpenSSL 3.5+) | oqs-provider (3.0–3.4) |
|------|------------------------|------------------------|
| ML-KEM-768 keypair | `openssl genpkey -algorithm ML-KEM-768 -out mlkem768.key` | `-algorithm mlkem768` |
| ML-DSA-65 keypair | `openssl genpkey -algorithm ML-DSA-65 -out mldsa65.key` | `-algorithm mldsa65` |
| Extract public key | `openssl pkey -in mldsa65.key -pubout -out mldsa65.pub` | same |

## Certificates

| Task | Command |
|------|---------|
| Self-signed ML-DSA cert | `openssl req -new -x509 -key mldsa65.key -out mldsa65.crt -days 365 -subj "/CN=pqc.example.com"` |
| Inspect signature alg | `openssl x509 -in mldsa65.crt -noout -text \| grep -A1 'Signature Algorithm'` |

## Sign / verify

| Task | Command |
|------|---------|
| Sign | `openssl dgst -sign mldsa65.key -out artifact.sig artifact.txt` |
| Verify | `openssl dgst -verify mldsa65.pub -signature artifact.sig artifact.txt` |

## Hybrid TLS key exchange

| Task | Command |
|------|---------|
| TLS server (hybrid group) | `openssl s_server -accept 4433 -www -tls1_3 -cert mldsa65.crt -key mldsa65.key -groups X25519MLKEM768` |
| TLS client (hybrid group) | `openssl s_client -connect localhost:4433 -tls1_3 -groups X25519MLKEM768` |
| Test public PQC endpoint | `openssl s_client -groups X25519MLKEM768 -tls1_3 -connect pq.cloudflareresearch.com:443` |

### Standardized hybrid TLS groups

| Group | Classical leg | PQC leg |
|-------|---------------|---------|
| X25519MLKEM768 | X25519 | ML-KEM-768 |
| SecP256r1MLKEM768 | NIST P-256 | ML-KEM-768 |
| SecP384r1MLKEM1024 | NIST P-384 | ML-KEM-1024 |

## NGINX hybrid config (OpenSSL 3.5+)

```nginx
ssl_protocols TLSv1.3;
ssl_ecdh_curve X25519MLKEM768:X25519:secp256r1;   # hybrid first, classical fallback
```

## oqs-provider activation (openssl.cnf)

```ini
[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect
[default_sect]
activate = 1
[oqsprovider_sect]
activate = 1
```

## CBOM generation

| Tool | Command |
|------|---------|
| cbomkit-theia (dir) | `cbomkit-theia dir ./myapp --output cbom.json` |
| cdxgen (Java + crypto) | `cdxgen -t java --include-crypto -o cbom.json ./myapp` |
