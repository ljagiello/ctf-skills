# ECDSA Nonce Reuse — Private Key Recovery

## When this applies

- Two or more ECDSA signatures are produced under the same private key, with the same per-signature nonce `k`.
- You see two `(r, s)` pairs that share the same `r` value (since `r = x(k·G)` is determined by `k`).
- Trigger keywords: "ECDSA", "nonce", "k reuse", "secp256k1", "Bitcoin signature reuse", "Sony PS3" (the canonical real-world case).
- Also applies to DSA and Schnorr with the same flaw.

## Technique

ECDSA signatures: `s = k^{-1} (h + r·d) mod n`, where `h = H(m)`, `d = private key`, `n = curve order`.

Two signatures `(r, s1)` on `h1 = H(m1)` and `(r, s2)` on `h2 = H(m2)` share `r` iff they share `k`. From the system:

```
s1·k = h1 + r·d
s2·k = h2 + r·d
```

Subtract: `(s1 - s2)·k = h1 - h2`, so `k = (h1 - h2) / (s1 - s2) mod n`. Then `d = (s1·k - h1) / r mod n`.

## Steps

### 1. Find two signatures with shared `r`

Scan a corpus of signatures: group by `r`. Any non-singleton group is a key-recovery oracle.

```python
from collections import defaultdict
groups = defaultdict(list)
for (r, s, m) in signatures:
    groups[r].append((s, m))
shared = {r: lst for r, lst in groups.items() if len(lst) > 1}
```

### 2. Recover `k`

```python
n = curve.order  # secp256k1: 0xFFFF…FFFEBAAEDCE6AF48A03BBFD25E8CD0364141
h1 = int.from_bytes(hashlib.sha256(m1).digest(), 'big')
h2 = int.from_bytes(hashlib.sha256(m2).digest(), 'big')

k = ((h1 - h2) * pow(s1 - s2, -1, n)) % n
```

### 3. Recover `d`

```python
d = ((s1 * k - h1) * pow(r, -1, n)) % n
```

### 4. Verify

Sign a test message with `d` and check it verifies under the public key.

```python
# pubkey = d * G
# verify by re-computing pubkey from d and comparing to known
```

### 5. (Optional) Forge new signatures

With `d` recovered, sign anything: `k_new = randint(1, n-1)`; `r_new = x(k_new·G)`; `s_new = k_new^{-1}(h + r_new·d) mod n`.

## Verifying success

- Test signature with recovered `d` verifies under the published public key.
- For Bitcoin: recovered `d` matches the private key for the published address (`pubkey_to_address(d·G) == known_address`).
- For PS3: recovered `d` is the famous private key matching public key in firmware.

## Common pitfalls

- **Hashing differences.** Some protocols use SHA-1, some SHA-256, some custom hash. Match the hash function exactly.
- **Truncation.** ECDSA truncates `h` to `bitlen(n)` bits. For secp256k1 (256-bit `n`) and SHA-256 it's a no-op; for P-521 with SHA-256, `h` is bit-length-extended.
- **Sign of `s`.** Some libraries normalize `s = min(s, n - s)`. If two raw signatures look different but share `r`, check both `s` and `n - s` for the second.
- **Nonce-related (not equal) k.** Lattice attacks recover `d` from many signatures with biased nonces (`k_i` known to be in a small range or with leaked low bits). See `scenarios/lattice/lll-basis-reduction.md`.
- **Curve order vs prime.** Modular inverse is mod `n` (curve order), never mod `p` (field prime).

## Tools

- `pycryptodome.PublicKey.ECC` or `ecdsa` Python library for curve arithmetic.
- `coincurve` for secp256k1 (Bitcoin/Ethereum).
- Hand-rolled in ~30 lines once you have the curve constants.
