# CTF Crypto - Modern Cipher Attacks

## Table of Contents
- [AES-CFB-8 Static IV State Forging](#aes-cfb-8-static-iv-state-forging)
- [ECB Pattern Leakage on Images](#ecb-pattern-leakage-on-images)
- [Padding Oracle Attack](#padding-oracle-attack)
- [CBC-MAC vs OFB-MAC Vulnerability](#cbc-mac-vs-ofb-mac-vulnerability)
- [Non-Permutation S-box Collision Attack](#non-permutation-s-box-collision-attack)
- [LCG Partial Output Recovery (0xFun 2026)](#lcg-partial-output-recovery-0xfun-2026)
- [Weak Hash Functions / GF(2) Gaussian Elimination](#weak-hash-functions-gf2-gaussian-elimination)

---

## AES-CFB-8 Static IV State Forging

**Pattern (Cleverly Forging Breaks):** AES-CFB with 8-bit feedback and reused IV allows state reconstruction.

**Key insight:** After encrypting 16 known bytes, the AES internal shift register state is fully determined by those ciphertext bytes. Forge new ciphertexts by continuing encryption from known state.

---

## ECB Pattern Leakage on Images

**Pattern (Electronic Christmas Book):** AES-ECB on BMP/image data preserves visual patterns.

**Exploitation:** Identical plaintext blocks produce identical ciphertext blocks, revealing image structure even when encrypted. Rearrange or identify patterns visually.

---

## Padding Oracle Attack

**Pattern (The Seer):** Server reveals whether decrypted padding is valid.

**Byte-by-byte decryption:**
```python
def decrypt_byte(block, prev_block, position, oracle, known):
    """known = bytearray(16) tracking recovered intermediate bytes for this block."""
    for guess in range(256):
        modified = bytearray(prev_block)
        # Set known bytes to produce valid padding
        pad_value = 16 - position
        for j in range(position + 1, 16):
            modified[j] = known[j] ^ pad_value
        modified[position] = guess
        if oracle(bytes(modified) + block):
            return guess ^ pad_value
```

---

## CBC-MAC vs OFB-MAC Vulnerability

OFB mode creates a keystream that can be XORed for signature forgery.

**Attack:** If you have signature for known plaintext P1, forge for P2:
```
new_sig = known_sig XOR block2_of_P1 XOR block2_of_P2
```

**Important:** Don't forget PKCS#7 padding in calculations! Small bruteforce space? Just try all combinations (e.g., 100 for 2 unknown digits).

---

## Non-Permutation S-box Collision Attack

**Pattern (Tetraes, Nullcon 2026):** Custom AES-like cipher with S-box collisions.

**Detection:** `len(set(sbox)) < 256` means collisions exist. Find collision pairs and their XOR delta.

**Attack:** For each key byte, try 256 plaintexts differing by delta. When `ct1 == ct2`, S-box input was in collision set. 2-way ambiguity per byte, 2^16 brute-force. Total: 4,097 oracle queries.

See [advanced-math.md](advanced-math.md) for full S-box collision analysis code.

---

## LCG Partial Output Recovery (0xFun 2026)

**Known parameters:** If LCG constants (M, A, C) are known and output is `state mod N`, iterate by N through modulus to find state:
```python
# output = state % N, state = (A * prev + C) % M
for candidate in range(output, M, N):
    # Check if candidate is consistent with next output
    next_state = (A * candidate + C) % M
    if next_state % N == next_output:
        print(f"State: {candidate}")
```

**Upper bits only (e.g., upper 32 of 64):** Brute-force lower 32 bits:
```python
for low in range(2**32):
    state = (observed_upper << 32) | low
    next_state = (A * state + C) % M
    if (next_state >> 32) == next_observed_upper:
        print(f"Full state: {state}")
```

---

## Weak Hash Functions / GF(2) Gaussian Elimination

Linear permutations (only XOR, rotations) are algebraically attackable. Build transformation matrix and solve over GF(2).

```python
import numpy as np

def solve_gf2(A, b):
    """Solve Ax = b over GF(2)."""
    m, n = A.shape
    Aug = np.hstack([A, b.reshape(-1, 1)]) % 2
    pivot_cols, row = [], 0
    for col in range(n):
        pivot = next((r for r in range(row, m) if Aug[r, col]), None)
        if pivot is None: continue
        Aug[[row, pivot]] = Aug[[pivot, row]]
        for r in range(m):
            if r != row and Aug[r, col]: Aug[r] = (Aug[r] + Aug[row]) % 2
        pivot_cols.append((row, col)); row += 1
    if any(Aug[r, -1] for r in range(row, m)): return None
    x = np.zeros(n, dtype=np.uint8)
    for r, c in reversed(pivot_cols):
        x[c] = Aug[r, -1] ^ sum(Aug[r, c2] * x[c2] for c2 in range(c+1, n)) % 2
    return x
```

---

## Affine Cipher over Composite Modulus (Nullcon 2026)

Affine encryption `c = A*x + b (mod M)` with composite M: split into prime factor fields, invert independently, CRT recombine. See [advanced-math.md](advanced-math.md#affine-cipher-over-composite-modulus-nullcon-2026) for full chosen-plaintext key recovery and implementation.

---

## Custom Linear MAC Forgery (Nullcon 2026)

**Pattern (Pasty):** Server signs paste IDs with a custom SHA-256-based construction. The signature is linear in three 8-byte secret blocks derived from the key.

**Structure:** For each 8-byte output block `i`:
- `selector = SHA256(id)[i*8] % 3` → chooses which secret block to use
- `out[i] = hash_block[i] XOR secret[selector] XOR chain[i-1]`

**Recovery:** Create ~10 pastes to collect `(id, sig)` pairs. Each pair reveals `secret[selector]` for 4 selectors. With ~4-5 pairs, all 3 secret blocks are recovered. Then forge for target ID.

**Key insight:** Linearity in custom crypto constructions (XOR-based signing) makes them trivially forgeable. Always check if the MAC has the property: knowing the secret components lets you compute valid signatures for arbitrary inputs.
