# CTF Crypto - Modern Cipher Attacks

Block cipher attacks, MAC forgery, padding oracles, and authenticated encryption. For hash/signature attacks (hash extension, PBKDF2, MD5 collision, Rabin, ECB oracles), see [modern-ciphers-2.md](modern-ciphers-2.md). For stream cipher attacks (LFSR, RC4, XOR), see [stream-ciphers.md](stream-ciphers.md).

## Table of Contents
- [AES-CFB-8 Static IV State Forging](#aes-cfb-8-static-iv-state-forging)
- [ECB Pattern Leakage on Images](#ecb-pattern-leakage-on-images)
- [Padding Oracle Attack](#padding-oracle-attack)
- [CBC-MAC vs OFB-MAC Vulnerability](#cbc-mac-vs-ofb-mac-vulnerability)
- [Non-Permutation S-box Collision Attack](#non-permutation-s-box-collision-attack)
- [LCG Partial Output Recovery (0xFun 2026)](#lcg-partial-output-recovery-0xfun-2026)
- [Weak Hash Functions / GF(2) Gaussian Elimination](#weak-hash-functions--gf2-gaussian-elimination)
- [Affine Cipher over Composite Modulus (Nullcon 2026)](#affine-cipher-over-composite-modulus-nullcon-2026)
- [AES-GCM with Derived Keys (EHAX 2026)](#aes-gcm-with-derived-keys-ehax-2026)
- [AES-GCM Nonce Reuse / Forbidden Attack](#aes-gcm-nonce-reuse--forbidden-attack)
- [Ascon-like Reduced-Round Differential Cryptanalysis (srdnlenCTF 2026)](#ascon-like-reduced-round-differential-cryptanalysis-srdnlenctf-2026)
- [Custom Linear MAC Forgery (Nullcon 2026)](#custom-linear-mac-forgery-nullcon-2026)
- [CBC Padding Oracle Attack](#cbc-padding-oracle-attack)
- [Bleichenbacher / PKCS#1 v1.5 RSA Padding Oracle](#bleichenbacher--pkcs1-v15-rsa-padding-oracle)
- [Birthday Attack / Meet-in-the-Middle](#birthday-attack--meet-in-the-middle)
- [CRC32 Collision-Based Signature Forgery (iCTF 2013)](#crc32-collision-based-signature-forgery-ictf-2013)

See also [modern-ciphers-2.md](modern-ciphers-2.md) for CRC32 forgery, Blum-Goldwasser, hash length extension, compression oracle, hash time reversal, OFB invertible RNG, weak key derivation, HMAC-CRC, DES weak keys, SRP bypass, modified AES S-Box, square attack, AES-ECB byte-at-a-time, AES-ECB cut-and-paste, AES-CBC IV bit-flip, Rabin LSB parity oracle, PBKDF2 pre-hash bypass, MD5 multi-collision, custom hash state reversal, and CRC32 brute-force.

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
```text
new_sig = known_sig XOR block2_of_P1 XOR block2_of_P2
```

**Important:** Don't forget PKCS#7 padding in calculations! Small bruteforce space? Just try all combinations (e.g., 100 for 2 unknown digits).

**Key insight:** OFB-MAC generates a keystream independent of the plaintext, so knowing one (message, MAC) pair lets you forge MACs for arbitrary messages by XORing the known plaintext blocks out and XORing the new ones in. CBC-MAC does not have this weakness because each block's encryption depends on the previous ciphertext block.

---

## Non-Permutation S-box Collision Attack

**Pattern (Tetraes, Nullcon 2026):** Custom AES-like cipher with S-box collisions.

**Detection:** `len(set(sbox)) < 256` means collisions exist. Find collision pairs and their XOR delta.

**Attack:** For each key byte, try 256 plaintexts differing by delta. When `ct1 == ct2`, S-box input was in collision set. 2-way ambiguity per byte, 2^16 brute-force. Total: 4,097 oracle queries.

See [advanced-math.md](advanced-math.md) for full S-box collision analysis code.

---

## LCG Partial Output Recovery (0xFun 2026)

**Known parameters:** If LCG (Linear Congruential Generator) constants (M, A, C) are known and output is `state mod N`, iterate by N through modulus to find state:
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

**Key insight:** LCG output truncation (modulo or upper bits only) hides part of the state, but consecutive outputs constrain it. When output is `state mod N`, iterate candidates by N through the modulus. When only upper bits are visible, brute-force the hidden lower bits and validate against the next output.

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

**Key insight:** Hash functions built from only XOR and rotations (no S-boxes or modular addition) are linear over GF(2). Build the transformation as a binary matrix, then invert it with Gaussian elimination to recover the preimage directly. This breaks any "custom hash" that avoids non-linear operations.

---

## Affine Cipher over Composite Modulus (Nullcon 2026)

Affine encryption `c = A*x + b (mod M)` with composite M: split into prime factor fields, invert independently, CRT recombine. See [advanced-math.md](advanced-math.md#affine-cipher-over-non-prime-modulus-nullcon-2026) for full chosen-plaintext key recovery and implementation.

---

## AES-GCM with Derived Keys (EHAX 2026)

**Pattern:** Final decryption step after recovering a secret (e.g., from LWE, key exchange). Session nonce and AES key derived via SHA-256 hashing of the recovered secret.

```python
import hashlib
from Cryptodome.Cipher import AES

# Common key derivation chain:
# 1. Recover secret bytes (s_bytes) from crypto challenge
# 2. Unwrap session nonce: nonce = wrapped_nonce XOR SHA256(s_bytes)[:nonce_len]
# 3. Derive AES key: key = SHA256(s_bytes + session_nonce)
# 4. Decrypt AES-GCM

def decrypt_with_derived_key(s_bytes, wrapped_nonce, ciphertext, aes_nonce, tag, nonce_len=16):
    secret_hash = hashlib.sha256(s_bytes).digest()
    session_nonce = bytes(a ^ b for a, b in zip(wrapped_nonce, secret_hash[:nonce_len]))
    aes_key = hashlib.sha256(s_bytes + session_nonce).digest()
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
```

**Key insight:** When AES-GCM authentication fails (`ValueError: MAC check failed`), the derived key is wrong — usually means the upstream secret recovery was incorrect or endianness is swapped.

---

## AES-GCM Nonce Reuse / Forbidden Attack

AES-GCM (Galois/Counter Mode) combines AES-CTR encryption with a GHASH polynomial authentication tag. Reusing a nonce with the same key is catastrophic -- it enables both plaintext recovery AND authentication key recovery.

**CTR keystream reuse:** Same nonce = same keystream. XOR two ciphertexts to cancel the keystream: `C1 XOR C2 = P1 XOR P2`. With known plaintext in one message, recover the other.

**GHASH authentication key recovery:** The authentication tag is a polynomial evaluation over GF(2^128). Two messages with the same nonce produce two equations in the same authentication key H. XOR the tag polynomials and factor over GF(2^128) to recover H. With H, forge valid tags for arbitrary messages.

```python
from Crypto.Cipher import AES
from sage.all import GF, PolynomialRing

# Given: two (ciphertext, tag, nonce) pairs with same nonce
# Step 1: Recover plaintext via CTR keystream reuse
keystream = xor(known_plaintext, ciphertext1)
plaintext2 = xor(keystream, ciphertext2)

# Step 2: Recover GHASH auth key H
# Construct tag difference polynomial in GF(2^128)
F = GF(2**128, 'x', modulus=...)  # GCM polynomial
# T1 XOR T2 = P(H) where P is polynomial from ciphertext difference
# Factor P(H) = 0 to find H candidates
# Verify H against known tags

# Step 3: Forge tags for arbitrary messages
# GHASH(H, aad, ciphertext) computed with recovered H
```

**Tool:** [nonce-disrespect](https://github.com/nonce-disrespect/nonce-disrespect) automates GHASH key recovery and tag forgery from nonce-reused GCM ciphertexts.

**Short nonce brute-force:** When GCM uses a short nonce (1-4 bytes), brute-force all nonce values if the key is known. AES-GCM with 1-byte nonce = only 256 candidates.

**Key insight:** AES-GCM is a "one-time nonce" scheme -- a single nonce reuse breaks both confidentiality (CTR keystream reuse) AND authenticity (GHASH key recovery). Always check for repeated nonces in GCM challenge traffic.

---

## Ascon-like Reduced-Round Differential Cryptanalysis (srdnlenCTF 2026)

**Pattern (Lightweight):** 4-round Ascon-like permutation with reduced diffusion. Key-dependent biases in output-bit differentials allow key recovery via chosen input differences.

**Attack:**
1. Reproduce the permutation exactly (critical: post-S-box x4 assignment order matters)
2. Invert the linear layer of x0 using a precomputed 64×64 GF(2) inverse matrix
3. For each bit position i, query with `diff = (1<<i, 1<<i)` across multiple samples
4. Measure empirical biases at output bits `j1 = (i+1) mod 64` and `j2 = (i+14) mod 64`
5. Classify key bits `(k0[i], k1[i])` via centroid-based clustering with sign-pattern mask
6. Verify candidate key in-session; refine low-margin bits with additional samples

**GF(2) linear layer inversion:**
```python
def build_inverse(shifts=(19, 28)):
    """Construct GF(2) inverse matrix for Ascon-like linear layer: x ^= rot(x,19) ^ rot(x,28)."""
    # Build 64x64 matrix over GF(2)
    M = [[0]*64 for _ in range(64)]
    for out_bit in range(64):
        M[out_bit][out_bit] = 1
        for shift in shifts:
            M[out_bit][(out_bit + shift) % 64] ^= 1
    # Gaussian elimination to find inverse
    aug = [row + [1 if i == j else 0 for j in range(64)] for i, row in enumerate(M)]
    for col in range(64):
        pivot = next(r for r in range(col, 64) if aug[r][col])
        aug[col], aug[pivot] = aug[pivot], aug[col]
        for r in range(64):
            if r != col and aug[r][col]:
                aug[r] = [a ^ b for a, b in zip(aug[r], aug[col])]
    return [row[64:] for row in aug]
```

**Centroid clustering for key classification:**
```python
# For each bit position, measure bias at two output positions
# 4 possible (k0[i], k1[i]) pairs → 4 centroid patterns
# Uses sign-pattern mask CMASK=0x73 to account for bit-position-dependent behavior
# Classify by minimum Euclidean distance in 2D bias space
CMASK = 0x73
for i in range(64):
    bias_j1, bias_j2 = measure_biases(i, samples)
    mask_bit = (CMASK >> (i % 8)) & 1
    centroids = centroid_table[mask_bit]  # Precomputed per-position centroids
    k0_bit, k1_bit = min(range(4), key=lambda c: euclidean_dist(
        (bias_j1, bias_j2), centroids[c]))
```

**Key insight:** Reduced-round lightweight ciphers (Ascon, GIFT, etc.) have exploitable biases when the number of rounds is insufficient for full diffusion. The linear layer's inverse can be computed algebraically, and differential biases measured across chosen-plaintext queries reveal individual key bits. This is practical even with noisy measurements if you collect enough samples.

---

## Custom Linear MAC Forgery (Nullcon 2026)

**Pattern (Pasty):** Server signs paste IDs with a custom SHA-256-based construction. The signature is linear in three 8-byte secret blocks derived from the key.

**Structure:** For each 8-byte output block `i`:
- `selector = SHA256(id)[i*8] % 3` → chooses which secret block to use
- `out[i] = hash_block[i] XOR secret[selector] XOR chain[i-1]`

**Recovery:** Create ~10 pastes to collect `(id, sig)` pairs. Each pair reveals `secret[selector]` for 4 selectors. With ~4-5 pairs, all 3 secret blocks are recovered. Then forge for target ID.

**Key insight:** Linearity in custom crypto constructions (XOR-based signing) makes them trivially forgeable. Always check if the MAC has the property: knowing the secret components lets you compute valid signatures for arbitrary inputs.

---

## CBC Padding Oracle Attack

**Pattern:** Server reveals whether CBC-mode ciphertext has valid PKCS#7 padding (via error messages, timing, or status codes). Decrypt any ciphertext block-by-block without the key.

```python
from pwn import *

def padding_oracle(iv, ct):
    """Returns True if server accepts padding."""
    resp = requests.post(URL, data={'iv': iv.hex(), 'ct': ct.hex()})
    return 'padding' not in resp.text.lower()  # or check status code

def decrypt_block(prev_block, target_block):
    """Decrypt one 16-byte block using padding oracle."""
    intermediate = bytearray(16)
    plaintext = bytearray(16)

    for byte_pos in range(15, -1, -1):
        pad_val = 16 - byte_pos
        # Set already-known bytes to produce correct padding
        crafted = bytearray(16)
        for k in range(byte_pos + 1, 16):
            crafted[k] = intermediate[k] ^ pad_val

        for guess in range(256):
            crafted[byte_pos] = guess
            if padding_oracle(bytes(crafted), target_block):
                intermediate[byte_pos] = guess ^ pad_val
                plaintext[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]
                break

    return bytes(plaintext)
```

**Tools:**
```bash
# PadBuster — automated padding oracle exploitation
padbuster http://target/decrypt.php ENCRYPTED_B64 16 \
  -encoding 0 -error "Invalid padding"

# Python: pip install padding-oracle
from padding_oracle import PaddingOracle
oracle = PaddingOracle(block_size=16, oracle_fn=check_padding)
plaintext = oracle.decrypt(ciphertext, iv=iv)
```

**Key insight:** The oracle only needs to distinguish "valid padding" from "invalid padding." This can be a different HTTP status code, error message, response time, or even whether the application processes the request further. A single bit of information per query is sufficient. Decryption requires at most 256 x 16 = 4096 queries per block.

**Detection:** CBC mode encryption + any distinguishable behavior difference on padding errors. Common in cookie encryption, token systems, and encrypted API parameters.

---

## Bleichenbacher / PKCS#1 v1.5 RSA Padding Oracle

**Pattern:** RSA encryption with PKCS#1 v1.5 padding where the server reveals whether decrypted plaintext has valid `0x00 0x02` prefix. Adaptive chosen-ciphertext attack recovers the plaintext.

```python
import gmpy2

def bleichenbacher_oracle(c, n, e):
    """Returns True if RSA decryption has valid PKCS#1 v1.5 padding (0x00 0x02 prefix)."""
    resp = send_to_server(c)
    return resp.status_code != 400  # Server returns 400 on bad padding

def bleichenbacher_attack(c0, n, e, oracle, k):
    """
    c0: target ciphertext (integer)
    k: byte length of modulus (e.g., 256 for RSA-2048)
    """
    B = pow(2, 8 * (k - 2))

    # Step 1: Start with s1 = ceil(n / 3B)
    s = (n + 3 * B - 1) // (3 * B)

    # Step 2: Search for s where oracle(c0 * s^e mod n) is True
    while True:
        c_prime = (c0 * pow(s, e, n)) % n
        if oracle(c_prime, n, e):
            break
        s += 1

    # Step 3: Narrow interval [a, b] using s values
    # Repeat: find new s, narrow interval, until a == b
    # When interval collapses, plaintext = a * modinv(s, n) % n
    # (Full implementation requires interval tracking — use existing tools)
```

**Tools:**
```bash
# ROBOT attack scanner (modern Bleichenbacher variant)
python3 robot-detect.py -H target.com

# TLS-Attacker framework
java -jar TLS-Attacker.jar -connect target:443 -workflow_type BLEICHENBACHER
```

**Key insight:** The attack is adaptive — each oracle response narrows the range of possible plaintexts. Typically requires ~10,000 oracle queries for RSA-2048. The ROBOT attack (Return Of Bleichenbacher's Oracle Threat) showed this affects modern TLS implementations through subtle timing differences. Any server that distinguishes "bad padding" from "bad content" is vulnerable.

---

## Birthday Attack / Meet-in-the-Middle

**Pattern:** Find collisions in hash functions or MACs using the birthday paradox. With an n-bit hash, expect a collision after ~2^(n/2) random inputs.

```python
import hashlib, os

def birthday_collision(hash_fn, output_bits, prefix=b''):
    """Find two inputs with the same truncated hash."""
    target_bytes = output_bits // 8
    seen = {}

    while True:
        msg = prefix + os.urandom(16)
        h = hash_fn(msg).digest()[:target_bytes]
        if h in seen:
            return seen[h], msg  # Collision found!
        seen[h] = msg

# Example: find collision on first 4 bytes of SHA-256 (~65536 attempts)
msg1, msg2 = birthday_collision(hashlib.sha256, 32)
```

**Meet-in-the-Middle (2DES, double encryption):**
```python
def meet_in_the_middle(encrypt_fn, decrypt_fn, plaintext, ciphertext, keyspace):
    """Break double encryption E(k2, E(k1, pt)) = ct."""
    # Forward: encrypt plaintext with all possible k1
    forward = {}
    for k1 in keyspace:
        intermediate = encrypt_fn(k1, plaintext)
        forward[intermediate] = k1

    # Backward: decrypt ciphertext with all possible k2
    for k2 in keyspace:
        intermediate = decrypt_fn(k2, ciphertext)
        if intermediate in forward:
            return forward[intermediate], k2  # Found k1, k2!
```

**Key insight:** Birthday attack: n-bit hash needs ~2^(n/2) queries for 50% collision probability. 32-bit hash -> ~65K, 64-bit -> ~4 billion. Meet-in-the-middle reduces double encryption from O(2^(2k)) to O(2^k) time + O(2^k) space — this is why 2DES provides only 1 extra bit of security over DES.

---

## CRC32 Collision-Based Signature Forgery (iCTF 2013)

**Pattern:** CRC32 is linear — appending 4 carefully chosen bytes to any message produces a target CRC32 value, enabling signature forgery without knowing the secret key.

**Key insight:** `CRC32(msg || secret)` is not a secure MAC. Given any signed response `(msg, sig)`, compute 4 suffix bytes that force `CRC32(forged_msg || suffix || secret) == target_sig`. The linearity of CRC32 means the suffix computation is deterministic and instant.

```python
import struct, binascii

def crc32_forge(data, target_crc):
    """Append 4 bytes to data so CRC32(data + suffix) == target_crc"""
    current = binascii.crc32(data) & 0xFFFFFFFF
    # CRC32 polynomial table lookup to find suffix bytes
    # that transform current CRC into target_crc
    suffix = b''
    crc = target_crc ^ 0xFFFFFFFF
    for _ in range(4):
        byte = (crc & 0xFF)
        crc = (crc >> 8)
        suffix = bytes([byte]) + suffix
    return data + suffix  # Simplified — full implementation requires polynomial division
```

**When to use:** Any protocol using CRC32 as a message authentication code (MAC). CRC32 is a checksum, not a cryptographic hash — it provides no integrity guarantees against adversarial modification.
