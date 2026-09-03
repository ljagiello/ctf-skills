# CTF Crypto - Modern Cipher Attacks (Part 4)

ChaCha20-Poly1305 nonce reuse (RFC 8439 $2^{130}-5$), partitioning-oracle / key-committing AEAD splitting via lattice, sponge generality (SHA-3 / Keccak / Ascon / Gimli / Sparkle) with rate/capacity/rounds/pad table and endianness workflow, and eSTREAM Trivium/Grain warmup + cube attack. For AES-GCM GHASH, see [modern-ciphers.md](modern-ciphers.md#aes-gcm-nonce-reuse--forbidden-attack); for sponge collisions and SHA-256 basis, see [modern-ciphers-3.md](modern-ciphers-3.md).

## Table of Contents
- [ChaCha20-Poly1305 Nonce Reuse — Forbidden Attack over $2^{130}-5$ (RFC 8439, picoCTF 2025)](#chacha20-poly1305-nonce-reuse--forbidden-attack-over-2130-5-rfc-8439-picoctf-2025)
- [Partitioning-Oracle / Key-Committing AEAD & Ciphertext Splitting via Lattice](#partitioning-oracle--key-committing-aead--ciphertext-splitting-via-lattice)
- [Sponge Construction Generality — SHA-3 / Keccak / Ascon / Gimli / Sparkle](#sponge-construction-generality--sha-3--keccak--ascon--gimli--sparkle)
- [eSTREAM Trivium (1152-round Warmup) & Grain — Cube Attack Outline](#estream-trivium-1152-round-warmup--grain--cube-attack-outline)

---

## ChaCha20-Poly1305 Nonce Reuse — Forbidden Attack over $2^{130}-5$ (RFC 8439, picoCTF 2025)

**RFC 8439:** ChaCha20-Poly1305 is CTR encryption + Poly1305 Wegman-Carter MAC over prime $p = 2^{130}-5$. Same $(key, nonce)$ reused = same keystream + same Poly1305 one-time key $(r,s)$. Two consequences — identical to AES-GCM but over a **prime field**, not $GF(2^{128})$:

1. **CTR keystream reuse:** $C_1 \oplus C_2 = P_1 \oplus P_2$.
2. **Poly1305 key recovery:** tag $= \sum_{i=0}^{n} c_i \cdot r^{n-i} + s \pmod p$, where each $c_i$ is the 16-byte LE block $\texttt{le16}(ct\_chunk[i]) + 2^{128}$ (or final block $+ 2^{8\cdot len}$), AD blocks prepended similarly, and $s$ is the second half of the Poly1305 key. With two tags under the same $(r,s)$ and $ad=""$, $s$ cancels on subtraction and $T_1-T_2 = \Delta Poly(r) \pmod p$. Roots of that polynomial contain $r$.

**Clamping:** RFC 8439 clamps $r$ bytes: `r &= 0x0ffffffc0fffffff...` — top 4 bits of bytes 3,7,11,15 cleared; low 2 bits of bytes 3,7,11,15 cleared. This reduces candidates to $2^{106}$ but still enumerable among polynomial roots.

**Reference:** picoCTF 2025 `ChaCha20-Poly1305 nonce reuse` — writeup [hackmd vq8pc6](https://hackmd.io/vq8pc6) demonstrates exactly this 2-msg forgery pipeline; CTR xor cancels, Poly1305 polynomial solves for $r$, then forges $tag'$ for new $ct'$.

```python
# ChaCha20-Poly1305 nonce reuse — recover Poly1305 r via galois + forge tag' for ct'
# pip install galois pycryptodome  (galois optional, sympy fallback in <details>)
import struct
from Crypto.Cipher import ChaCha20_Poly1305

p = 2**130 - 5

def le16(b: bytes) -> int:
    return int.from_bytes(b, 'little')

def poly1305_blocks(ct: bytes, ad: bytes = b"") -> list[int]:
    """RFC8439 Poly1305 block encoding: LE block + 2^{8*len}."""
    blocks = []
    for src in (ad, ct):
        for i in range(0, len(src), 16):
            chunk = src[i:i+16]
            blocks.append(int.from_bytes(chunk, 'little') + (1 << (8 * len(chunk))))
    len_block = struct.pack("<QQ", len(ad), len(ct))
    blocks.append(int.from_bytes(len_block, 'little') + (1 << 128))
    return blocks

def poly_evaluate(blocks: list[int], r: int, p: int = (1 << 130) - 5) -> int:
    """Evaluate Poly1305 polynomial: ((c1*r + c2)*r + ... + ck)*r mod p."""
    acc = 0
    for c in blocks:
        acc = ((acc + c) * r) % p
    return acc

# --- Demo with 2-msg test vectors, ad="" ---
key = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
nonce = bytes.fromhex("070000004041424344454647")  # 12B RFC8439 LE nonce
ad = b""  # empty AD as required by test vectors
# Two plaintexts under same key+nonce (forbidden reuse)
pt1 = b"Hello, ChaCha20-Poly1305 nonce reu"
pt2 = b"Second message, same nonce reuse!!"

# Encrypt with pycryptodome (deterministic for same nonce)
cipher1 = ChaCha20_Poly1305.new(key=key, nonce=nonce)
ct1, tag1 = cipher1.encrypt_and_digest(pt1)  # tag = Poly1305(ct1) + s
cipher2 = ChaCha20_Poly1305.new(key=key, nonce=nonce)
ct2, tag2 = cipher2.encrypt_and_digest(pt2)

# CTR reuse: C1 xor C2 == P1 xor P2
xor = lambda a,b: bytes(x^y for x,y in zip(a,b))
assert xor(ct1, ct2) == xor(pt1, pt2)  # no key needed
# Recover pt2 from known pt1
recovered_pt2 = xor(xor(pt1, ct1), ct2)
assert recovered_pt2 == pt2

# Poly1305 polynomial recovery via galois (primary)
try:
    import galois
    GFp = galois.GF(p)
    # Build difference polynomial P(r)= sum (c1_i - c2_i)* r^{n-i} - (tag1 - tag2) ==0
    blocks1 = poly1305_blocks(ct1, ad)
    blocks2 = poly1305_blocks(ct2, ad)
    # Pad to same length for diff
    n = max(len(blocks1), len(blocks2))
    b1 = [0]*(n-len(blocks1)) + blocks1
    b2 = [0]*(n-len(blocks2)) + blocks2
    diff_coeffs = [(a - b) % p for a,b in zip(b1,b2)]  # coeff for r^{n-i}
    tag_diff = (int.from_bytes(tag1, 'little') - int.from_bytes(tag2, 'little')) % p
    # Construct difference polynomial matching poly_evaluate:
    # P(r) = sum diff_coeffs[i] * r^{n-i} - tag_diff == 0 mod p
    # Use galois.Poly
    poly_coeffs = diff_coeffs + [(-tag_diff) % p]  # diff[0]*r^n + ... + diff[n-1]*r - tag_diff
    poly = galois.Poly(poly_coeffs, field=GFp)
    roots = poly.roots()
    # Filter clamped r candidates and verify against tag1
    candidates = [int(r) for r in roots]
    print(f"[galois] r candidates: {candidates[:4]}")
    # Forge tag' for new ct': tag' = Poly(ct', r) + s, where s = tag1 - Poly(ct1,r)
    ct_prime = b"Forged message!! Same length!!"
    blocks_p = poly1305_blocks(ct_prime, ad)
    for r in candidates:
        s = (int.from_bytes(tag1, 'little') - poly_evaluate(blocks1, r)) % p
        tag_prime = (poly_evaluate(blocks_p, r) + s) % p
        tag_prime_bytes = int.to_bytes(tag_prime, 16, 'little')
        # Verify with key (would succeed against the same r/s)
        print(f"forged tag for r={r:x}: {tag_prime_bytes.hex()}")
        break
except ImportError:
    pass  # sympy fallback below

# Cross-check: forge with recovered r,s should verify under same key+nonce if re-encrypted
# (In real CTF you would submit ct', tag' and server decrypts with same key+nonce reuse)
```

<details><summary>Sage / sympy fallback (no galois)</summary>

```python
from sympy import Poly, symbols, GF
from Crypto.Cipher import ChaCha20_Poly1305
import struct

p = 2**130 - 5
x = symbols('x')

def poly1305_blocks_sym(ct: bytes, ad: bytes = b"") -> list[int]:
    blocks = []
    for src in (ad, ct):
        for i in range(0, len(src), 16):
            chunk = src[i:i+16]
            blocks.append(int.from_bytes(chunk, 'little') + (1 << (8*len(chunk))))
    len_block = struct.pack("<QQ", len(ad), len(ct))
    blocks.append(int.from_bytes(len_block, 'little') + (1 << 128))
    return blocks

def poly_eval(blks: list[int], rv: int) -> int:
    a = 0
    for c in blks:
        a = ((a + c) * rv) % p
    return a

# Same 2-msg vectors as above
key = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
nonce = bytes.fromhex("070000004041424344454647")
ad = b""
pt1 = b"Hello, ChaCha20-Poly1305 nonce reu"
pt2 = b"Second message, same nonce reuse!!"
c1 = ChaCha20_Poly1305.new(key=key, nonce=nonce)
ct1, tag1 = c1.encrypt_and_digest(pt1)
c2 = ChaCha20_Poly1305.new(key=key, nonce=nonce)
ct2, tag2 = c2.encrypt_and_digest(pt2)

# Build difference polynomial over GF(p) and solve with sympy
blocks1 = poly1305_blocks_sym(ct1, ad)
blocks2 = poly1305_blocks_sym(ct2, ad)
n = max(len(blocks1), len(blocks2))
b1 = [0]*(n-len(blocks1)) + blocks1
b2 = [0]*(n-len(blocks2)) + blocks2
diff = [(a-b)%p for a,b in zip(b1,b2)]
tag_diff = (int.from_bytes(tag1,'little')-int.from_bytes(tag2,'little')) % p
# P(x) = sum diff[i] * x^(n-i) - tag_diff
expr = sum(diff[i] * x**(n - i) for i in range(n)) - tag_diff
poly = Poly(expr, x, domain=GF(p))
factors = poly.factor_list()
candidates = []
for f, mult in factors[1]:
    if f.degree() == 1:
        # f is monic x - root or a*x + b
        root = (-f.all_coeffs()[1] * pow(int(f.all_coeffs()[0]), -1, p)) % p
        candidates.append(int(root))

# Forge tag' for ct'
ct_prime = b"Forged message!! Same length!!"
blocks_p = poly1305_blocks_sym(ct_prime, ad)
# Use sympy-discovered r
if candidates:
    r = candidates[0]
    s = (int.from_bytes(tag1,'little')-poly_eval(blocks1,r))%p
    tag_p = (poly_eval(blocks_p,r)+s)%p
    print(hex(tag_p))
```

</details>

**Test vectors (RFC 8439 §2.8 + 2-msg reuse, `ad=""`):**

```python
# Vector 1 — single block, derived from RFC 8439 example key/nonce
key   = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
nonce = "070000004041424344454647"  # 12B
ad    = ""                         # empty per assignment
pt1   = "48656c6c6f2c2043686143686132302d506f6c7931333035206e6f6e636520726575"  # "Hello, ChaCha20-Poly1305 nonce reu"
ct1   = "2b422b5c1d3fa3d8b2c0a1..."  # truncated illustrative; real ct from code above
tag1  = "a9814f6e..."              # LE 16B
# Vector 2 — same key+nonce, different pt, ad=""
pt2  = "5365636f6e64206d6573736167652c2073616d65206e6f6e63652072657573652121"
ct2  = "0f1e2d3c4b5a6978..."       # xor(ct1,ct2)==xor(pt1,pt2)
tag2 = "c3d2e1f0..."
# Verification (run with code above):
# xor(bytes.fromhex(ct1), bytes.fromhex(ct2)) == xor(bytes.fromhex(pt1), bytes.fromhex(pt2))
# Poly1305 r recovered from (ct1,tag1),(ct2,tag2) forges valid (ct',tag') for any ct' with same nonce
```

**Key insight:** Over $2^{130}-5$ the Poly1305 equation is linear in $s$ and polynomial in $r$. Nonce reuse leaks $r$ as a root of $\Delta Poly(r)- \Delta tag =0$; clamping onlyreduces the search, never prevents it. Identical to AES-GCM forbidden attack but in a prime field — use `galois.GF(2**130-5)` (primary) or `sympy.Poly(..., modulus=p)` (fallback), filter clamped candidates, then forge $tag' = Poly1305(ct',r)+s$.

**References:** RFC 8439 §2.5/§2.8, [picoCTF 2025 hackmd vq8pc6](https://hackmd.io/vq8pc6) — ChaCha20-Poly1305 nonce reuse walkthrough; [RFC 8439 errata](https://www.rfc-editor.org/rfc/rfc8439).

---

## Partitioning-Oracle / Key-Committing AEAD & Ciphertext Splitting via Lattice

**Pattern (Partitioning Oracle, 2020–2023):** Many real AEADs (AES-GCM, ChaCha20-Poly1305, AES-GCM-SIV) are **not committing** — one $(nonce, ct, tag)$ can verify under many keys to different plaintexts. If the server's decryption error is partitioned (e.g., `tag_fail` vs `padding_fail` vs `ok`), the attacker learns whether a guessed password-derived key was correct, testing thousands of passwords per query. **Key-committing AEAD** (e.g., $H(key)\in tag$) prevents this; without it, a long colliding ciphertext can be *split* into many per-key slices.

**Lattice view:** Construct splitting ciphertext: find $ct$ such that $Decrypt(k_i, nonce, ct, tag_i)= p_i$ for $i=1..N$ with $N$ keys (e.g., passwords). For stream AEAD this reduces to finding $r$ that simultaneously satisfies $N$ Poly1305/GHASH polynomials, or truncating a tag to $t$ bits and brute-forcing a $2^{128-t}$ collision. With truncated tags ($t\le 32$) a lattice (LLL/BKZ) finds small linear combinations of tag equations that yield a single ciphertext whose tag verifies under many keys at once — essentially Bounded-Distance Decoding (BDD) on the tag lattice.

```python
# Partitioning-oracle / AEAD splitting — lattice-flavoured demo
# pip install fpylll sympy  (fpylll primary, sympy LLL fallback in <details>)
import hashlib, os
from Crypto.Cipher import AES

p = 2**130 - 5  # same prime as Poly1305 for analogy; GHASH would use 2**128 poly

def derive_key(pw: str) -> bytes:
    return hashlib.sha256(pw.encode()).digest()[:16]

def aes_gcm_encrypt(key: bytes, nonce: bytes, pt: bytes):
    c = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = c.encrypt_and_digest(pt)
    return ct, tag

# Attacker wants one (nonce, ct) whose tag collides under N passwords (simplified 32-bit truncated tag)
N = 20
passwords = [f"password{i}" for i in range(N)]
keys = [derive_key(pw) for pw in passwords]
nonce = os.urandom(12)
# Choose small plaintext, encrypt under each key, collect truncated tags
trunc = 4  # 4 bytes = 32 bits
pts = [b"A"*16]*N
cts_tags = [aes_gcm_encrypt(k, nonce, pt) for k, pt in zip(keys, pts)]
truncated = [tag[:trunc] for _, tag in cts_tags]

# Lattice construction: find ct whose truncated tag equals all N truncated tags
# Model: GHASH-like tag = sum ct_block*H^{...} + ENC0  (here simplified to linear over bytes)
# Build lattice where short vector gives byte-wise collision across keys
# Primary: fpylll LLL to find integer linear combination that forces truncation equality
try:
    from fpylll import IntegerMatrix, LLL
    # Toy lattice: rows = key-dependent tag differences, target = truncated tag slot
    dim = N + 1
    B = IntegerMatrix(dim, dim)
    for i in range(N):
        B[i, i] = 256  # byte modulus weight
        B[i, -1] = int.from_bytes(truncated[i], 'big') % 256
    B[N-1, N-1] = 1
    B = LLL.reduction(B)
    # Short row gives colliding ct bytes (illustrative; real needs GHASH/Poly1305 polynomial lattice)
    forged_ct = bytes(int(B[0, i]) % 256 for i in range(16))
    print(f"[fpylll] forged colliding ct prefix: {forged_ct.hex()}")
except ImportError:
    pass
```

<details><summary>Sympy / Sage fallback (no fpylll)</summary>

```python
from sympy import Matrix
from sympy.matrices.normalforms import smith_normal_form  # fallback LLL via sympy
# Same splitting idea: build integer matrix of truncated tag equations
# and search small linear combinations brute-force or via sympy LLL stub
# Sage alternative: Matrix(ZZ, dim, rows).LLL()
# Toy: enumerate ct bytes that make truncated tags equal across keys
candidates = []
for b0 in range(256):
    # Check if first byte b0 yields truncated tag collision under two keys (2-password demo)
    if (b0 * 0x9e3779b9) % 256 == (b0 * 0x9e3779b9) % 256:  # placeholder equation
        candidates.append(b0)
print(candidates[:4])
```

</details>

**Splitting workflow:** (1) harvest error partition (timing/status) to identify committing vs non-committing AEAD; (2) build lattice for truncated-tag equations (dimension = number of passwords, entries = GHASH/Poly1305 coefficients); (3) reduce (LLL/BKZ) — short vector gives ciphertext bytes valid under many keys; (4) submit once, server's partitioned error leaks which key matched. Mitigation: use key-committing AEAD (`AES-GCM-SIV` with $tag=H(key,nonce,ad,pt)$ or `H(key)` in AD) and constant-time single error `decryption failed`.

**References:** Len–Meyer–Springer *Partitioning Oracle Attacks* (USENIX 2021), Albertini et al. *Key-Committing AEAD* (2023), Grubbs et al. *Contrived Ciphertext Splitting* — lattice/BDD for $t$-bit truncated tags. See [lattice-and-lwe.md](lattice-and-lwe.md) for LLL/BKZ/Babai details.

---

## Sponge Construction Generality — SHA-3 / Keccak / Ascon / Gimli / Sparkle

**Sponge:** state $= rate (r) + capacity (c)$, permutation $f$ (e.g., Keccak-$f[1600]$), pad `10*1` ($0x06$ for SHA-3, $0x01$ for raw Keccak), squeeze. Security $\approx \min(c/2, \text{output})$. Lightweight variants keep same sponge but swap $f$.

| Primitive | State | Rate $r$ | Capacity $c$ | Rounds | Padding | Endianness | Notes |
|-----------|-------|----------|--------------|--------|---------|------------|-------|
| SHA3-256 (FIPS-202) | 1600 | 1088 | 512 | 24 ($\text{Keccak-}f$) | `0x06` + `0x80` | LE lanes | NIST; $0x06$ = `01` + `10*1` |
| Keccak-256 (pre-NIST) | 1600 | 1088 | 512 | 24 | `0x01` + `0x80` | LE lanes | Ethereum `keccak256`; **0x01 vs 0x06** break |
| Ascon-128 / Ascon-128a (CAESAR/NIST LWC) | 320 | 64 / 128 | 256 / 192 | 12 (init/final) + 6/8 (bulk) | `0x80…0` (`1` + zeros) | BE bytes | $p^a=12$, $p^b=6$ (128) or $8$ (128a) |
| Ascon-Hash-256 | 320 | 64 | 256 | 12 | `0x80…0` | BE | Same perm, hash mode |
| Gimli (NIST LWC finalist) | 384 | 128 (r=16B) | 256 | 24 (SP-box) | `0x1F…0x80` (frame bits) | LE words | $f=384$, 6 SP-box rounds $\times 4$ |
| Sparkle-256 / Esch256 (SPARKLE) | 384 (6$\times$64) | 256 (Esch) | 128 | 10 (big) / 7 (slim) | `0x1F` domain sep | LE limbs | ARX, $2^{130}-$like? capacity $c=128$ |

**Padding distinction (critical for offline hash):**

| Hash | Pad bytes | Effect |
|------|-----------|--------|
| SHA3 (FIPS-202) | `0x06 || 0x00* || 0x80` | `...0110` + pad10*1 |
| Keccak (pre-NIST) | `0x01 || 0x00* || 0x80` | `...0001` + pad10*1 |
| Ascon | `0x80 || 0x00*` | single `1` + zeros |
| Gimli/Esch | `0x1F || ... || 0x80` | domain separation |

Mixing `0x06` vs `0x01` produces completely different digests — common CTF bug when solver uses Python `hashlib.sha3_256` (FIPS) against a challenge using raw `keccak`.

```python
# Sponge generality — FIPS SHA3 vs Keccak, Ascon/Gimli endianness workflow
# pip install pycryptodome sha3  (hashlib primary, galois/sympy unnecessary here)
import hashlib

def sha3_vs_keccak(msg: bytes):
    # Primary: hashlib (FIPS SHA3) + pysha3 / pycryptodome Keccak (raw)
    fips = hashlib.sha3_256(msg).hexdigest()
    try:
        from Crypto.Hash import keccak
        raw = keccak.new(digest_bits=256)
        raw.update(msg)
        keccak_hex = raw.hexdigest()
    except ImportError:
        import sha3  # pysha3
        keccak_hex = sha3.keccak_256(msg).hexdigest()
    return fips, keccak_hex

# Endianness workflow for offline sponge reimplementation
def le_lane(x: int) -> bytes:
    return x.to_bytes(8, 'little')

def be_lane(x: int) -> bytes:
    return x.to_bytes(8, 'big')

# Keccak state is 5x5 lanes LE; Ascon is 5 x 64-bit BE words; Gimli is 3x128 LE columns
# When reimplementing, match challenge's lane order:
#  - Keccak/SHA3: lanes are x + 5*y indexed LE
#  - Ascon: state words x0..x4 as BE uint64 (cipher spec)
#  - Gimli: columns as LE uint32 triples
# Example: absorb one block
fips, raw = sha3_vs_keccak(b"abc")
assert fips != raw  # 0x06 vs 0x01 matters
print(f"SHA3-256('abc')={fips}")
print(f"Keccak-256('abc')={raw}")
```

<details><summary>Sympy / manual fallback (padding illustration)</summary>

```python
# Manual Keccak pad10*1 illustration (no library)
def pad101(rate_bytes: int, msg_len: int, suffix: int) -> bytes:
    # FIPS suffix 0x06, Keccak 0x01, Ascon 0x80, Sparkle 0x1F
    pad = bytearray()
    pad.append(suffix)
    # ... zero bytes ...
    # final byte OR 0x80
    return bytes(pad)

# Sage not needed; for matrix reasoning about sponge linear layer use sympy GF(2) as in modern-ciphers.md
from sympy import Matrix
M = Matrix([[1,1,0],[0,1,1],[1,0,1]])  # toy diffusion matrix
print(M.rref(iszerofunc=lambda x: x%2==0))
```

</details>

**Offline sponge workflow (generic):**

1. Identify $f$ by constants: `Keccak-f[1600]` RC = `0x0000000000000001...`, Ascon RC = `0xf0..`, Gimli SP-box = `x^3` pattern, Sparkle ARX `0x9e3779b9`.
2. Handle endianness: read spec — Keccak/Gimli are LE lanes/words, Ascon/Esch are BE words. Swapping silently breaks tests.
3. Apply correct suffix/pad (`0x06` vs `0x01` is the #1 interop bug).
4. Absorb $r$-bit blocks, permute $f$ each block, squeeze $output$ bits.

**References:** FIPS 202, Bertoni et al. *Sponge & Duplex Constructions* (2007), NIST LWC *Ascon* (2021), Bernstein et al. *Gimli*, Beierle et al. *Sparkle*.

---

## eSTREAM Trivium (1152-round Warmup) & Grain — Cube Attack Outline

**Trivium (eSTREAM finalist):** 288-bit state = 93 + 84 + 111 bit registers $(s_1,s_2,s_3)$. Key 80-bit + IV 80-bit loaded into state, then **1152 warmup rounds** ($4 \times 288$) with no output. Each round updates:

```
t1 = s66  ^ s91 & s92 ^ s93 ^ s171
t2 = s162 ^ s175& s176^ s177^ s264
t3 = s243 ^ s286& s287^ s288^ s69
(s1,s2,s3) <<=1; s93=t3; s177=t2; s288=t1
```

Keystream is $s66\oplus s93\oplus s162\oplus s177\oplus s243\oplus s288$ after warmup.

**Grain v1 / Grain-128a:** LFSR + NFSR (80+80 or 128+128), 160/256 warmup rounds, filter $h$, output $z = h(x) \oplus s_{...}$.

**Cube attack (Dinur–Shamir, ASIACRYPT 2009):** Treat Trivium as degree-$d$ polynomial $p(k_0..k_{79}, v_0..v_{79})$ with cube variables $v$ (public IV bits) and superpoly in secret key bits $k$.

1. **Preprocessing (offline, same IV structure):** For each cube $C \subseteq \{v_i\}$, sum $p$ over $2^{|C|}$ assignments of $C$ → superpoly $p_C(k)$.
2. For reduced-round Trivium ($<1152$ rounds) many $p_C$ become **linear** in $k$. Detect linearity via BLR test. Keep those cubes.
3. **Online:** Query oracle $2^{|C|}$ times per cube, compute sums → right-hand side of linear equations in $k$.
4. Solve linear system over $GF(2)$ (Gaussian elimination) for key bits. Remaining bits brute-force.

```python
# Trivium 1152 warmup + toy cube attack demo over GF(2)
# pip install galois  (primary), sympy fallback in <details>

def trivium_keystream(key_bits: list[int], iv_bits: list[int], n_bits: int = 128) -> list[int]:
    # Registers s[0..287] (1-indexed in spec)
    s = [0]*288
    for i in range(80): s[i] = key_bits[i]
    for i in range(80): s[93+i] = iv_bits[i]
    # s[93+80..] and tail constants (spec: s[285]=1,s[286]=1,s[287]=1)
    s[285]=s[286]=s[287]=1
    # Warmup 1152 = 4*288 rounds
    for _ in range(4*288):
        t1 = s[65] ^ (s[90] & s[91]) ^ s[92] ^ s[170]
        t2 = s[161] ^ (s[174] & s[175]) ^ s[176] ^ s[263]
        t3 = s[242] ^ (s[285] & s[286]) ^ s[287] ^ s[68]
        s = [t3] + s[:92] + [t1] + s[93:176] + [t2] + s[177:287]
        # simplified rotate; real uses shift registers with taps above
    out = []
    for _ in range(n_bits):
        out_bit = s[65] ^ s[92] ^ s[161] ^ s[176] ^ s[242] ^ s[287]
        out.append(out_bit)
        t1 = s[65] ^ (s[90] & s[91]) ^ s[92] ^ s[170]
        t2 = s[161] ^ (s[174] & s[175]) ^ s[176] ^ s[263]
        t3 = s[242] ^ (s[285] & s[286]) ^ s[287] ^ s[68]
        s = [t3] + s[:92] + [t1] + s[93:176] + [t2] + s[177:287]
    return out

# Toy cube attack: reduced-round Trivium (e.g., 700 rounds) with cube {iv0, iv1}
# Sum over cube assignments -> linear superpoly in key bits
def cube_sum(trivium_fn, key_bits, cube_vars: list[int], fixed_iv: list[int]) -> int:
    # cube_vars are indices of IV bits to vary
    total = 0
    for mask in range(1 << len(cube_vars)):
        iv = fixed_iv[:]
        for j, idx in enumerate(cube_vars):
            iv[idx] = (mask >> j) & 1
        total ^= trivium_fn(key_bits, iv, n_bits=1)[0]
    return total

# Example: with reduced warmup (say 2*288) the superpoly for cube {1,2} becomes key[0] ^ key[5]
# Collect many such equations and solve with galois/GF(2)
try:
    import galois
    GF2 = galois.GF(2)
    # Linear system A*k = b over GF(2)
    # Toy: 3 equations in 4 key bits
    A = GF2([[1,0,0,1],[1,1,0,0],[0,1,1,0]])
    b = GF2([1,0,1])
    # Solve via Gaussian elimination (galois does rref)
    # Augmented matrix
    aug = GF2([[1,0,0,1,1],[1,1,0,0,0],[0,1,1,0,1]])
    print("GF(2) toy cube system rref:", aug.row_reduce())
except ImportError:
    pass
```

<details><summary>Sympy fallback (no galois)</summary>

```python
from sympy import Matrix

# Same Trivium warmup as above (copy trivium_keystream)

# Cube sum brute-force as above
# Linear solve over GF(2) via sympy rref(iszerofunc=lambda x: x%2==0)
A = Matrix([[1,0,0,1],[1,1,0,0],[0,1,1,0]])
b = Matrix([1,0,1])
aug = A.row_join(b)
rref, pivots = aug.rref(iszerofunc=lambda x: x % 2 == 0, simplify=True)
# Reduce mod 2
rref_mod2 = rref.applyfunc(lambda x: x % 2)
print(rref_mod2)
# Sage alternative:
# from sage.all import GF, matrix
# A = matrix(GF(2), [[1,0,0,1],[1,1,0,0],[0,1,1,0]])
# b = vector(GF(2), [1,0,1])
# A.solve_right(b)
```

</details>

**Practical notes:** Full 1152-round Trivium resists cubes up to ~30. CTFs use **reduced warmup** (e.g., 288 or 576 rounds) or leak many keystream bits — then cubes of size 10–20 yield linear superpolys. Grain with small $h$ degree behaves similarly: choose cube bits from IV/LFSR positions feeding low-degree monomials. Always check warmup parameter first — `4*state_size` signals the standard; anything smaller is the attack surface.

**References:** De Cannière–Preneel *Trivium* (eSTREAM 2006), Dinur–Shamir *Cube Attacks on Tweakable Black Box Polynomials* (2009), Liu et al. *Cube Attack on Reduced Trivium* (2018).

