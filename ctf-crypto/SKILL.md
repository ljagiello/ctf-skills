---
name: ctf-crypto
description: Cryptography techniques for CTF challenges. Use when attacking encryption, hashing, ZKP, signatures, or mathematical crypto problems.
user-invocable: false
allowed-tools: ["Bash", "Read", "Write", "Edit", "Glob", "Grep", "Task", "WebFetch", "WebSearch"]
---

# CTF Cryptography

Quick reference for crypto challenges. For detailed techniques, see supporting files.

## Additional Resources

- [prng.md](prng.md) - PRNG attacks (Mersenne Twister, LCG, time-based seeds, password cracking)
- [historical.md](historical.md) - Historical ciphers (Lorenz SZ40/42)
- [advanced-math.md](advanced-math.md) - Advanced mathematical attacks (isogenies, Pohlig-Hellman, LLL, Coppersmith)

---

## ZKP Attacks

- Look for information leakage in proofs
- If proving IMPOSSIBLE problem (e.g., 3-coloring K4), you must cheat
- Find hash collisions to commit to one value but reveal another
- PRNG state recovery: salts generated from seeded PRNG can be predicted
- Small domain brute force: if you know `commit(i) = sha256(salt(i), color(i))` and have salt, brute all colors

## Graph 3-Coloring

```python
import networkx as nx
nx.coloring.greedy_color(G, strategy='saturation_largest_first')
```

## CBC-MAC vs OFB-MAC Vulnerability

- OFB mode creates a keystream that can be XORed for signature forgery
- If you have signature for known plaintext P1, forge for P2:
  ```
  new_sig = known_sig XOR block2_of_P1 XOR block2_of_P2
  ```
- Don't forget PKCS#7 padding in calculations!
- Small bruteforce space? Just try all combinations (e.g., 100 for 2 unknown digits)

## Weak Hash Functions

- Linear permutations (only XOR, rotations) are algebraically attackable
- Build transformation matrix and solve over GF(2)

## GF(2) Gaussian Elimination

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

## RSA Attacks

- Small e with small message: take eth root
- Common modulus: extended GCD attack
- Wiener's attack: small d
- Fermat factorization: p and q close together
- Pollard's p-1: smooth p-1
- Hastad's broadcast attack: same message, multiple e=3 encryptions

## RSA with Consecutive Primes

**Pattern (Loopy Primes):** q = next_prime(p), making p ≈ q ≈ sqrt(N).

**Factorization:** Find first prime below sqrt(N):
```python
from sympy import nextprime, prevprime, isqrt

root = isqrt(n)
p = prevprime(root + 1)
while n % p != 0:
    p = prevprime(p)
q = n // p
```

**Multi-layer variant:** 1024 nested RSA encryptions, each with consecutive primes of increasing bit size. Decrypt in reverse order.

## Multi-Prime RSA

When N is product of many small primes (not just p*q):
```python
# Factor N (easier when many primes)
from sympy import factorint
factors = factorint(n)  # Returns {p1: e1, p2: e2, ...}

# Compute phi using all factors
phi = 1
for p, e in factors.items():
    phi *= (p - 1) * (p ** (e - 1))

d = pow(e, -1, phi)
plaintext = pow(ciphertext, d, n)
```

## AES Attacks

- ECB mode: block shuffling, byte-at-a-time oracle
- CBC bit flipping: modify ciphertext to change plaintext
- Padding oracle: decrypt without key

## AES-CFB-8 Static IV State Forging

**Pattern (Cleverly Forging Breaks):** AES-CFB with 8-bit feedback and reused IV allows state reconstruction.

**Key insight:** After encrypting 16 known bytes, the AES internal shift register state is fully determined by those ciphertext bytes. Forge new ciphertexts by continuing encryption from known state.

## Classic Ciphers

- Caesar: frequency analysis or brute force 26 keys
- Vigenere: Kasiski examination, index of coincidence
- Substitution: frequency analysis, known plaintext

### Vigenère Cipher

**Known Plaintext Attack (most common in CTFs):**
```python
def vigenere_decrypt(ciphertext, key):
    result = []
    key_index = 0
    for c in ciphertext:
        if c.isalpha():
            shift = ord(key[key_index % len(key)].upper()) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base - shift) % 26 + base))
            key_index += 1
        else:
            result.append(c)
    return ''.join(result)

def derive_key(ciphertext, plaintext):
    """Derive key from known plaintext (e.g., flag format CCOI26{)"""
    key = []
    for c, p in zip(ciphertext, plaintext):
        if c.isalpha() and p.isalpha():
            c_val = ord(c.upper()) - ord('A')
            p_val = ord(p.upper()) - ord('A')
            key.append(chr((c_val - p_val) % 26 + ord('A')))
    return ''.join(key)
```

**When standard keys don't work:**
1. Key may not repeat - could be as long as message
2. Key derived from challenge theme (character names, phrases)
3. Key may have "padding" - repeated letters (IICCHHAA instead of ICHA)
4. Try guessing plaintext words from theme, derive full key

## Elliptic Curve Attacks (General)

**Small subgroup attacks:**
- Check curve order for small factors
- Pohlig-Hellman: solve DLP in small subgroups, combine with CRT

**Invalid curve attacks:**
- If point validation missing, send points on weaker curves
- Craft points with small-order subgroups

**Singular curves:**
- If discriminant Δ = 0, curve is singular
- DLP becomes easy (maps to additive/multiplicative group)

**Smart's attack:**
- For anomalous curves (order = field size p)
- Lifts to p-adics, solves DLP in O(1)

```python
# SageMath ECC basics
E = EllipticCurve(GF(p), [a, b])
G = E.gens()[0]  # generator
order = E.order()
```

## ECC Fault Injection

**Pattern (Faulty Curves):** Bit flip during ECC computation reveals private key bits.

**Attack:** Compare correct vs faulty ciphertext, recover key bit-by-bit:
```python
# For each key bit position:
# If fault at bit i changes output → key bit i affects computation
# Binary distinguisher: faulty_output == correct_output → bit is 0
```

## Useful Tools

```bash
# Python setup
pip install pycryptodome z3-solver sympy gmpy2

# SageMath for advanced math (required for ECC)
sage -python script.py
```

## Common Patterns

```python
from Crypto.Util.number import *

# RSA basics
n = p * q
phi = (p-1) * (q-1)
d = inverse(e, phi)
m = pow(c, d, n)

# XOR
from pwn import xor
xor(ct, key)
```

## Z3 SMT Solver

Z3 solves constraint satisfaction - useful when crypto reduces to finding values satisfying conditions.

**Basic usage:**
```python
from z3 import *

# Boolean variables (for bit-level problems)
bits = [Bool(f'b{i}') for i in range(64)]

# Integer/bitvector variables
x = BitVec('x', 32)  # 32-bit bitvector
y = Int('y')         # arbitrary precision int

solver = Solver()
solver.add(x ^ 0xdeadbeef == 0x12345678)
solver.add(y > 100, y < 200)

if solver.check() == sat:
    model = solver.model()
    print(model.eval(x))
```

**BPF/SECCOMP filter solving:**

When challenges use BPF bytecode for flag validation (e.g., custom syscall handlers):

```python
from z3 import *

# Model flag as array of 4-byte chunks (how BPF sees it)
flag = [BitVec(f'f{i}', 32) for i in range(14)]
s = Solver()

# Constraint: printable ASCII
for f in flag:
    for byte in range(4):
        b = (f >> (byte * 8)) & 0xff
        s.add(b >= 0x20, b < 0x7f)

# Extract constraints from BPF dump (seccomp-tools dump ./binary)
mem = [BitVec(f'm{i}', 32) for i in range(16)]

# Example BPF constraint reconstruction
s.add(mem[0] == flag[0])
s.add(mem[1] == mem[0] ^ flag[1])
s.add(mem[4] == mem[0] + mem[1] + mem[2] + mem[3])
s.add(mem[8] == 4127179254)  # From BPF if statement

if s.check() == sat:
    m = s.model()
    flag_bytes = b''
    for f in flag:
        val = m[f].as_long()
        flag_bytes += val.to_bytes(4, 'little')
    print(flag_bytes.decode())
```

**Converting bits to flag:**
```python
from Crypto.Util.number import long_to_bytes

if solver.check() == sat:
    model = solver.model()
    flag_bits = ''.join('1' if model.eval(b) else '0' for b in bits)
    print(long_to_bytes(int(flag_bits, 2)))
```

**When to use Z3:**
- Type system constraints (OCaml GADTs, Haskell types)
- Custom hash/cipher with algebraic structure
- Equation systems over finite fields
- Boolean satisfiability encoded in challenge
- Constraint propagation puzzles

## Cascade XOR (First-Byte Brute Force)

**Pattern (Shifty XOR):** Each byte XORed with previous ciphertext byte.

```python
# c[i] = p[i] ^ c[i-1] (or similar cascade)
# Brute force first byte, rest follows deterministically
for first_byte in range(256):
    flag = [first_byte]
    for i in range(1, len(ct)):
        flag.append(ct[i] ^ flag[i-1])
    if all(32 <= b < 127 for b in flag):
        print(bytes(flag))
```

## ECB Pattern Leakage on Images

**Pattern (Electronic Christmas Book):** AES-ECB on BMP/image data preserves visual patterns.

**Exploitation:** Identical plaintext blocks produce identical ciphertext blocks, revealing image structure even when encrypted. Rearrange or identify patterns visually.

## Padding Oracle Attack

**Pattern (The Seer):** Server reveals whether decrypted padding is valid.

**Byte-by-byte decryption:**
```python
def decrypt_byte(block, prev_block, position, oracle):
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

## Atbash Cipher

Simple substitution: A↔Z, B↔Y, C↔X, etc.
```python
def atbash(text):
    return ''.join(
        chr(ord('Z') - (ord(c.upper()) - ord('A'))) if c.isalpha() else c
        for c in text
    )
```

**Identification:** Challenge name hints ("Abashed" ≈ Atbash), preserves spaces/punctuation, 1-to-1 substitution.

## Substitution Cipher with Rotating Wheel

**Pattern (Wheel of Mystery):** Physical cipher wheel with inner/outer alphabets.

**Brute force all rotations:**
```python
outer = "ABCDEFGHIJKLMNOPQRSTUVWXYZ{}"
inner = "QNFUVWLEZYXPTKMR}ABJICOSDHG{"  # Given

for rotation in range(len(outer)):
    rotated = inner[rotation:] + inner[:rotation]
    mapping = {outer[i]: rotated[i] for i in range(len(outer))}
    decrypted = ''.join(mapping.get(c, c) for c in ciphertext)
    if decrypted.startswith("METACTF{"):
        print(decrypted)
```

## Non-Permutation S-box Collision Attack

**Pattern (Tetraes, Nullcon 2026):** Custom AES-like cipher with S-box collisions.

**Detection:** `len(set(sbox)) < 256` means collisions exist. Find collision pairs and their XOR delta.

**Attack:** For each key byte, try 256 plaintexts differing by delta. When `ct1 == ct2`, S-box input was in collision set. 2-way ambiguity per byte, 2^16 brute-force. Total: 4,097 oracle queries.

See [advanced-math.md](advanced-math.md) for full S-box collision analysis code.

## Polynomial CRT in GF(2)[x]

**Pattern (Going in Circles, Nullcon 2026):** `r = flag mod f` where f is random GF(2) polynomial. Collect ~20 pairs, filter coprime, CRT combine.

See [advanced-math.md](advanced-math.md) for GF(2)[x] polynomial arithmetic and CRT implementation.

## Manger's RSA Padding Oracle Attack

**Pattern (TLS, Nullcon 2026):** RSA-encrypted key with threshold oracle. Phase 1: double f until `k*f >= threshold`. Phase 2: binary search. ~128 total queries for 64-bit key.

See [advanced-math.md](advanced-math.md) for full implementation.

## Book Cipher Brute Force

**Pattern (Booking Key, Nullcon 2026):** Book cipher with "steps forward" encoding. Brute-force starting position with charset filtering reduces ~56k candidates to 3-4.

See [historical.md](historical.md) for implementation.

## Affine Cipher over Non-Prime Modulus

**Pattern (Matrixfun, Nullcon 2026):** `c = A @ p + b (mod m)` with composite m. Chosen-plaintext difference attack. For composite modulus, solve via CRT in each prime factor field separately.

See [advanced-math.md](advanced-math.md) for CRT approach and Gauss-Jordan implementation.

## Deterministic OTP with Load-Balanced Backends (Pragyan 2026)

**Pattern (DumCows):** Service encrypts data with deterministic keystream that resets per connection. Multiple backends with different keystreams behind a load balancer.

**Attack:**
1. Send known plaintext (e.g., 18 bytes of 'A'), XOR with ciphertext → recover keystream
2. XOR keystream with target ciphertext → decrypt secret
3. **Backend matching:** Must connect to same backend for keystream to match. Retry connections until patterns align.

```python
def recover_keystream(known, ciphertext):
    return bytes(k ^ c for k, c in zip(known, ciphertext))

def decrypt(keystream, target_ct):
    return bytes(k ^ c for k, c in zip(keystream, target_ct))
```

**Key insight:** When encryption is deterministic per connection with no nonce/IV, known-plaintext attack is trivial. The challenge is matching backends.

## Polynomial Hash with Trivial Root (Pragyan 2026)

**Pattern (!!Cand1esaNdCrypt0!!):** RSA signature scheme using polynomial hash `g(x,a,b) = x(x^2 + ax + b) mod P`.

**Vulnerability:** `g(0) = 0` for all parameters `a,b`. RSA signature of 0 is always 0 (`0^d mod n = 0`).

**Exploitation:** Craft message suffix so `bytes_to_long(prefix || suffix) ≡ 0 (mod P)`:
```python
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61  # 128-bit prime
# Compute required suffix value mod P
req = (-prefix_val * pow(256, suffix_len, P)) % P
# Brute-force partial bytes until all printable ASCII
while True:
    high = os.urandom(32).translate(printable_table)
    low_val = (req - int.from_bytes(high, 'big') * shift) % P
    low = low_val.to_bytes(16, 'big')
    if all(32 <= b <= 126 for b in low):
        suffix = high + low
        break
# Signature is simply 0
```

**General lesson:** Always check if hash function has trivial inputs (0, 1, -1). Factoring the polynomial often reveals these.

## XOR with Rotation: Power-of-2 Bit Isolation (Pragyan 2026)

**Pattern (R0tnoT13):** Given `S XOR ROTR(S, k)` for multiple rotation offsets k, recover S.

**Key insight:** When ALL rotation offsets are powers of 2 (2, 4, 8, 16, 32, 64), even-indexed and odd-indexed bits NEVER mix across any frame. This reduces N-bit recovery to just 2 bits of brute force.

**Algorithm:**
1. Express every bit of S in terms of two unknowns (s_0 for even bits, s_1 for odd bits) using the k=2 frame
2. Only 4 candidate states → try all, verify against all frames
3. XOR valid state with ciphertext → plaintext

## Weak XOR Verification Brute Force (Pragyan 2026)

**Pattern (Dor4_Null5):** Verification XORs all comparison bytes into a single byte instead of checking each individually.

**Vulnerability:** Any fixed response has 1/256 probability of passing. With enough interaction budget (e.g., 4919 attempts), brute-force succeeds with ~256 expected attempts.

```python
for attempt in range(3000):
    r.sendlineafter(b"prompt: ", b"00" * 8)  # Fixed zero response
    result = r.recvline()
    if b"successful" in result:
        break
```

## RSA with Restricted-Digit Primes (LACTF 2026)

**Pattern (six-seven):** RSA primes p, q composed only of digits {6, 7}, ending in 7.

**Digit-by-digit factoring from LSB:**
```python
# At each step k, we know p mod 10^k → compute q mod 10^k = n * p^{-1} mod 10^k
# Prune: only keep candidates where digit k of both p and q is in {6, 7}
candidates = [(6,), (7,)]  # p ends in 6 or 7
for k in range(1, num_digits):
    new_candidates = []
    for p_digits in candidates:
        for d in [6, 7]:
            p_val = sum(p_digits[i] * 10**i for i in range(len(p_digits))) + d * 10**k
            q_val = (n * pow(p_val, -1, 10**(k+1))) % 10**(k+1)
            q_digit_k = (q_val // 10**k) % 10
            if q_digit_k in {6, 7}:
                new_candidates.append(p_digits + (d,))
    candidates = new_candidates
```

**General lesson:** When prime digits are restricted to a small set, digit-by-digit recovery from LSB with modular arithmetic prunes exponentially. Works for any restricted character set.

## Coppersmith for Structured RSA Primes (LACTF 2026)

**Pattern (six-seven-again):** p = base + 10^k · x where base is fully known and x is small (x < N^0.25).

**Attack via SageMath:**
```python
# Construct f(x) such that f(x_secret) ≡ 0 (mod p) and thus (mod N)
# p = base + 10^k * x → x + base * (10^k)^{-1} ≡ 0 (mod p)
R.<x> = PolynomialRing(Zmod(N))
f = x + (base * inverse_mod(10**k, N)) % N
roots = f.small_roots(X=2**70, beta=0.5)  # x < N^0.25
```

**When to use:** Whenever part of a prime is known and the unknown part is small enough for Coppersmith bounds (< N^{1/e} for degree-e polynomial, approximately N^0.25 for linear).

## Clock Group DLP via Pohlig-Hellman (LACTF 2026)

**Pattern (the-clock):** Diffie-Hellman on unit circle group: x² + y² ≡ 1 (mod p).

**Key facts:**
- Group law: (x₁,y₁) · (x₂,y₂) = (x₁y₂ + y₁x₂, y₁y₂ - x₁x₂)
- **Group order = p + 1** (not p - 1!)
- Isomorphic to GF(p²)* elements of norm 1

**Attack when p+1 is smooth:**
```python
# 1. Recover p from points: gcd(x^2 + y^2 - 1) across known points
# 2. Factor p+1 into small primes
# 3. Pohlig-Hellman: solve DLP in each small subgroup, CRT combine
# 4. Compute shared secret, derive AES key (e.g., via MD5)
```

**Identification:** Challenge mentions "clock", "circle", or gives points satisfying x²+y²≡1. Always check if p+1 (not p-1) is smooth.

## Garbled Circuits: Free XOR Delta Recovery (LACTF 2026)

**Pattern (sisyphus):** Yao's garbled circuit with free XOR optimization. Circuit designed so normal evaluation only reaches one wire label, but the other is needed.

**Free XOR property:** Wire labels satisfy `W_0 ⊕ W_1 = Δ` for global secret Δ.

**Attack:** XOR three of four encrypted truth table entries to cancel AES terms:
```python
# Encrypted rows: E_i = AES(key_a_i ⊕ key_b_i, G_out_f(a,b))
# XOR of three rows where AES inputs differ by Δ causes cancellation
# Reveals Δ directly, then compute: W_1 = W_0 ⊕ Δ
```

**General lesson:** In garbled circuits, if you can obtain any two labels for the same wire, you recover Δ and can compute all labels.

## Bigram/Trigram Substitution → Constraint Solving (LACTF 2026)

**Pattern (lazy-bigrams):** Bigram substitution cipher where plaintext has known structure (NATO phonetic alphabet).

**OR-Tools CP-SAT approach:**
1. Model substitution as injective mapping (IntVar per bigram)
2. Add crib constraints from known flag prefix
3. Add **regular language constraint** (automaton) for valid NATO word sequences
4. Solver finds unique solution

**Pattern (not-so-lazy-trigrams):** "Trigram substitution" that decomposes into three independent monoalphabetic ciphers on positions mod 3.

**Decomposition insight:** If cipher uses `shuffle[pos % n][char]`, each residue class `pos ≡ k (mod n)` is an independent monoalphabetic substitution. Solve each separately with frequency analysis or known-plaintext.

## Shamir Secret Sharing with Deterministic Coefficients (LACTF 2026)

**Pattern (spreading-secrets):** Coefficients `a_1...a_9` are deterministic functions of secret s (via RNG seeded with s). One share (x_0, y_0) is revealed.

**Vulnerability:** Given one share, the equation `y_0 = s + g(s)*x_0 + g²(s)*x_0² + ... + g⁹(s)*x_0⁹` is **univariate** in s.

**Root-finding via Frobenius:**
```python
# In GF(p), find roots of h(s) via gcd with x^p - x
# h(s) = s + g(s)*x_0 + ... + g^9(s)*x_0^9 - y_0
# Compute x^p mod h(x) via binary exponentiation with polynomial reduction
# gcd(x^p - x, h(x)) = product of (x - root_i) for all roots
R.<x> = PolynomialRing(GF(p))
h = construct_polynomial(x0, y0)
xp = pow(x, p, h)  # Fast modular exponentiation
g = gcd(xp - x, h)  # Extract linear factors
roots = [-g[0]/g[1]] if g.degree() == 1 else g.roots()
```

**General lesson:** If ALL Shamir coefficients are derived from the secret, a single share creates a univariate equation. This completely breaks the (k,n) threshold scheme.

## Race Condition in Crypto-Protected Endpoints (LACTF 2026)

**Pattern (misdirection):** Endpoint has TOCTOU vulnerability: `if counter < 4` check happens before increment, allowing concurrent requests to all pass the check.

**Exploitation:**
1. **Cache-bust signatures:** Modify each request slightly (e.g., prepend zeros to nonce) so server can't use cached verification results
2. **Synchronize requests:** Use multiprocessing with barrier to send ~80 simultaneous requests
3. All pass `counter < 4` check before any increments → counter jumps past limit

```python
from multiprocessing import Process, Barrier
barrier = Barrier(80)

def make_request(barrier, modified_sig):
    barrier.wait()  # Synchronize all processes
    requests.post(url, json={"sig": modified_sig})

# Launch 80 processes with unique signature modifications
processes = [Process(target=make_request, args=(barrier, modify_sig(i))) for i in range(80)]
```

**Key insight:** TOCTOU in `check-then-act` patterns. Look for read-modify-write without atomicity/locking.
