# CTF Crypto - PRNG & Key Recovery

Foundational PRNG state/seed recovery techniques. For CTF-era advanced attacks (MT19937 constraint propagation, Rule 86 cellular automaton, Java LCG MITM, LFSR bit-fold, Z3 timing oracle, randcrack DSA, NTP-poisoned UUID), see [prng-attacks.md](prng-attacks.md).

## Table of Contents
- [Mersenne Twister (MT19937) State Recovery](#mersenne-twister-mt19937-state-recovery)
- [MT State Recovery from random.random() Floats via GF(2) Matrix (PHD CTF Quals 2012)](#mt-state-recovery-from-randomrandom-floats-via-gf2-matrix-phd-ctf-quals-2012)
- [Time-Based Seed Attacks](#time-based-seed-attacks)
- [C srand/rand Synchronization via Python ctypes](#c-srandrand-synchronization-via-python-ctypes)
- [Layered Encryption Recovery](#layered-encryption-recovery)
- [LCG Parameter Recovery Attack](#lcg-parameter-recovery-attack)
- [ChaCha20 Key Recovery](#chacha20-key-recovery)
- [GF(2) Matrix PRNG Seed Recovery (0xFun 2026)](#gf2-matrix-prng-seed-recovery-0xfun-2026)
- [Middle-Square PRNG Brute Force (UTCTF 2024)](#middle-square-prng-brute-force-utctf-2024)
- [Deterministic RNG from Flag Bytes + Hill Climbing (VuwCTF 2025)](#deterministic-rng-from-flag-bytes--hill-climbing-vuwctf-2025)
- [Byte-by-Byte Oracle with Random Mode Matching (VuwCTF 2025)](#byte-by-byte-oracle-with-random-mode-matching-vuwctf-2025)
- [RSA Key Reuse / Replay (UTCTF 2024)](#rsa-key-reuse--replay-utctf-2024)
- [Password Cracking Strategy](#password-cracking-strategy)
- [Logistic Map / Chaotic PRNG Seed Recovery (BYPASS CTF 2025)](#logistic-map--chaotic-prng-seed-recovery-bypass-ctf-2025)
- [V8 XorShift128+ State Recovery (Math.random Prediction)](#v8-xorshift128-state-recovery-mathrandom-prediction)
- [PCG Family — Permuted Congruential Generator (XSH-RR / XSL-RR / DXSM)](#pcg-family--permuted-congruential-generator-xsh-rr--xsl-rr--dxsm)
- [xoroshiro / xoshiro Family — Constants & Scramblers](#xoroshiro--xoshiro-family--constants--scramblers)
- [Blum-Blum-Shub (BBS) — LSB Hardness & Parity Trap](#blum-blum-shub-bbs--lsb-hardness--parity-trap)
- [Chaotic Maps — Henon & Arnold Cat Map (Image Scrambling)](#chaotic-maps--henon--arnold-cat-map-image-scrambling)

See [prng-attacks.md](prng-attacks.md) for CTF-era advanced attacks (2017+).

---

## Mersenne Twister (MT19937) State Recovery

Python's `random` module uses Mersenne Twister. If you can observe outputs, you can recover the state and predict future values.

**Key properties:**
- 624 × 32-bit internal state
- Each output is tempered from state
- After 624 outputs, state is twisted (regenerated)

**Basic untemper (reverse single output):**
```python
def untemper(y):
    y ^= y >> 18
    y ^= (y << 15) & 0xefc60000
    for _ in range(7):
        y ^= (y << 7) & 0x9d2c5680
    y ^= y >> 11
    y ^= y >> 22
    return y

# Given 624 consecutive outputs, recover state
state = [untemper(output) for output in outputs]
```

**Python's randrange(maxsize) on 64-bit:**
- `maxsize = 2^63 - 1`, so `getrandbits(63)` is used
- Each 63-bit output uses 2 MT outputs: `(mt1 << 31) | (mt2 >> 1)`
- One bit lost per output → need symbolic solving

**Symbolic approach with z3:**
```python
from z3 import *

def symbolic_temper(y):
    y = y ^ (LShR(y, 11))
    y = y ^ ((y << 7) & 0x9d2c5680)
    y = y ^ ((y << 15) & 0xefc60000)
    y = y ^ (LShR(y, 18))
    return y

# Create symbolic MT state
mt = [BitVec(f'mt_{i}', 32) for i in range(624)]
solver = Solver()

# For each observed 63-bit output
for i, out63 in enumerate(outputs):
    if 2*i + 1 >= 624: break
    y1 = symbolic_temper(mt[2*i])
    y2 = symbolic_temper(mt[2*i + 1])
    combined = Concat(Extract(31, 0, y1), Extract(31, 1, y2))
    solver.add(combined == out63)

if solver.check() == sat:
    state = [solver.model()[mt[i]].as_long() for i in range(624)]
```

**Applications:**
- MIME boundary prediction (email libraries)
- Session token prediction
- CAPTCHA bypass (predictable codes)
- Game RNG exploitation

## MT State Recovery from random.random() Floats via GF(2) Matrix (PHD CTF Quals 2012)

**Pattern:** Server exposes `random.random()` float outputs (e.g., via an API endpoint). Standard MT untemper requires 624 × 32-bit integer outputs, but `random.random()` produces 53-bit floats — truncating each to 8 usable bits per observation. A precomputed GF(2) magic matrix maps observed byte values back to the 624-word MT state.

**Key insight:** `random.random()` returns `(a*2^27+b)/2^53` where `a` = 27 bits from one MT output and `b` = 26 bits from the next. Truncating `int(float * 256)` yields only 8 bits per float, so 3360+ observations are needed (vs. 624 for integer outputs). The `not_random` library precomputes the GF(2) relationship between observed bits and state bits.

```python
import random, gzip, hashlib

# Load precomputed GF(2) magic matrix (from github.com/fx5/not_random)
f = gzip.GzipFile("magic_data", "r")
magic = eval(f.read())
f.close()

def rebuild_from_floats(floats):
    """Convert float observations to byte values, then recover MT state."""
    vals = [int(f * 256) for f in floats]  # truncate to 8-bit
    return rebuild_random(vals)

def rebuild_random(vals):
    """Recover MT19937 state from 3360+ byte observations using GF(2) matrix."""
    def getbit(bit):
        assert bit >= 0
        return (vals[bit // 8] >> (7 - bit % 8)) & 1
    state = []
    for i in range(624):
        val = 0
        data = magic[i % 2]
        for bit in data:
            val <<= 1
            for b in bit:
                val ^= getbit(b + (i // 2) * 8 - 8)
        state.append(val)
    state.append(0)
    ran = random.Random()
    ran.setstate((3, tuple(state), None))
    # Advance past consumed outputs
    for i in range(len(vals) - 3201 + 394):
        ran.randint(0, 255)
    return ran

# Collect 3360+ random.random() floats from the target
floats = [...]  # observed values from server API

# Recover state and predict future outputs
my_random = rebuild_from_floats(floats[:3360])

# Verify predictions match remaining observations
for observed, predicted in zip(floats[3360:], [my_random.random() for _ in range(40)]):
    assert '%.16f' % observed == '%.16f' % predicted

# Forge password reset token (same hash the server computes)
token = hashlib.md5(('%.16f' % my_random.random()).encode()).hexdigest()
reset_url = f'http://target/reset/{user_id}-{token}/'
```

**Attack flow (password reset token prediction):**
1. Request 3360+ random float values from an API endpoint that exposes them (e.g., `/?count=3360`)
2. Simultaneously trigger a password reset (the reset token is `md5(random.random())`)
3. Recover the MT state from the observed floats
4. Predict the `random.random()` call used for the reset token
5. Construct the reset URL with the predicted token

**When to use:** Server uses Python's `random.random()` for security-sensitive tokens (session IDs, password resets, CSRF tokens) and also exposes random values through another endpoint. The `not_random` library handles the bit-level math — focus on collecting enough float observations and synchronizing timing with the target operation.

---

## Time-Based Seed Attacks

When encryption uses time-based PRNG seed:
```python
seed = f"{username}_{timestamp}_{random_bits}"
```

**Attack approach:**
1. **Username:** Extract from metadata, email headers, challenge context
2. **Timestamp:** Get from file metadata (ZIP, exiftool)
3. **Random bits:** Check for hardcoded seed in binary, or bruteforce if small range

**Timestamp extraction:**
```bash
# Set timezone to match target
TZ=Pacific/Galapagos exiftool file.enc
# Look for File Modification Date/Time
```

**Bruteforce milliseconds:**
```python
from datetime import datetime
import random

for ms in range(1000):
    ts = f"2021-02-09!07:23:54.{ms:03d}"
    seed = f"{username}_{ts}_{rdata}"
    rng = random.Random()
    rng.seed(seed)
    key = bytes(rng.getrandbits(8) for _ in range(32))
    if try_decrypt(ciphertext, key):
        print(f"Found seed: {seed}")
        break
```

## C srand/rand Synchronization via Python ctypes

**Pattern:** Binary seeds C's PRNG with `srand(time(NULL))` at startup and uses `rand()` for encryption keys, random challenges, or XOR masks. Python's `random` module uses Mersenne Twister (different algorithm), so calling `random.seed(t)` produces wrong outputs. Use `ctypes` to load the same libc and call C's `srand()`/`rand()` directly.

**Basic synchronization (L3akCTF 2024, MireaCTF):**
```python
from ctypes import CDLL
from time import time

# Load the SAME libc used by the target binary
libc = CDLL('./libc.so.6')  # or CDLL('libc.so.6') for system libc

# Seed at the same second as the binary starts
libc.srand(int(time()))

# Generate the same sequence as the binary's rand() calls
for i in range(16):
    value = libc.rand() & 0xff  # match binary's truncation (e.g., & 0xff for byte)
    print(value)
```

**Decrypting XOR-encrypted data (L3akCTF 2024 chonccfile):**
```python
from ctypes import CDLL
from time import time
from pwn import u32, p32

libc_imp = CDLL('./libc.so.6')
libc_imp.srand(int(time()))

# Binary XORs each 4-byte block with rand() output
encrypted_data = b'...'  # read from heap/memory
result = b''
for i in range(0, len(encrypted_data), 4):
    block = u32(encrypted_data[i:i+4])
    libc_imp.rand()       # skip delay-related rand() call if binary does extra calls
    key = libc_imp.rand()
    block ^= key
    result += p32(block)
```

**Timing considerations:**
- `time(NULL)` has 1-second granularity — start the exploit within the same second as the binary
- Remote targets may have startup delay — try offsets of `+1` or `+2` seconds
- Account for any `rand()` calls between `srand()` and the target usage (e.g., random delays)
- Not 100% reliable on first try — retry with adjacent seeds if needed

**Key insight:** Python's `random` and C's `rand()` are completely different PRNGs. When a C binary uses `srand(time(NULL))`, the only way to reproduce the sequence from Python is `ctypes.CDLL` calling the same libc's `srand`/`rand`. Load the challenge's provided `libc.so.6` for exact compatibility. This works for any C PRNG output prediction — XOR keys, random challenges, token generation, or encrypted heap data.

**Alternative — custom shared library (MireaCTF):**
```c
// random_lib.c — compile with: gcc -shared -o random_lib.so random_lib.c
#include <stdlib.h>
void setseed(int seed) { srand(seed); }
int generate() { return rand() & 0xff; }
```
```python
from ctypes import CDLL
lib = CDLL('./random_lib.so')
lib.setseed(int(time()) + 1)  # +1 for remote delay
numbers = [lib.generate() for _ in range(16)]
```

---

## Layered Encryption Recovery

When binary uses multiple encryption layers:
1. Identify encryption order (e.g., Serpent → TEA)
2. Find seed derivation (e.g., sum of flag chars)
3. Keys often derived from `srand()` sequence
4. Bruteforce seed range (sum of printable ASCII is limited)

## LCG Parameter Recovery Attack

Linear Congruential Generators are weak PRNGs. Given consecutive outputs, recover parameters:

**LCG formula:** `x_{n+1} = (a * x_n + c) mod m`

**Recovery from output sequence (SageMath):**
```python
# Given sequence: [s0, s1, s2, s3, ...]
# crypto-attacks library: github.com/jvdsn/crypto-attacks
from attacks.lcg import parameter_recovery

sequence = [
    72967016216206426977511399018380411256993151454761051136963936354667101207529,
    49670218548812619526153633222605091541916798863041459174610474909967699929824,
    # ... more outputs
]

m, a, c = parameter_recovery.attack(sequence)
print(f"Modulus m: {m}")
print(f"Multiplier a: {a}")
print(f"Increment c: {c}")
```

**Weak RSA from LCG primes:**
- If RSA primes are generated from LCG, recover LCG params first
- Use known plaintext XOR ciphertext to extract LCG outputs
- Regenerate same prime sequence to factor N

```python
# Recover XOR key (which is LCG output)
def recover_lcg_output(plaintext, ciphertext, timestamp):
    pt_bytes = plaintext.encode('utf-8').ljust(32, b'\0')
    ct_int = int.from_bytes(bytes.fromhex(ciphertext), 'big')
    return timestamp ^ int.from_bytes(pt_bytes, 'big') ^ ct_int

# After recovering LCG params, generate RSA primes
lcg = LCG(a, c, m, seed)
primes = []
while len(primes) < 8:
    candidate = lcg.next()
    if is_prime(candidate) and candidate.bit_length() == 256:
        primes.append(candidate)

n = prod(primes)
phi = prod(p - 1 for p in primes)
d = pow(65537, -1, phi)
```

## ChaCha20 Key Recovery

When ChaCha20 key is derived from recoverable data:

```python
from Crypto.Cipher import ChaCha20

# If key derived from predictable source (timestamp, PID, etc.)
for candidate_key in generate_candidates():
    cipher = ChaCha20.new(key=candidate_key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    if is_valid(plaintext):  # Check for expected format
        print(f"Key found: {candidate_key.hex()}")
        break
```

**Ghidra emulator for key extraction:**
When key is computed by complex function, emulate it rather than reimplementing.

## GF(2) Matrix PRNG Seed Recovery (0xFun 2026)

**Pattern (BitStorm):** PRNG using only XOR, shifts, and rotations is linear over GF(2).

**Key insight:** Express entire PRNG as matrix multiplication: `output_bits = M * seed_bits (mod 2)`. With enough outputs, Gaussian elimination recovers the seed.

```python
import numpy as np

def build_prng_matrix(prng_func, seed_bits=2048, output_bits=2048):
    """Build GF(2) matrix by running PRNG on unit vectors."""
    M = np.zeros((output_bits, seed_bits), dtype=np.uint8)
    for i in range(seed_bits):
        # Set bit i of seed
        seed = 1 << (seed_bits - 1 - i)
        output = prng_func(seed)
        for j in range(output_bits):
            M[j, i] = (output >> (output_bits - 1 - j)) & 1
    return M

# Given output, solve: M * seed = output (mod 2)
# Use GF(2) Gaussian elimination (see modern-ciphers.md solve_gf2)
seed = solve_gf2(M, output_bits_array)
```

**Identification:** Any PRNG using only `^`, `<<`, `>>`, bitwise rotate. DON'T try iterative state recovery — go straight to the matrix.

---

## Middle-Square PRNG Brute Force (UTCTF 2024)

**Pattern (numbers go brrr):** Middle-square method with small seed space.

```python
# PRNG: seed = int(str(seed * seed).zfill(12)[3:9])  — 6-digit seed
# Seed source: int(time.time() * 1000) % (10**6) — only 1M possibilities
# AES key: 8 rounds of PRNG, each produces seed % 2^16 as 2-byte fragment

def middle_square_keygen(seed):
    key = b''
    for _ in range(8):
        seed = int(str(seed * seed).zfill(12)[3:9])
        key += (seed % (2**16)).to_bytes(2, 'big')
    return key

# Brute-force: encrypt known plaintext, compare
for seed in range(10**6):
    key = middle_square_keygen(seed)
    if try_decrypt(ciphertext, key):
        print(f"Seed: {seed}")
        break
```

**Even with time-limited interactions:** 1 known-plaintext pair suffices for offline brute force.

---

## Deterministic RNG from Flag Bytes + Hill Climbing (VuwCTF 2025)

**Pattern (Totally Random Art):** Flag bytes seed Python `random.Random()`. First N bytes of flag are known format, remaining bytes produce deterministic output.

**Attack:** When PRNG seed is known/derivable from flag format, hill-climb unknown characters:
```python
import random

def render(flag_bytes):
    rng = random.Random()
    rng.seed(flag_bytes)
    grid = [[0]*10 for _ in range(5)]
    for b in flag_bytes:
        steps, stroke = divmod(b, 16)
        x, y = 0, 0
        for _ in range(steps):
            dx, dy = rng.choice([(0,1),(0,-1),(1,0),(-1,0)])
            x = (x + dx) % 10
            y = (y + dy) % 5
        grid[y][x] = (grid[y][x] + stroke) % 16
    return grid

# Hill climb: try each byte value, keep the one that maximizes grid match
target = parse_target_art()
flag = list(b'VuwCTF{')
for pos in range(7, 17):
    best_score, best_char = -1, 0
    for c in range(32, 127):
        candidate = bytes(flag + [c])
        score = sum(1 for y in range(5) for x in range(10)
                    if render(candidate)[y][x] == target[y][x])
        if score > best_score:
            best_score, best_char = score, c
    flag.append(best_char)
```

---

## Byte-by-Byte Oracle with Random Mode Matching (VuwCTF 2025)

**Pattern (Unorthodox IV):** Server encrypts with one of N random modes/IVs per encryption. Can submit own plaintexts.

**Attack strategy:**
1. Connect, get encrypted flag
2. Probe with known prefix to check if connection can "reach" the flag's mode (same mode = same ciphertext prefix). ~50 probes, if no match, reconnect.
3. Once reachable, test candidate characters. Mode match AND next byte match = correct char. Mode match but byte mismatch = eliminate candidate permanently.
4. Elimination persists across reconnections.

**Key insight:** Probe for mode reachability first to avoid wasting attempts. Elimination-based search is more efficient than confirmation-based when modes are randomized.

---

## RSA Key Reuse / Replay (UTCTF 2024)

**Pattern (simple signature):** RSA keys reused across rounds with alternating inputs.

**Attack:** Submit previously captured encrypted output back to the server. If keys are static across interactions, replay attacks are trivial. Always check if crypto keys change between rounds.

---

## Logistic Map / Chaotic PRNG Seed Recovery (BYPASS CTF 2025)

**Pattern (Chaotic Trust):** Stream cipher using the logistic map `x_{n+1} = r * x * (1 - x)` as PRNG. Keystream generated by packing iterated float values.

**Key insight:** Logistic map with `r ≈ 4.0` is chaotic but deterministic — recovering the seed (initial x value) enables full keystream reconstruction. Seed is usually a decimal between 0 and 1, such as 0.123456789.

```python
import struct

def logistic_map(x, r=3.99):
    return r * x * (1 - x)

def decrypt_logistic(cipher_hex, seed):
    cipher = bytes.fromhex(cipher_hex)
    x = seed
    stream = b""

    while len(stream) < len(cipher):
        x = logistic_map(x)
        # Pack float as bytes for keystream (check endianness)
        stream += struct.pack("<f", x)[-2:]  # or full 4 bytes

    stream = stream[:len(cipher)]
    return bytes(a ^ b for a, b in zip(cipher, stream))

# Brute-force seed precision
for precision in range(6, 12):
    for base in [123456, 234567, 314159, 271828]:
        seed = base / (10 ** precision)
        result = decrypt_logistic(cipher_hex, seed)
        if b"FLAG" in result or b"CTF" in result:
            print(f"Seed: {seed}, Flag: {result}")
```

**Variations:**
- **r parameter:** Usually `r = 3.99` or `r = 4.0` (full chaos regime)
- **Packing:** `struct.pack("<f", x)` (4 bytes), `struct.pack("<d", x)` (8 bytes), or `[-2:]` for 2-byte fragments
- **Seed range:** Often a recognizable decimal like `0.123456789` or derived from challenge hints

**Identification:** Challenge mentions "chaos", "logistic", "butterfly effect", or provides `r` parameter. Look for source code containing `x = r * x * (1 - x)` iteration.

---

## V8 XorShift128+ State Recovery (Math.random Prediction)

**Pattern:** Web challenge uses `Math.floor(CONST * Math.random())` to generate tokens, codes, or game values. V8's `Math.random()` uses XorShift128+ (xs128p) PRNG. Given consecutive floored outputs, recover the internal state (state0, state1) with Z3, then predict future values.

**V8 internals:**
1. xs128p produces 64-bit state; V8 uses `state0 >> 12 | 0x3FF0000000000000` to create a double in [1.0, 2.0), then subtracts 1.0
2. `Math.random()` reads from a **64-value LIFO cache**. When the cache is empty, `RefillCache()` generates 64 new values. Values are consumed in reverse order from the cache
3. Only `state0` is used for the output (not `state1`)

**xs128p algorithm:**
```python
def xs128p(state0, state1):
    s1 = state0 & 0xFFFFFFFFFFFFFFFF
    s0 = state1 & 0xFFFFFFFFFFFFFFFF
    s1 ^= (s1 << 23) & 0xFFFFFFFFFFFFFFFF
    s1 ^= (s1 >> 17) & 0xFFFFFFFFFFFFFFFF
    s1 ^= s0 & 0xFFFFFFFFFFFFFFFF
    s1 ^= (s0 >> 26) & 0xFFFFFFFFFFFFFFFF
    state0 = state1 & 0xFFFFFFFFFFFFFFFF
    state1 = s1 & 0xFFFFFFFFFFFFFFFF
    return state0, state1, state0  # output is new state0
```

**Z3 solver for `Math.floor(CONST * Math.random())`:**
```python
from z3 import *
from decimal import Decimal
import struct

def to_double(value):
    double_bits = (value >> 12) | 0x3FF0000000000000
    return struct.unpack('d', struct.pack('<Q', double_bits))[0] - 1

def from_double(dbl):
    return struct.unpack('<Q', struct.pack('d', dbl + 1))[0] & 0x7FFFFFFFFFFFFFFF

def sym_xs128p(s0, s1):
    s1_ = s0
    s0_ = s1
    s1_ ^= (s1_ << 23)
    s1_ ^= LShR(s1_, 17)
    s1_ ^= s0_
    s1_ ^= LShR(s0_, 26)
    return s1, s1_  # new state0, state1

def solve_v8_random(observed_values, multiple):
    """Recover xs128p state from consecutive Math.floor(multiple * Math.random()) outputs.
    observed_values must be in REVERSE order (oldest first after tac)."""
    ostate0, ostate1 = BitVecs('ostate0 ostate1', 64)
    sym_s0, sym_s1 = ostate0, ostate1
    slvr = SolverFor("QF_BV")

    for val in observed_values:
        sym_s0, sym_s1 = sym_xs128p(sym_s0, sym_s1)
        calc = LShR(sym_s0, 12)  # V8's ToDouble mantissa bits
        # Constrain: floor(multiple * to_double(state0)) == val
        lower = from_double(Decimal(val) / Decimal(multiple))
        upper = from_double(Decimal(val + 1) / Decimal(multiple))
        lower_m = lower & 0x000FFFFFFFFFFFFF
        upper_m = upper & 0x000FFFFFFFFFFFFF
        upper_e = (upper >> 52) & 0x7FF
        slvr.add(And(lower_m <= calc, Or(upper_m >= calc, upper_e == 1024)))

    if slvr.check() == sat:
        m = slvr.model()
        return m[ostate0].as_long(), m[ostate1].as_long()
    return None, None

# Predict next values after state recovery
def predict_next(state0, state1, multiple, count):
    results = []
    for _ in range(count):
        state0, state1, output = xs128p(state0, state1)
        import math
        results.append(math.floor(multiple * to_double(output)))
    return results
```

**Usage (tool: d0nutptr/v8_rand_buster):**
```bash
# Collect observed values, reverse them (LIFO cache order), pipe to solver
cat observed_codes.txt | tac | python3 xs128p.py --multiple 100000

# Generate predictions from recovered state
python3 xs128p.py --multiple 100000 --gen <state0>,<state1>,<count>
```

**Key insight:** The LIFO cache means observed values are in reverse generation order — reverse them with `tac` before solving. The Z3 `QF_BV` (quantifier-free bitvector) theory efficiently handles the bitwise operations. Typically 5-10 consecutive outputs suffice for a unique solution.

**Common pitfalls:**
- Forgetting to reverse the observation order (cache is LIFO)
- Multiple browser tabs or web workers may have separate PRNG states
- Cache boundary (every 64 calls) can introduce discontinuities if observations span a refill

**Inverse xorshift128+ (backward prediction):** After recovering state, step the PRNG backward to predict values generated *before* the observed sequence. Essential when the target value was generated earlier than observations (e.g., predicting another user's 2FA code). (Midnight Flag 2026)

```python
def undo_rshift_xor(val, shift):
    """Invert val ^= (val >> shift)"""
    result = val
    for _ in range(3):  # 3 iterations sufficient for 64-bit
        result = val ^ (result >> shift)
    return result & 0xFFFFFFFFFFFFFFFF

def undo_lshift_xor(val, shift):
    """Invert val ^= (val << shift)"""
    result = val
    for _ in range(3):
        result = val ^ ((result << shift) & 0xFFFFFFFFFFFFFFFF)
    return result & 0xFFFFFFFFFFFFFFFF

def reverse_step(s0, s1):
    """Run xs128p one step backward: (s0, s1) → (old_s0, old_s1)"""
    old_s1 = s0
    known = (s1 ^ s0 ^ ((s0 >> 26) & 0xFFFFFFFFFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
    x = undo_rshift_xor(known, 17)
    old_s0 = undo_lshift_xor(x, 23)
    return old_s0, old_s1

# Usage: step backward N times from recovered state
for _ in range(N):
    state0, state1 = reverse_step(state0, state1)
    predicted = math.floor(CONST * to_double(state0))
```

**When to use:** Web challenge where JavaScript generates predictable-looking random values (tokens, verification codes, game rolls) using `Math.random()`. Look for patterns like `Math.floor(N * Math.random())` or `Math.random().toString(36).substr(2)` in client-side or server-side Node.js code.

---

## Password Cracking Strategy

**Attack order for unknown passwords:**
1. Common wordlists: `rockyou.txt`, `10k-common.txt`
2. Theme-based wordlist (usernames, challenge keywords)
3. Rules attack: wordlist + `best66.rule`, `dive.rule`
4. Hybrid: `word + ?d?d?d?d` (word + 4 digits)
5. Brute force: start at 4 chars, increase

**SHA256 with hex salt (VuwCTF 2025, Delicious Cooking):** Format `hash$hex_salt`. Salt must be hex-decoded before `SHA256(password + salt_bytes)`. Password often derivable from security questions (e.g., "fav movie + PIN" = "ratatouille0000"-"ratatouille9999").

**CTF password patterns:**
```text
base_password + year     → actnowonclimatechange2026
username + digits        → nemo123, admin2026
theme + numbers          → flag2026, ctf2025
leet speak               → p@ssw0rd, s3cr3t
```

**Hashcat modes reference:**
```bash
# Common modes
-m 0      # MD5
-m 1000   # NTLM
-m 5600   # NTLMv2
-m 13600  # WinZip AES
-m 13000  # RAR5
-m 11600  # 7-Zip

# Attack modes
-a 0      # Dictionary
-a 3      # Brute force mask
-a 6      # Hybrid (word + mask)
-a 7      # Hybrid (mask + word)
```

**When password relates to another in challenge:**
- Try variations: `password + year`, `password + 123`
- Try reversed: `drowssap`
- Try with common suffixes: `!`, `@`, `#`, `1`, `123`
- If SMB/FTP password known, ZIP password often related

---

## PCG Family — Permuted Congruential Generator (XSH-RR / XSL-RR / DXSM)

**Pattern:** CTF uses PCG-64 (e.g., `pcg64` from NumPy) or custom PCG-32 with small state. State update is LCG: `s_{n+1} = a * s_n + c mod 2^k` where `k = 64` or `128`. Output is a permuted slice: `XSH-RR`, `XSL-RR`, or the newer `DXSM`. PCG's output function hides bits but the LCG step is fully invertible.

**Identification:** Challenge imports `numpy.random.PCG64`, mentions `pcg`, or shows constants `a = 6364136223846793005` (PCG default multiplier for 64-bit) or `a = 25492914187169442445` for 128-bit state.

**Output permutations:**

| Variant | State bits | Output bits | Permutation |
|---------|-----------|-------------|-------------|
| XSH-RR 64/32 | 64 | 32 | `xorshift(state>>something)`, `rotate32` by `state>>58` |
| XSH-RR 64/64 | 128 | 64 | `rotate64(state ^ (state>>64), state>>122)` |
| XSL-RR 128/64 | 128 | 64 | `rotate64((state>>64) ^ state, state>>122)` — xor low/high then rotate |
| DXSM 128/64 | 128 | 64 | `state * c2 ^ (state>>64)` double-xorshift-multiply |

**Canonical 128/64 XSH-RR (what CTFs use):**

```python
MASK128 = (1 << 128) - 1
MASK64  = (1 << 64) - 1
MUL = 25492914187169442445   # PCG 128-bit default
INC = 1234567890123456789    # odd increment (challenge-specific, may be 1442695040888963407)

def rotr64(v, r):
    r &= 63
    return ((v >> r) | (v << (64 - r))) & MASK64

def pcg_output(state128):
    """XSH-RR 128->64 : rotate64(state ^ (state>>64), state>>122)"""
    xorshifted = (((state128 >> 64) ^ state128) >> 58) & MASK64  # upper bits for rotate not used here
    # canonical form per spec:
    rot = (state128 >> 122) & 63
    x = (state128 ^ (state128 >> 64)) & MASK64
    return rotr64(x, rot)

def pcg_step(state):
    return (state * MUL + INC) & MASK128

# Collect outputs, then reverse
outs = [...]  # observed 64-bit outputs
```

**Why brute force works — 64-branch inversion:**

Given one 64-bit output `o`, the pre-image state is NOT unique: the rotate amount `rot = state>>122` is 6 bits (0..63) and `x = rotr_inv(o, rot)` constrains only 64 of 128 state bits. Each `rot` gives a 64-bit search space reduced to 2 candidates via the LCG relation.

```python
def rotl64(v, r):
    r &= 63
    return ((v << r) | (v >> (64 - r))) & MASK64

def invert_pcg_output(out, rot):
    """Given output `out` and guessed rot, recover the x = state ^ (state>>64) low 64."""
    return rotl64(out, rot)

# Full reversal: try all 64 rotations, solve LCG linkage with Z3
from z3 import BitVec, BitVecVal, Solver, LShR, RotateRight

def recover_pcg_z3(outputs):
    s = [BitVec(f's{i}', 128) for i in range(len(outputs)+1)]
    solver = Solver()
    for i in range(len(outputs)):
        solver.add(s[i+1] == s[i] * MUL + INC)  # mod 2^128 automatic for BitVec
        rot = LShR(s[i], 122)  # 6-bit rotate
        x = (s[i] ^ LShR(s[i], 64)) & 0xFFFFFFFFFFFFFFFF  # low 64 of xor
        # Z3 RotateRight expects concrete or symbolic rotation
        solver.add(RotateRight(x & 0xFFFFFFFFFFFFFFFF, rot) == outputs[i])
    # Alternative: branch instead of symbolic rotate for older Z3
    #   solver.add(Or(*[And(rot==r, RotateRight(x,r)==outputs[i]) for r in range(64)]))
    if solver.check().sat:
        m = solver.model()
        return [m[si].as_long() for si in s]
    return None
```

<details><summary>Sage fallback (optional)</summary>

```python
from sage.all import *

# Sage brute-force over 64 rotations, then meet-in-the-middle on state
MUL = 25492914187169442445
INC = 1442695040888963407
MASK64 = (1<<64)-1

def rotr64(v, r):
    return ((v >> r) | (v << (64 - r))) & MASK64

def sage_pcg_recover(outputs):
    # Try each rotation for first output; derive high bits, propagate via LCG, test second output
    for rot in range(64):
        x = ((outputs[0] << rot) | (outputs[0] >> (64-rot))) & MASK64  # rotl
        # x = low64(state ^ (state>>64)); so high64(state) = low64(state) ^ x ^ carry from cross
        # Brute-force low64 via second output filter (still 2^64 worst; use Z3 in practice)
        # With 3 outputs, Sage's IntegerMod ring solves directly
        R = Zmod(2**128)
        # Encode as IntegerMod and let Sage solve — prefer Z3 path above for speed
        pass
```

</details>

**Branch-Or Z3 model:** The symbolic `RotateRight(x, rot)` where `rot` is `state>>122` is hard for Z3 (symbolic rotate). Rewrite as 64-way `Or` over concrete rotates — `Or(And(rot==r, RotateRight(x, r)==out) for r in range(64))`. This enumerates the 6-bit rotation and keeps the solver in QF_BV decidable fragment. Two consecutive outputs usually pinpoint a unique seed; three outputs eliminate false positives from the 64-branch.

**When to recognize:** Challenge leaks 2-3 consecutive `pcg64` outputs as 64-bit integers or floats derived from them. Look for `numpy`, `pcg`, or the multiplier `6364136223846793005` (64-bit) / `25492914187169442445` (128-bit).

---

## xoroshiro / xoshiro Family — Constants & Scramblers

**Pattern:** Non-cryptographic but CTF-predictable generators: `xoroshiro128+`, `xoroshiro128**`, `xoshiro256**`, `xoshiro256++`, and V8's `xoroshiro128+` alias `xs128p`. Each has a distinct linear transition (xor/shift/rotate) and a scrambler that hides the state.

| Generator | State | Transition constants | Scrambler | Output |
|-----------|-------|---------------------|-----------|--------|
| xs128p (V8 Math.random) | 128 (2x64) | `a=23, b=17, c=26` | `+` (add) | `s0 + s1` |
| xoroshiro128+ | 128 (2x64) | `a=23, b=17, c=26` | `+` | `s0 + s1` |
| xoroshiro128** | 128 (2x64) | `a=24, b=16, c=22` | `**` (`rotl(s0*5,7)*9`) | `rotl(s0*5,7)*9` |
| xoshiro256** | 256 (4x64) | `a=23, b=17, c=26` via rotates | `**` (`rotl(s0*5,7)*9`) | `rotl(s0*5,7)*9` |
| xoshiro256+ | 256 (4x64) | same | `+` (`s0 + s3`) | `s0 + s3` |
| xoshiro256++ | 256 (4x64) | same | `++` (`rotl(s0+s3,23)+s0`) | `rotl(s0+s3,23)+s0` |

**Transition (xoroshiro128 family):**

```python
MASK64 = (1 << 64) - 1

def rotl64(x, k):
    return ((x << k) | (x >> (64 - k))) & MASK64

def xoroshiro128_next(s0, s1, a=23, b=17, c=26):
    s1 ^= s0
    s0 = rotl64(s0, a) ^ s1 ^ ((s1 << b) & MASK64)
    s1 = rotl64(s1, c)
    return s0, s1

def xoshiro256_next(s):
    # s = [s0,s1,s2,s3]
    t = (s[1] << 17) & MASK64
    s[2] ^= s[0]
    s[3] ^= s[1]
    s[1] ^= s[2]
    s[0] ^= s[3]
    s[2] ^= t
    s[3] = rotl64(s[3], 45)
    return s

def scrambler_plus(s0, s1):            # xoroshiro128+
    return (s0 + s1) & MASK64

def scrambler_starstar(s0):             # xoroshiro128** / xoshiro256**
    return (rotl64((s0 * 5) & MASK64, 7) * 9) & MASK64
```

**Recovering state — linear + scrambler:**

The transition is linear over GF(2); only the scrambler is non-linear (`+` or `*`). For `+`, the sum leaks carries; for `**`, the multiply leaks low bits. With 3-4 consecutive outputs, Z3 over BitVec 64 recovers the full state.

```python
from z3 import BitVec, BitVecVal, Solver, LShR, RotateLeft

def recover_xoroshiro128_plus(outputs):
    s0, s1 = BitVec('s0', 64), BitVec('s1', 64)
    solver = Solver()
    cur0, cur1 = s0, s1
    for o in outputs:
        solver.add((cur0 + cur1) == o)
        # step: s1 ^= s0; s0 = rotl(s0,23) ^ s1 ^ (s1<<17); s1 = rotl(s1,26)
        ns1 = cur1 ^ cur0
        ns0 = RotateLeft(cur0, 23) ^ ns1 ^ (ns1 << 17)
        ns1 = RotateLeft(ns1, 26)
        cur0, cur1 = ns0, ns1
    if solver.check().sat:
        m = solver.model()
        return m[s0].as_long(), m[s1].as_long()
    return None

def recover_xoshiro256_starstar(outputs):
    s = [BitVec(f's{i}', 64) for i in range(4)]
    solver = Solver()
    cur = s[:]
    for o in outputs:
        solver.add(RotateLeft((cur[0] * 5) & 0xFFFFFFFFFFFFFFFF, 7) * 9 == o)
        # xoshiro256 transition
        t = cur[1] << 17
        cur[2] ^= cur[0]
        cur[3] ^= cur[1]
        cur[1] ^= cur[2]
        cur[0] ^= cur[3]
        cur[2] ^= t
        cur[3] = RotateLeft(cur[3], 45)
        # loop continues with new cur
    if solver.check().sat:
        m = solver.model()
        return [m[si].as_long() for si in s]
    return None
```

<details><summary>Sage fallback (optional)</summary>

```python
from sage.all import *

# Sage: model xoroshiro as linear system over GF(2) plus scrambler as integer constraints
# For xoroshiro128+, brute-force via Sage's BitVector SAT or convert to z3 via sage's z3 interface
# Prefer pure-Python Z3 path above; Sage path mirrors it with sage's z3 solver bridge
def sage_xoroshiro(outputs):
    from sage.sat.boolean_polynomials import solve as sat_solve
    # Encode transition as Boolean polynomials, scrambler as carry constraints
    pass
```

</details>

**Differential choice:** The `+` scrambler is weaker than `**` — addition's low bits are linear (no carry into bit 0), so bit 0 of the output directly leaks `s0[0] ^ s1[0]`. Start guessing from LSB upward. For `**`, the multiply by 5 (`s0*5 = s0*4 + s0`) also leaks low bits; `rotl(...,7)` then moves them to bits 7+ — enumerate low bytes first.

**When to recognize:** Challenge says `xoroshiro`, `xoshiro`, or shows `rotl`/`xor`/`<<` constants like `23,17,26` or `45`. Check `numpy.random` docs: `SFC64`, `Philox` are different; `MT19937` is Mersenne. Confirm by matching constants to the table above.

---

## Blum-Blum-Shub (BBS) — LSB Hardness & Parity Trap

**Pattern:** BBS: `x_{i+1} = x_i^2 mod n` where `n = p*q`, `p,q` primes `= 3 mod 4`. Security relies on quadratic residuosity — predicting the LSB is as hard as factoring `n` — but CTF breaks come from `n` even, small `n`, or repeated same-bit leakage that pins `x_0` near a boundary.

**Core:**

```python
def bbs_next(x, n):
    return pow(x, 2, n)

def bbs_bits(x0, n, count):
    x = x0
    out = []
    for _ in range(count):
        x = pow(x, 2, n)
        out.append(x & 1)  # LSB oracle; some CTFs use parity (x % 2) or x & 1
    return out

# BBS is unbiased: P(LSB=0) ~ 0.5 when p,q = 3 mod 4 (Blum primes)
# When n is even, parity leaks directly and LSB is trivially predictable!
```

**Hardness vs CTF instantiation:**

The LSB of BBS is provably unpredictable under factoring hardness (Blum-Micali). The HTB/Bloom observation: extracting more than `O(log log n)` bits per iteration via `x_i % 2^k` breaks the proof — but LSB-only remains hard unless `n` has structure.

**The parity trap — even `n`:**

If the challenge generates `n` as `random.getrandbits(512)` without checking oddness, `n` is even with probability 0.5. Then `x_{i+1} = x_i^2 mod n` preserves parity: even `x` stays even, odd `x` stays odd, so the LSB sequence is constant `0` or `1`. Detection is trivial:

```python
import hashlib

def bloom_parity_trap(n, bits):
    """If n even and 256 consecutive BBS bits are identical, we brute-force x0."""
    if n % 2 == 1:
        return None  # not trapped; need factoring path
    # All bits same => x0 had that parity throughout
    if len(set(bits)) != 1:
        return None
    const_bit = bits[0]
    # sha256('0'*256) vs sha256('1'*256) fingerprint — challenge checks this
    # HTB Bloom: service hashes the bitstring; we compare
    h0 = hashlib.sha256(b'0'*256).hexdigest()
    h1 = hashlib.sha256(b'1'*256).hexdigest()
    # Only 2 candidates survive: x0 even vs odd preimage
    # Brute-force x0 parity class and step backward via modular sqrt mod even n
    candidates = []
    if const_bit == 0:
        # x0 even — any even seed squares to even mod even n
        candidates = [2, 4]  # minimal even representatives; real solver tries sqrt chain
    else:
        candidates = [1, 3]
    return candidates, (h0, h1)

# Full BBS solver for even-n parity trap (HTB Bloom pattern)
def solve_bloom_bbs(n, observed_bits):
    # observed_bits is 256 copies of same bit? Then:
    assert len(observed_bits) == 256 and len(set(observed_bits)) == 1
    # Challenge expects you to notice the trap and return the 2 possible hash preimages
    bit = str(observed_bits[0])
    h = hashlib.sha256((bit*256).encode()).hexdigest()
    # The flag is hidden behind which candidate the oracle accepts
    print(h)
    # Then invert BBS one step at a time via Tonelli-Shanks mod n (when n even, just parity)
    return h
```

<details><summary>Sage fallback (optional)</summary>

```python
from sage.all import *

def sage_bbs_sqrt(x_next, n):
    # Square roots mod n = p*q via CRT; needs factorization
    # For even n, factor 2 out and solve mod odd part, then combine
    p, q = factor(n)  # Sage factor
    # Tonelli-Shanks for p,q = 3 mod 4: sqrt(x) = x^((p+1)//4) mod p
    roots_p = [pow(int(x_next % p), (int(p)+1)//4, int(p))]
    roots_p.append(int(p) - roots_p[0])
    roots_q = [pow(int(x_next % q), (int(q)+1)//4, int(q))]
    roots_q.append(int(q) - roots_q[0])
    # CRT combine — 4 roots
    return crt_combine(roots_p, roots_q, p, q)
```

</details>

**General BBS attack checklist:**

1. Check `n % 2 == 0` → parity trap → constant-bit fingerprint `sha256('0'*256)` / `sha256('1'*256)`, only 2 candidates.
2. If `n` small (< 512 bits) → factor with `yafu`/`factordb`/`sage`, then compute square roots via Tonelli-Shanks `(p+1)//4` for Blum primes to walk backward from any `x_i`.
3. If many bits leaked per iteration (>1 bit, e.g., `x_i & 0xFF`) → Coppersmith/lattice on the truncated `x_i`.
4. LSB-only, `n` odd, large → hard; challenge must give `n` even or leak extra bits.

**References:** HTB Bloom, Blum-Micali 1984.

---

## Chaotic Maps — Henon & Arnold Cat Map (Image Scrambling)

**Pattern:** Image encryption via chaotic maps: Henon map shuffles pixel positions or XORs keystream; Arnold cat map permutes `N x N` blocks with matrix `[[1,p],[q,p*q+1]] mod N`. The first scrambling weakens quickly — brute-force the chaotic seed + map parameters and score with PNG header.

**Henon map:**

```
x_{n+1} = 1 - a*x_n^2 + y_n
y_{n+1} = b*x_n
a = 1.4, b = 0.3  (classic chaotic regime)
```

```python
def henon(x, y, a=1.4, b=0.3):
    x_next = 1 - a*x*x + y
    y_next = b*x
    return x_next, y_next

def henon_keystream(x0, y0, n, a=1.4, b=0.3):
    x, y = x0, y0
    ks = []
    for _ in range(n):
        x, y = henon(x, y, a, b)
        ks.append(int(abs(x) * 1e9) & 0xff)  # challenge-specific extraction
    return bytes(ks)

# Brute-force x0 when quantized to 4 decimals (10000 possibilities per y0)
def brute_henon(cipher, y0=0.0):
    best = (None, -1)
    for x0_int in range(-10000, 10000):
        x0 = x0_int / 10000
        ks = henon_keystream(x0, y0, len(cipher))
        pt = bytes(c ^ k for c, k in zip(cipher, ks))
        # PNG header scoring: 89 50 4E 47 0D 0A 1A 0A
        score = sum(1 for a, b in zip(pt[:8], b'\x89PNG\r\n\x1a\n') if a == b)
        if score > best[1]:
            best = ((x0, y0, pt), score)
            if score == 8:
                return best[0]
    return best[0]
```

**Arnold cat map — forward, inverse, and brute force:**

The cat map permutes pixel `(x,y)` as:

```
[x'] = [[1, p    ]] [x]  mod N
[y']   [[q, p*q+1]] [y]
```

Its inverse is:

```
M^{-1} = [[p*q+1, -p]]  mod N
         [[-q,     1]]
```

```python
def arnold_forward(x, y, p, q, N):
    return ( (x + p*y) % N, (q*x + (p*q+1)*y) % N )

def arnold_inverse(x, y, p, q, N):
    return ( ((p*q+1)*x - p*y) % N, (-q*x + y) % N )

def arnold_scramble(img, p, q, N, rounds=1):
    """Permute N x N image `rounds` times with cat map."""
    out = [[0]*N for _ in range(N)]
    for y in range(N):
        for x in range(N):
            nx, ny = x, y
            for _ in range(rounds):
                nx, ny = arnold_forward(nx, ny, p, q, N)
            out[ny][nx] = img[y][x]
    return out

def arnold_unscramble(img, p, q, N, rounds=1):
    out = [[0]*N for _ in range(N)]
    for y in range(N):
        for x in range(N):
            nx, ny = x, y
            for _ in range(rounds):
                nx, ny = arnold_inverse(nx, ny, p, q, N)
            out[ny][nx] = img[y][x]
    return out

# Brute-force p,q in [1,5] + quantized x0 for Henon-XOR layer, score with PNG header
PNG_MAGIC = b'\x89PNG\r\n\x1a\n'

def brute_arnold_henon(cipher_img, N):
    for p in range(1, 6):
        for q in range(1, 6):
            # try unscrambling with this cat map
            unscrambled = arnold_unscramble(cipher_img, p, q, N, rounds=1)
            flat = bytes(v & 0xff for row in unscrambled for v in row)
            # score header
            if flat[:8] == PNG_MAGIC:
                print(f"cat map p={p} q={q} -> PNG header matched")
                return p, q, flat
            # if Henon XOR layer present, nest x0 brute-force inside (4-decimal quantized)
            for x0_int in range(0, 10000):
                x0 = x0_int / 10000
                ks = henon_keystream(x0, 0.0, len(flat))
                pt = bytes(c ^ k for c, k in zip(flat, ks))
                if pt[:8] == PNG_MAGIC:
                    return p, q, x0, pt
    return None
```

<details><summary>Sage fallback (optional)</summary>

```python
from sage.all import *

def sage_arnold_period(p, q, N):
    M = matrix(Zmod(N), [[1, p],[q, p*q+1]])
    # period is order of M in GL(2, Z_N)
    return M.multiplicative_order()
```

</details>

**Scoring oracle:** After each trial descramble, check `pt[:8] == b'\x89PNG\r\n\x1a\n'` or `pt[1:4] == b'PNG'` plus `pt[12:16] == b'IHDR'`. The cat map period divides `3*N` for prime `N` (and is tiny for `N` power of 2), so iterating `period` times returns the original image — use this to bound search.

**When to recognize:** Challenge shows scrambled image, mentions `Henon`, `Arnold`, `cat map`, `chaotic`, or gives matrix `[[1,p],[q,pq+1]]`. The keyspace is tiny: `p,q` in `[1,5]` and `x0` quantized to 4 decimals (10k tries). Start with header scoring, not entropy.
