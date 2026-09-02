# CTF Crypto - Stream Cipher Attacks

LFSR, RC4, and XOR-based stream cipher attacks. For block cipher attacks (AES, padding oracle, MAC forgery), see [modern-ciphers.md](modern-ciphers.md).

## Table of Contents
- [LFSR Stream Cipher Attacks](#lfsr-stream-cipher-attacks)
  - [Berlekamp-Massey Algorithm](#berlekamp-massey-algorithm)
  - [Correlation Attack](#correlation-attack)
  - [Known-Plaintext on LFSR Keystream](#known-plaintext-on-lfsr-keystream)
  - [Galois vs Fibonacci LFSR](#galois-vs-fibonacci-lfsr)
  - [Common LFSR Lengths and Polynomials](#common-lfsr-lengths-and-polynomials)
  - [Galois LFSR Tap Recovery via Autocorrelation (BSidesSF 2026)](#galois-lfsr-tap-recovery-via-autocorrelation-bsidessf-2026)
- [RC4 Second-Byte Bias Distinguisher (Hackover CTF 2015)](#rc4-second-byte-bias-distinguisher-hackover-ctf-2015)
- [XOR Consecutive Byte Correlation Attack (Defcamp 2015)](#xor-consecutive-byte-correlation-attack-defcamp-2015)
- [Fibonacci Stream Cipher Position-Shifting Oracle (EKOPARTY 2017)](#fibonacci-stream-cipher-position-shifting-oracle-ekoparty-2017)
- [Z3 Constraint Solving for Custom Stream Ciphers (Tokyo Westerns 2017)](#z3-constraint-solving-for-custom-stream-ciphers-tokyo-westerns-2017)
- [Keystream Recovery via Run-Length Encoding Collisions (Google CTF Quals 2018)](#keystream-recovery-via-run-length-encoding-collisions-google-ctf-quals-2018)
- [LFSR Filter Linear Annihilator Attack (Hack.lu 2018)](#lfsr-filter-linear-annihilator-attack-hacklu-2018)
- [Hostname-as-XOR-Key Leaked via DNS Capture (SECCON 2018)](#hostname-as-xor-key-leaked-via-dns-capture-seccon-2018)
- [RC4 Family — RC4 vs RC4A vs VMPC vs Spritz](#rc4-family--rc4-vs-rc4a-vs-vmpc-vs-spritz)
- [eSTREAM Portfolio — Trivium / Grain / Mickey (Reduced-Round Z3)](#estream-portfolio--trivium--grain--mickey-reduced-round-z3)

---

## LFSR Stream Cipher Attacks

Linear Feedback Shift Registers generate keystreams from an initial state and feedback polynomial. Common in CTF crypto challenges and lightweight/custom ciphers.

**Detection:** Look for bit-level operations (XOR, shift, AND with tap mask), short repeating keystreams, or challenge descriptions mentioning "stream cipher", "LFSR", "shift register", or "linear recurrence".

### Berlekamp-Massey Algorithm

**Pattern:** Given a portion of known keystream (from known plaintext XOR), recover the minimal LFSR that generates it. Once you have the feedback polynomial and state, predict all future (and past) output.

**Key insight:** Berlekamp-Massey finds the shortest LFSR producing a given sequence in O(n^2). If you have 2L consecutive keystream bits (where L is the LFSR length), you can fully recover the LFSR.

```python
# Known keystream bits (from known plaintext XOR ciphertext)
keystream = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1]

# Pure-Python Berlekamp-Massey over GF(2)
def berlekamp_massey(seq):
    n = len(seq)
    s = seq[:]
    C, B = [1], [1]
    L, m, b = 0, -1, 1
    for n_idx in range(n):
        d = s[n_idx]
        for i in range(1, L+1):
            d ^= C[i] & s[n_idx - i] if i < len(C) and n_idx - i >= 0 else 0
        if d == 0:
            continue
        T = C[:]
        need = n_idx - m + len(B)
        if len(C) < need:
            C += [0] * (need - len(C))
        for i in range(len(B)):
            C[n_idx - m + i] ^= B[i]
        if 2 * L <= n_idx:
            L = n_idx + 1 - L
            m = n_idx
            B = T
    # C is connection polynomial; trim
    C = C[:L+1]
    return C, L  # C[0]=1, taps where C[i]==1

C, L = berlekamp_massey(keystream)
# C[0]==1 is the constant term; exclude 0 from taps (feedback only)
print(f"LFSR polynomial taps: {[i for i,c in enumerate(C) if c and i!=0]}")
print(f"LFSR length: {L}")

# Recover initial state from first L bits
state = keystream[:L]

# Generate future keystream — Fibonacci LFSR: taps are 1-indexed from the end
def lfsr_next(state, taps):
    """taps = list of tap positions from polynomial (1-indexed, 0 excluded).
    For Fibonacci LFSR, new_bit = XOR of state[-t] for t in taps.
    Example: L=2, C=[1,1,1] -> taps=[1,2] -> new_bit = state[-1] ^ state[-2] (no IndexError)."""
    new_bit = 0
    for t in taps:
        new_bit ^= state[-t]
    return state[1:] + [new_bit]

# Derive taps correctly (exclude constant term 0):
taps = [i for i, c in enumerate(C) if c and i != 0]
```

<details><summary>Sage fallback (optional)</summary>

```python
from sage.all import *

# Known keystream bits (from known plaintext XOR ciphertext)
keystream = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1]

# Berlekamp-Massey in SageMath
F = GF(2)
seq = [F(b) for b in keystream]
R = berlekamp_massey(seq)  # Returns the feedback polynomial
print(f"LFSR polynomial: {R}")
print(f"LFSR length: {R.degree()}")

# Recover initial state from first L bits
L = R.degree()
state = keystream[:L]

# Generate future keystream — Fibonacci LFSR: exclude constant term, taps are 1-indexed from end
def lfsr_next(state, taps):
    """taps = feedback positions (1-indexed, 0 excluded); new_bit = XOR(state[-t] for t in taps)"""
    new_bit = 0
    for t in taps:
        new_bit ^= state[-t]
    return state[1:] + [new_bit]
```

</details>

### Correlation Attack

**Pattern:** Combined LFSR generator (multiple LFSRs combined through a nonlinear function). If the combining function has correlation bias toward one LFSR's output, attack that LFSR independently.

**Key insight:** If `P(output = LFSR_i output) > 0.5`, brute-force LFSR_i's initial state (2^L candidates for length-L LFSR) and check correlation with known keystream. Much faster than brute-forcing the full combined state.

```python
# Correlation attack on a single biased LFSR
def correlation_attack(keystream_bits, lfsr_length, taps, threshold=0.6):
    """Try all 2^L initial states, keep those with high correlation"""
    best_corr, best_state = 0, None
    for seed in range(2**lfsr_length):
        state = [(seed >> i) & 1 for i in range(lfsr_length)]
        matches = 0
        s = state[:]
        for i, bit in enumerate(keystream_bits):
            if s[0] == bit:
                matches += 1
            s = lfsr_next(s, taps)
        corr = matches / len(keystream_bits)
        if corr > best_corr:
            best_corr, best_state = corr, seed
    return best_state, best_corr
```

### Known-Plaintext on LFSR Keystream

**Pattern:** XOR known plaintext with ciphertext to get keystream. With >=2L keystream bits, solve the linear system directly.

```python
# Given 2L keystream bits, solve for L-bit state + L feedback taps
# Keystream relation: k[i+L] = c[0]*k[i] + c[1]*k[i+1] + ... + c[L-1]*k[i+L-1] (mod 2)
def solve_lfsr(keystream, L):
    """Solve for LFSR feedback from 2L keystream bits over GF(2)"""
    # Build matrix: each row is [k[i], k[i+1], ..., k[i+L-1]] = k[i+L]
    A = []
    b = []
    for i in range(L):
        A.append(keystream[i:i+L])
        b.append(keystream[i+L])
    # Solve over GF(2) using sympy
    from sympy import Matrix
    M = Matrix(A)
    v = Matrix(b)
    # Gaussian elimination mod 2
    aug = M.row_join(v)
    # rref over GF(2) via integer rref then mod 2
    rref, pivots = aug.rref(iszerofunc=lambda x: x % 2 == 0, simplify=True)
    # Extract solution assuming full rank
    n = M.cols
    sol = [0]*n
    for r, c in enumerate(pivots):
        if c < n:
            sol[c] = int(rref[r, -1] % 2)
    return sol
```

<details><summary>Sage fallback (optional)</summary>

```python
import numpy as np

# Given 2L keystream bits, solve for L-bit state + L feedback taps
# Keystream relation: k[i+L] = c[0]*k[i] + c[1]*k[i+1] + ... + c[L-1]*k[i+L-1] (mod 2)
def solve_lfsr(keystream, L):
    """Solve for LFSR feedback from 2L keystream bits over GF(2)"""
    # Build matrix: each row is [k[i], k[i+1], ..., k[i+L-1]] = k[i+L]
    A = []
    b = []
    for i in range(L):
        A.append(keystream[i:i+L])
        b.append(keystream[i+L])
    # Solve over GF(2) using SageMath
    from sage.all import matrix, vector, GF
    M = matrix(GF(2), A)
    v = vector(GF(2), b)
    coeffs = M.solve_right(v)
    return list(coeffs)
```

</details>

### Galois vs Fibonacci LFSR

Two equivalent representations — same keystream, different wiring:
- **Fibonacci:** feedback from multiple taps XOR'd into last position (most common in CTFs)
- **Galois:** feedback distributed across the register (faster in hardware)

Conversion: Galois polynomial is the reciprocal of Fibonacci polynomial. Most CTF tools assume Fibonacci form.

### Common LFSR Lengths and Polynomials

| Bits | Common primitive polynomial | Period |
|------|---------------------------|--------|
| 16 | x^16 + x^14 + x^13 + x^11 + 1 | 65535 |
| 32 | x^32 + x^22 + x^2 + x + 1 | 2^32 - 1 |
| 64 | x^64 + x^4 + x^3 + x + 1 | 2^64 - 1 |

**Maximal-length LFSR:** Primitive polynomial -> period = 2^L - 1 (visits all nonzero states).

### Galois LFSR Tap Recovery via Autocorrelation (BSidesSF 2026)

**Pattern (lfstream):** A PNG file is encrypted by XORing each N-bit block with the current state of a Galois LFSR (right-shift model). The LFSR length, seed, and tap mask are unknown. Recover all three from the known 16-byte PNG header.

**Step 1 — Recover keystream via known plaintext:**

```bash
# PNG header is always: 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52
# XOR first 16 encrypted bytes with this header to get 128 keystream bits
```

**Step 2 — Find LFSR length via autocorrelation sliding:**

Slide the 128-bit keystream against itself at increasing offsets. The offset where most bits align reveals the LFSR period. For a right-shift Galois LFSR, the keystream repeats with a one-bit shift per step, so the autocorrelation peak occurs at offset = LFSR length + 1.

```python
def find_lfsr_length(bits, min_len=8, max_len=64, step=8):
    """Slide keystream bits against themselves to find LFSR period."""
    best = None
    for n in range(min_len, max_len + 1, step):
        # Split keystream into n-bit state windows
        states = [int(bits[i*n:(i+1)*n], 2) for i in range(len(bits) // n)]
        if len(states) < 2:
            continue

        # For each transition, check Galois right-shift consistency
        mask_votes = {}
        mismatches = 0
        for i in range(len(states) - 1):
            s, nxt = states[i], states[i + 1]
            base = s >> 1  # Right-shift without feedback
            if s & 1:      # LSB was 1 → feedback applied
                derived_mask = base ^ nxt
                mask_votes[derived_mask] = mask_votes.get(derived_mask, 0) + 1
            else:           # LSB was 0 → no feedback, next = base
                if nxt != base:
                    mismatches += 1

        if mask_votes:
            best_mask, support = max(mask_votes.items(), key=lambda kv: kv[1])
            if mismatches == 0:
                print(f"Length {n}: tap_mask=0x{best_mask:0{n//4}x}, "
                      f"support={support}, mismatches=0 ← MATCH")
```

**Step 3 — Decrypt with recovered parameters:**

```python
def galois_lfsr_step(state, tap_mask, bits):
    """Single step of right-shift Galois LFSR."""
    out = state & 1
    state >>= 1
    if out:
        state ^= tap_mask
    return state & ((1 << bits) - 1)

# Seed = first keystream block (LFSR state before first step)
seed = int(keystream_bits[:lfsr_bits], 2)
state = seed

with open("flag.png.enc_lfsr", "rb") as f_in, open("flag.png", "wb") as f_out:
    block_size = lfsr_bits // 8
    while True:
        chunk = f_in.read(block_size)
        if not chunk:
            break
        key = state.to_bytes(block_size, "big")
        f_out.write(bytes(b ^ k for b, k in zip(chunk, key)))
        state = galois_lfsr_step(state, tap_mask, lfsr_bits)
```

**Key insight:** For a Galois right-shift LFSR (`state >>= 1; if lsb: state ^= tap_mask`), the tap mask is directly computable from any two consecutive states where the outgoing LSB is 1: `tap_mask = (state >> 1) XOR next_state`. This is more direct than Berlekamp-Massey (which assumes Fibonacci form) and requires no algebraic libraries. The autocorrelation approach to find the LFSR length works because correct-length windows produce consistent tap masks with zero mismatches, while incorrect lengths produce contradictory masks.

**When to recognize:** Challenge encrypts a file with known headers (PNG, PDF, ZIP, ELF) using XOR with an unknown "stream cipher" or "PRNG". Filename or description mentions "LFSR", "shift register", or "stream". The encrypted file preserves the original length (no padding), indicating a stream cipher. Try Galois tap recovery first — it's faster and simpler than Berlekamp-Massey for right-shift implementations.

**Known file headers for keystream recovery:**

| Format | Header bytes | Usable bits |
|--------|-------------|-------------|
| PNG | `89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52` | 128 |
| PDF | `25 50 44 46 2d` ("%PDF-") | 40 |
| ZIP | `50 4b 03 04` | 32 |
| ELF | `7f 45 4c 46` | 32 |
| JFIF | `ff d8 ff e0` | 32 |

---

## RC4 Second-Byte Bias Distinguisher (Hackover CTF 2015)

**Pattern:** Distinguish RC4 output from true random data by exploiting RC4's second-byte bias. The second output byte of RC4 is biased toward `0x00` with probability 1/128 (vs expected 1/256).

```python
count_zero = 0
for sample in all_samples:
    if sample[1] == 0x00:  # second byte
        count_zero += 1

# Expected: random = N/256, RC4 = N/128 (2x more zeros)
if count_zero > threshold:
    print("RC4")
else:
    print("Random")
```

**Key insight:** RC4's key scheduling creates a well-known bias where `P(second_byte == 0) = 1/128` instead of `1/256`. With ~2048 samples, RC4 produces ~16 zero second-bytes vs ~8 for random. Other RC4 biases: bytes 3-255 show weaker biases; long-term biases exist at every 256th position.

---

## XOR Consecutive Byte Correlation Attack (Defcamp 2015)

When a cipher XORs consecutive ciphertext bytes, the relationship between two ciphertexts reveals plaintext differences without knowing the key:

```python
# Observation: xorct[i] = ct[i] ^ ct[i+1]
# For two ciphertext/plaintext pairs:
# plain2[i] ^ plain1[i] == xorct1[i] ^ xorct2[i]

# With one known plaintext, decrypt the other:
for i in range(len(ct2)):
    xorct1 = ct1[i] ^ ct1[i+1]
    xorct2 = ct2[i] ^ ct2[i+1]
    plain2_char = xorct1 ^ xorct2 ^ plain1[i]
```

**Key insight:** XOR of consecutive bytes cancels key material, leaving only plaintext-dependent differences. One known plaintext breaks all subsequent messages.

---

## Fibonacci Stream Cipher Position-Shifting Oracle (EKOPARTY 2017)

**Pattern:** Custom cipher encrypts byte at position `k` as `Fib(seed + k) + plaintext_byte`. The seed is encoded in the first byte of each query. Incrementing the first byte by N shifts the Fibonacci starting position by 1, turning the server into an oracle: given any 2-byte query, the server returns the Fibonacci value at an arbitrary position XOR'd with the corresponding plaintext byte.

**Attack (flag recovery via oracle):**
1. Send queries of the form `[seed_offset][target_byte_position]` to request specific positions in the target ciphertext
2. For each position, try all 256 candidate plaintext values: `candidate_byte + Fib(adjusted_seed + pos)` should match the observed server output
3. Compare against the known target ciphertext byte to identify the correct plaintext

```python
# Oracle: server returns Fib(seed + k) XOR plaintext[k]
# Shift seed by 1 per byte offset increment
for pos in range(flag_length):
    for candidate in range(256):
        # Query with adjusted seed to reach this position
        oracle_output = query(seed_offset=pos, position=0)
        fib_val = oracle_output ^ candidate
        if matches_target_ciphertext(fib_val, pos):
            flag_bytes.append(candidate)
            break
```

**Key insight:** When keystream depends on position in a predictable mathematical way and the starting position is controllable, the server becomes a decryption oracle. Complexity is O(n * 256) queries where n is the flag length — linear in the target size.

**References:** EKOPARTY CTF 2017

---

## Z3 Constraint Solving for Custom Stream Ciphers (Tokyo Westerns 2017)

**Pattern:** Custom stream cipher with algebraic mixing: `encrypted[i] = (message[i] + key[i%13] + encrypted[i-1]) % 128`. Known plaintext prefix (e.g., `TWCTF{`) anchors the first several constraints. Z3 solver encodes each step as an integer constraint and directly recovers both the unknown key and the remaining flag characters.

```python
from z3 import *

key_len = 13
flag_len = len(encrypted)

key = [Int(f'k{i}') for i in range(key_len)]
flag = [Int(f'f{i}') for i in range(flag_len)]

s = Solver()

# Cipher recurrence: enc[i] = (flag[i] + key[i%13] + enc[i-1]) % 128
for i in range(flag_len):
    prev = encrypted[i-1] if i > 0 else 0
    s.add(encrypted[i] == (flag[i] + key[i % key_len] + prev) % 128)

# Key and flag must be printable ASCII
for k in key:
    s.add(k >= 32, k <= 126)
for f in flag:
    s.add(f >= 32, f <= 126)

# Anchor with known plaintext prefix
for i, c in enumerate(b'TWCTF{'):
    s.add(flag[i] == c)

if s.check() == sat:
    m = s.model()
    recovered = bytes([m[flag[i]].as_long() for i in range(flag_len)])
    print(recovered)
```

**Key insight:** Stream ciphers with algebraic (addition-based) mixing are directly amenable to Z3 constraint solving. Encode each step as an integer constraint, add known-plaintext anchors for the flag prefix, and let the solver recover key and remaining plaintext simultaneously. This avoids any manual analysis of the cipher structure.

**References:** Tokyo Westerns CTF 2017

---

## Keystream Recovery via Run-Length Encoding Collisions (Google CTF Quals 2018)

**Pattern (DogeStore):** Server computes `sha3(rle_decode(decrypt(xor(input, keystream))))`. Two different inputs can produce the same decoded plaintext when RLE has multiple valid encodings of the same byte run (e.g., `a\x02` vs `a\x01a\x00` both decode to `aa`). Equal hashes across different ciphertexts therefore expose XOR relationships between keystream bytes.

**Exploit:** For each candidate byte position pair `(i, i+2)` and each byte value `x`, submit two ciphertexts that differ only at those positions by `x`. If the SHA3 outputs match, `keystream[i] XOR keystream[i+2] == x`.

```python
def probe(i, x):
    # Builds two ciphertexts that differ by x at positions i and i+2
    c1 = baseline_cipher(i, 0, 0)
    c2 = baseline_cipher(i + 2, x, x)
    return sha3(server_decode(c1)) == sha3(server_decode(c2))

diffs = {}
for i in range(keystream_len - 2):
    for x in range(256):
        if probe(i, x):
            diffs[i] = x  # k[i] ^ k[i+2] = x
            break
```

Chain the recovered differences to reconstruct the entire keystream once any single byte is known (or constrained by a flag-prefix crib).

**Key insight:** Whenever a protocol post-processes plaintext with a lossy or many-to-one step (RLE, normalization, lowercase), a hash oracle over the post-processed output leaks equalities between unknown plaintext bytes — and therefore keystream bytes — without ever decrypting.

**References:** Google CTF Quals 2018 — writeup 10370

---

## LFSR Filter Linear Annihilator Attack (Hack.lu 2018)

**Pattern:** Keystream is generated by passing the LFSR state through a nonlinear filter function `f`. If `f` has a small linear annihilator `g` (i.e. `g(f(x)) = 0` over GF(2)), every ciphertext byte produces a linear equation in the LFSR state. Enough bytes yield a solvable GF(2) system that recovers the initial state.

```python
from sympy import Matrix
# 1. Build matrix A: each row is g(f(state_at_t)) expressed linearly in bits of state_0
# 2. Solve A * state_0 = 0 (kernel gives candidate seeds) over GF(2)
# 3. Filter candidates whose plaintext is printable
# Pure-Python kernel over GF(2) via rref
M_sym = Matrix(A)  # A built earlier over GF(2) as 0/1 entries
null = M_sym.nullspace()  # over QQ; reduce mod 2
for cand in null:
    cand_bits = [int(c % 2) for c in cand]
    pt = decrypt(cipher, cand_bits)
    if all(0x20 <= b < 0x7f for b in pt): print(pt)
```

<details><summary>Sage fallback (optional)</summary>

```python
from sage.all import *
R = PolynomialRing(GF(2), 'x')
F = GF(2)
# 1. Build matrix A: each row is g(f(state_at_t)) expressed linearly in bits of state_0
# 2. Solve A * state_0 = 0 (kernel gives candidate seeds)
# 3. Filter candidates whose plaintext is printable
for cand in A.right_kernel():
    pt = decrypt(cipher, cand)
    if all(0x20 <= b < 0x7f for b in pt): print(pt)
```

</details>

**Key insight:** Any LFSR-based stream cipher with a nonlinear filter is only as strong as its filter's algebraic immunity. If `f` has an annihilator of low degree, the effective keystream is linear, and Gaussian elimination recovers the state. Check the filter function against BoolFunction databases before trusting it.

**References:** Hack.lu CTF 2018 — LFSR StreamCipher, writeup 12084

---

## Hostname-as-XOR-Key Leaked via DNS Capture (SECCON 2018)

**Pattern:** Binary fetches `gethostbyaddr()` on its own IP, reverses the resulting hostname, and uses it as an XOR key for a file at `/flag.txt.encrypted`. The hostname is long and unusual (`cur10us4ndl0ngh0stn4m3`), but appears *in cleartext* in captured DNS traffic during the reverse lookup.

```python
hostname = b"cur10us4ndl0ngh0stn4m3"[::-1]  # recovered from pcap
with open('flag.txt.encrypted','rb') as f: ct = f.read()
flag = bytes(b ^ hostname[i % len(hostname)] for i, b in enumerate(ct))
```

**Key insight:** DNS queries, HTTP `Host` headers, and TLS SNI often leak secrets that the binary treats as confidential. Always pcap the challenge binary during execution — the "key" may never even touch memory you can inspect.

**References:** SECCON 2018 — Boguscrypt, writeup 12054

---

## RC4 Family — RC4 vs RC4A vs VMPC vs Spritz

**Pattern:** CTF labels the cipher `RC4` but actually uses a variant: `RC4A` (two state arrays), `VMPC` (heavy permutation), or `Spritz` (sponge-like RC4 redesign). Each variant changes the PRGA step; a naive RC4 key recovery fails silently. Distinguish via differential test before attacking.

| Cipher | State | KSA | PRGA step | Output |
|--------|-------|-----|-----------|--------|
| RC4 | `S[256]` | `j=(j+S[i]+K[i%kl])%256` | `j=(j+S[i])%256; swap(S[i],S[j]); t=(S[i]+S[j])%256` | `S[t]` |
| RC4A | `S1[256],S2[256]` | RC4 KSA on each | Alternate `S1`/`S2`: even steps use `S1`, odd use `S2`; cross `t` uses both | `S_{step%2}[t]` |
| VMPC | `P[256]` | `P[i]=i; for i: j=(j+P[i]+K[i%kl])%256`<br>`+ 768 extra permutations` | `s=P[(P[P[(s+P[n])%256]]+1)%256]` heavily permuted | `P[(P[P[s]]+1)]` |
| Spritz | `S[256] + a,i,j,k,w,z` | Spritz state init absorbs key via `absorb` | `a+=w; i+=w; j=k+S[j+S[i]]; k=i+k+S[j]; swap(S[i],S[j]); z=S[j+S[i+S[z+k]]]` | `z` |

**Differential test — which variant is this?**

Submit two keys differing in one byte and compare keystreams. RC4's first few output bytes are key-biased (second-byte `0x00` bias `1/128`), VMPC's first bytes are uniform, Spritz has no RC4 bias.

```python
def rc4_ksa(key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    return S

def rc4_prga(S, n):
    i = j = 0
    out = []
    S = S[:]
    for _ in range(n):
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) & 0xff])
    return bytes(out)

def rc4a_prga(S1, S2, n):
    i = j1 = j2 = 0
    out = []
    S1, S2 = S1[:], S2[:]
    for step in range(n):
        i = (i + 1) & 0xff
        if step % 2 == 0:
            j1 = (j1 + S1[i]) & 0xff
            S1[i], S1[j1] = S1[j1], S1[i]
            out.append(S2[(S1[i] + S1[j1]) & 0xff])
        else:
            j2 = (j2 + S2[i]) & 0xff
            S2[i], S2[j2] = S2[j2], S2[i]
            out.append(S1[(S2[i] + S2[j2]) & 0xff])
    return bytes(out)

def spritz_prga(key, n):
    # Simplified Spritz keystream after absorbing key
    N = 256
    S = list(range(N))
    a = i = j = k = z = 0
    w = 1
    # absorb key
    for b in key:
        # absorbByte
        # swap S[a], S[(b + S[a]) % N] style; simplified
        S[a], S[(b + S[a]) % N] = S[(b + S[a]) % N], S[a]
        a = (a + 1) % N
    # shuffle (simplified; real Spritz has whip/crush)
    for _ in range(2):
        for v in range(N):
            # update-like step
            pass
    out = []
    for _ in range(n):
        a = (a + w) % N
        i = (i + w) % N
        j = (k + S[(j + S[i]) % N]) % N
        k = (i + k + S[j]) % N
        S[i], S[j] = S[j], S[i]
        z = S[(j + S[(i + S[(z + k) % N]) % N]) % N]
        out.append(z)
    return bytes(out)

def differential_test(oracle, key1, key2):
    """Call oracle(key) -> keystream bytes; detect variant by bias/variance."""
    ks1 = oracle(key1)
    ks2 = oracle(key2)
    # RC4: first-byte biases; VMPC: no bias; Spritz: heavier but sponge-like
    # Count second-byte zeros over many keys to detect RC4 family
    if ks1[1] == 0:
        # RC4 second-byte zero bias 1/128 vs random 1/256
        return "likely RC4/RC4A"
    # Compare RC4 vs RC4A: RC4A keystreams for same key differ at odd positions
    if ks1[:16] == rc4_prga(rc4_ksa(key1), 16):
        return "RC4"
    # Fallback: try Spritz reference vs oracle
    return "Spritz/VMPC (test VMPC ref next)"
```

<details><summary>Sage fallback (optional)</summary>

```python
from sage.all import *

# Sage can brute-force Spritz absorb via IntegerMod; use Python path for KSA/PRGA checks
# This fallback mirrors the differential logic in Sage syntax for completeness
def sage_differential(ks_oracle, key):
    # Compare oracle keystream against Sage-computed RC4/VMPC/Spritz
    def rc4_sage(key):
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        return S
    return rc4_sage(key)
```

</details>

**Attack per variant:**

- **RC4:** Classic Fluhrer-Mantin-Shamir (FMS) / Klein / second-byte bias. See [RC4 Second-Byte Bias](#rc4-second-byte-bias-distinguisher-hackover-ctf-2015).
- **RC4A:** Two interleaved RC4s — recover `S1` from even keystream bytes, `S2` from odd bytes independently, then cross-check `t = S1[i]+S1[j1]` vs `S2[i]+S2[j2]`.
- **VMPC:** Invert 768-round KSA via Z3: `P` is a permutation (`AllDifferent`), `j` update is `(j+P[i]+K[i%kl])`. With known keystream, model as permutation constraints.
- **Spritz:** Sponge-like — absorb key nibble-by-nibble via shuffle. Known-plaintext yields `z` constraint: `z = S[j + S[i + S[z+k]]]`. Encode full state (a,i,j,k,w,S) as Z3 BitVec 8×258 and `Array(BitVec8, BitVec8)` for `S`, unroll PRGA.

**When to recognize:** Challenge says `RC4` but `S` size is 256×2, or mentions `Spritz`/`VMPC`/`RC4A`, or shows six state variables `a,i,j,k,w,z`. Run the differential test before assuming RC4 — wrong variant wastes hours.

---

## eSTREAM Portfolio — Trivium / Grain / Mickey (Reduced-Round Z3)

**Pattern:** Lightweight stream ciphers from eSTREAM: `Trivium` (80-bit key, 80-bit IV, 1152 init clocks), `Grain` (80-bit key variants 128a/128), `Mickey` (80-bit key, 211/260-bit state). CTF gives reduced initialization rounds (e.g., Trivium 300 instead of 1152, Grain 160 instead of 256, Mickey  50 instead of  211) so Z3 can solve.

| Cipher | Key | IV | State | Init clocks | CTF reduced |
|--------|-----|-----|-------|-------------|-------------|
| Trivium | 80 | 80 | 288 (93+84+111) | 1152 (4×288) | 200-400 |
| Grain v1 | 80 | 64 | 160 (80 NFSR+80 LFSR) | 160 | 80 |
| Grain-128a | 128 | 96 | 256 | 320 | 160 |
| Mickey 2.0 | 80 | 80 | 211 (100 R +111 S) | 211 | 50-100 |
| Mickey-128 2.0 | 128 | 128 | 260 | 260 | 80-120 |

**Trivium — structure and reduced-init Z3:**

Trivium state = `s[0..92] | s[93..176] | s[177..287]`. Each clock:

```
t1 = s65 ^ s92 ^ (s90 & s91) ^ s170
t2 = s161 ^ s176 ^ (s174 & s175) ^ s263
t3 = s242 ^ s287 ^ (s285 & s286) ^ s68
s_next = [t3] + s[0..92] + [t1] + s[93..176] + [t2] + s[177..286]  (shift with feedback)
keystream bit = s65 ^ s92 ^ s161 ^ s176 ^ s242 ^ s287  (before shift)
```

Init: load `key(80) | 0s | iv(80) | 0s | 1 1 1` into state, clock 1152 times without outputting.

```python
from z3 import BitVec, Bool, Solver, And, Or, Xor

def trivium_clock(state):
    """Symbolic single Trivium clock; state is list[BitVec 1 or Bool]."""
    s = state
    t1 = s[65] ^ s[92] ^ (s[90] & s[91]) ^ s[170]
    t2 = s[161] ^ s[176] ^ (s[174] & s[175]) ^ s[263]
    t3 = s[242] ^ s[287] ^ (s[285] & s[286]) ^ s[68]
    # shift registers
    ns = [t3] + s[0:93] + [t1] + s[93:177] + [t2] + s[177:288]
    # ns length 288? Trim to 288: we inserted 3 but shifted 3 positions; actual lengths 93,84,111
    # Use canonical shift:
    #   s0..92 <- t3, s0..91 ; s93..176 <- t1, s93..175 ; s177..287 <- t2, s177..286
    ns = ([t3] + s[0:93])[:93] + ([t1] + s[93:93+84])[:84] + ([t2] + s[177:177+111])[:111]
    # Flatten conceptual; real impl uses 3-register list of lists
    return ns

def trivium_keystream_bit(state):
    return state[65] ^ state[92] ^ state[161] ^ state[176] ^ state[242] ^ state[287]

def trivium_recover(ct_keystream, reduced_clocks=300):
    """Recover 80-bit Trivium key from known keystream with reduced init."""
    key = [BitVec(f'k{i}', 1) for i in range(80)]
    iv  = [BitVec(f'iv{i}', 1) for i in range(80)]  # often known; else symbolic
    s = Solver()
    # build init state symbolic
    state = key + [0]*13 + iv + [0]*4 + [0]*94 + [1,1,1]  # padded to 288 bit list of BitVec 1
    # Actually model as 288 BitVec 1 variables; constants as BitVecVal(0/1,1)
    from z3 import BitVecVal
    state = [BitVecVal(0,1) if v==0 else BitVecVal(1,1) if v in (0,1) and isinstance(v,int) else v for v in state]
    # Wait: key/iv already BitVec; need uniform: use helper to build
    # (full impl enumerates state as list of BitVec 1)
    # Clock `reduced_clocks` times
    for _ in range(reduced_clocks):
        state = trivium_clock(state)
    # Constrain keystream bits
    for i, kb in enumerate(ct_keystream):
        # keystream bit is linear combo before clock? Depends on spec order
        s.add(trivium_keystream_bit(state) == kb)
        state = trivium_clock(state)
    if s.check().sat:
        m = s.model()
        return [m[k].as_long() & 1 for k in key]
    return None
```

Note: Trivium init is fully linear except the three `AND` gates (`s90&s91` etc). Keeping `reduced_clocks < 400` leaves only ~`3*reduced_clocks` non-linear terms — Z3 friendly. At 1152 clocks, the degree explodes and Z3 times out — challenge MUST reduce it.

**Grain — 80-bit and 128-bit variants:**

Grain uses LFSR + NFSR + filter `h(x)`. Init loads key into NFSR, IV into LFSR (pad 1), then clocks 160 (Grain-v1) or 320 (Grain-128a) times feeding output back into both registers.

```python
def grain80_recover(keystream_bits, reduced_clocks=80):
    """Toy Grain-80 recovery model: NFSR 80 + LFSR 80, 160 init reduced to 80."""
    from z3 import BitVec, Solver, BitVecVal
    key = [BitVec(f'k{i}', 1) for i in range(80)]
    # LFSR init often known IV; Grain-128a: 96-bit IV
    s = Solver()
    # Model Grain80 clock: nfsr_next = lfsr[0] ^ nfsr[0]^nfsr[5]^... ; lfsr_next = feedback poly
    # Filter h = ... ; output = h(...) ^ nfsr[62] ^ ...
    # (omit full polynomial for brevity; use spec: Grain v1 uses taps (0,13,23,38,51,62) etc.)
    # Add reduced_clocks, then constrain keystream
    return s

# Checklist for Grain CTF:
# - Grain-v1: 80-bit key, 64-bit IV, 160 state, 160 init
# - Grain-128a: 128-bit key, 96-bit IV, 256 state, 320 init (feedback also includes auth)
```

**Mickey — 2.0 (211 state) vs Mickey-128 (260):**

Mickey uses two irregularly clocked registers `R` (linear) and `S` (non-linear). Init clocks `211` (Mickey 2.0) or `260` (128). Reduced variant clocks `50-100` and gives `~100` keystream bits → overdetermined Z3 system (state bits 211, equations 100+ non-linear still solvable when reduced).

```python
def mickey_clock(R, S, mixed_bit):
    """One Mickey clock; control bits decide clocking irregularity."""
    control_R = S[34] ^ R[67]  # simplified; real control uses COMP0/COMP1
    control_S = S[67] ^ R[33]
    # ... linear vs nonlinear update per register
    return R_next, S_next

# Recovery: symbolic R,S, unroll reduced_clocks + len(keystream), constrain output = R[0]^S[0]
```

<details><summary>Sage fallback (optional)</summary>

```python
from sage.all import *

# Sage: model Trivium as Boolean polynomial system; use sage's sat solver
# Trivium's 3 AND gates are degree-2; at reduced rounds the system stays degree < 4
# Sage's `BooleanPolynomialRing` + `solve` is alternative to Z3 BitVec
def sage_trivium(keystream, clocks=300):
    B = BooleanPolynomialRing(80, 'k')
    # encode Trivium equations as BooleanPolynomials, then
    # B.ideal(equations).groebner_basis() or sat_solve — prefer Z3 path for large clocks
    pass
```

</details>

**Checklist — when facing Trivium/Grain/Mickey:**

1. Read spec: confirm key/IV sizes and state layout. CTF almost always tells you the cipher name or shows the three-register shift in source.
2. Count init clocks in the binary/source — if `1152`/`160`/`320`/`211`/`260` appears verbatim, it's full-round (likely not Z3). If you see `for _ in range(300)` or `160`, it's reduced.
3. Check how much keystream you get — need `>= key_bits * 1.2` equations to overdetermine.
4. Model in Z3: `BitVec(1)` per state bit, `&` for AND, `^` for XOR. Unroll `reduced_clocks + len(keystream)` exactly. Use `Array` if state is `S[256]`-style.
5. If Z3 hangs — try `Tactic('bv').solver()` or `SolverFor('QF_BV')`, and reduce init further by binary searching `reduced_clocks`.

**References:** eSTREAM portfolio (Trivium/Grain/Mickey specs), ciphers `TriviumSpec.pdf`, `GrainSpec.pdf`.
