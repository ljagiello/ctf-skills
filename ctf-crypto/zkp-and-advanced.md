# CTF Crypto - ZKP, Solvers & Advanced Techniques

## Table of Contents
- [ZKP Attacks](#zkp-attacks)
- [Graph 3-Coloring](#graph-3-coloring)
- [Z3 SMT Solver Guide](#z3-smt-solver-guide)
- [Garbled Circuits: Free XOR Delta Recovery (LACTF 2026)](#garbled-circuits-free-xor-delta-recovery-lactf-2026)
- [Bigram/Trigram Substitution -> Constraint Solving (LACTF 2026)](#bigramtrigram-substitution-constraint-solving-lactf-2026)
- [Shamir Secret Sharing with Deterministic Coefficients (LACTF 2026)](#shamir-secret-sharing-with-deterministic-coefficients-lactf-2026)
- [Race Condition in Crypto-Protected Endpoints (LACTF 2026)](#race-condition-in-crypto-protected-endpoints-lactf-2026)
- [Garbled Circuits: AES Key Recovery via Metadata Leakage (srdnlenCTF 2026)](#garbled-circuits-aes-key-recovery-via-metadata-leakage-srdnlenctf-2026)
- [Post-Quantum Signature Fault Injection: MAYO (srdnlenCTF 2026)](#post-quantum-signature-fault-injection-mayo-srdnlenctf-2026)
- [Lattice-Based Threshold Signature Attack: FROST (srdnlenCTF 2026)](#lattice-based-threshold-signature-attack-frost-srdnlenctf-2026)

---

## ZKP Attacks

- Look for information leakage in proofs
- If proving IMPOSSIBLE problem (e.g., 3-coloring K4), you must cheat
- Find hash collisions to commit to one value but reveal another
- PRNG state recovery: salts generated from seeded PRNG can be predicted
- Small domain brute force: if you know `commit(i) = sha256(salt(i), color(i))` and have salt, brute all colors

---

## Graph 3-Coloring

```python
import networkx as nx
nx.coloring.greedy_color(G, strategy='saturation_largest_first')
```

---

## Z3 SMT Solver Guide

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

---

## Garbled Circuits: Free XOR Delta Recovery (LACTF 2026)

**Pattern (sisyphus):** Yao's garbled circuit with free XOR optimization. Circuit designed so normal evaluation only reaches one wire label, but the other is needed.

**Free XOR property:** Wire labels satisfy `W_0 XOR W_1 = delta` for global secret delta.

**Attack:** XOR three of four encrypted truth table entries to cancel AES terms:
```python
# Encrypted rows: E_i = AES(key_a_i XOR key_b_i, G_out_f(a,b))
# XOR of three rows where AES inputs differ by delta causes cancellation
# Reveals delta directly, then compute: W_1 = W_0 XOR delta
```

**General lesson:** In garbled circuits, if you can obtain any two labels for the same wire, you recover delta and can compute all labels.

---

## Bigram/Trigram Substitution -> Constraint Solving (LACTF 2026)

**Pattern (lazy-bigrams):** Bigram substitution cipher where plaintext has known structure (NATO phonetic alphabet).

**OR-Tools CP-SAT approach:**
1. Model substitution as injective mapping (IntVar per bigram)
2. Add crib constraints from known flag prefix
3. Add **regular language constraint** (automaton) for valid NATO word sequences
4. Solver finds unique solution

**Pattern (not-so-lazy-trigrams):** "Trigram substitution" that decomposes into three independent monoalphabetic ciphers on positions mod 3.

**Decomposition insight:** If cipher uses `shuffle[pos % n][char]`, each residue class `pos = k (mod n)` is an independent monoalphabetic substitution. Solve each separately with frequency analysis or known-plaintext.

---

## Shamir Secret Sharing with Deterministic Coefficients (LACTF 2026)

**Pattern (spreading-secrets):** Coefficients `a_1...a_9` are deterministic functions of secret s (via RNG seeded with s). One share (x_0, y_0) is revealed.

**Vulnerability:** Given one share, the equation `y_0 = s + g(s)*x_0 + g^2(s)*x_0^2 + ... + g^9(s)*x_0^9` is **univariate** in s.

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

---

## Race Condition in Crypto-Protected Endpoints (LACTF 2026)

**Pattern (misdirection):** Endpoint has TOCTOU vulnerability: `if counter < 4` check happens before increment, allowing concurrent requests to all pass the check.

**Exploitation:**
1. **Cache-bust signatures:** Modify each request slightly (e.g., prepend zeros to nonce) so server can't use cached verification results
2. **Synchronize requests:** Use multiprocessing with barrier to send ~80 simultaneous requests
3. All pass `counter < 4` check before any increments -> counter jumps past limit

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

---

## Garbled Circuits: AES Key Recovery via Metadata Leakage (srdnlenCTF 2026)

**Pattern (FHAES):** Service evaluates AES via garbled circuits with a fixed per-connection key. Exploit garbling metadata rather than AES cryptanalysis.

**Attack:**
1. Construct a custom circuit with one attacker-controlled AND gate that leaks the global Free-XOR offset delta
2. Use delta to locally evaluate the key-schedule section (first 1360 AND gates) as the evaluator
3. For each of the first 16 key-schedule S-box calls, brute-force the input byte by re-garbling the S-box chunk and comparing observed AND tables
4. Reconstruct key words from S-box outputs and recover the full 128-bit key through algebraic manipulation of the AES-128 schedule recurrence

```python
def garble_and(A, B, D, and_idx):
    """Reproduce garbling with proper parity handling."""
    r = B & 1
    alpha = A & 1
    beta = B & 1
    # Computes gate0, gate1, z output via hash-based approach
    return gate0, gate1, z

def evaluator_and(A, B, gate0, gate1, and_idx):
    """Evaluate AND gate using hash-based approach."""
    hashA = h_wire(A, and_idx)
    hashB = h_wire(B, and_idx)
    L = hashA if (A & 1) == 0 else (hashA ^ gate0)
    R = hashB if (B & 1) == 0 else (hashB ^ gate1)
    return L ^ R ^ (A * (B & 1))
```

**Key insight:** Garbled circuits that use free XOR optimization with fixed keys across sessions leak key material through the AND gate truth tables. Each S-box has a small enough input space (256 values) to brute-force when you know delta. This extends the LACTF technique from "recovering delta" to "recovering the entire AES key."

---

## Post-Quantum Signature Fault Injection: MAYO (srdnlenCTF 2026)

**Pattern (Faulty Mayo):** One-byte fault injection window in `mayo_sign_signature` before final `s = v + O*x` construction. Controlled bit flips across 64 signature queries recover the secret matrix O row by row.

**Attack:**
1. Reverse binary to map fault offsets to `mayo_sign_signature` instructions
2. For each of 64 rows of secret matrix O, use faulted signatures to extract linear equations over GF(16)
3. Solve 17-variable linear systems over GF(16) for each row using Gaussian elimination
4. Rebuild equivalent signer using recovered O and public seed from compressed public key
5. Forge valid signature for challenge message

**GF(16) Gaussian elimination:**
```python
# Precompute multiplication and inverse tables for GF(16)
# GF(16) = GF(2)[x] / (x^4 + x + 1), elements 0-15
INV = [0] * 16  # multiplicative inverses
MUL = [[0]*16 for _ in range(16)]  # multiplication table

def solve_linear_gf16(equations, nvars=17):
    """Gaussian elimination over GF(16)."""
    A = [x[:] + [y] for x, y in equations]
    m, row = len(A), 0
    for col in range(nvars):
        piv = next((r for r in range(row, m) if A[r][col] != 0), None)
        if piv is None: continue
        A[row], A[piv] = A[piv], A[row]
        invp = INV[A[row][col]]
        A[row] = [MUL[invp][v] for v in A[row]]
        for r in range(m):
            if r != row and A[r][col] != 0:
                f = A[r][col]
                A[r] = [A[r][c] ^ MUL[f][A[row][c]] for c in range(nvars + 1)]
        row += 1
    return [A[i][nvars] for i in range(nvars)]
```

**Key insight:** Post-quantum signature schemes like MAYO can be broken with fault injection if you can cause controlled bit flips during signing. Each fault creates a linear equation over GF(16), and 17+ equations per row suffice to recover the secret. This is analogous to DFA on classical schemes but over extension fields.

---

## Lattice-Based Threshold Signature Attack: FROST (srdnlenCTF 2026)

**Pattern (Threshold):** Preprocessing queue capacity allows collecting many signatures. Fixed challenge construction enables solving 1D noisy linear equations per coefficient.

**Attack:**
1. Exploit queue-depth cap (≤8 active) rather than total-usage cap by alternating menu options
2. Force fixed challenge `c` by choosing commitment `w₀` each query to zero aggregate commitment before high-bit extraction
3. With fixed `c`, each coefficient becomes: `z = λ·u + noise (mod q)`
4. Select multiple signer subsets to obtain different Lagrange coefficient scales (small/mid/huge) for each target signer
5. Solve via interval intersection and maximum-likelihood selection
6. Recover 7 signer shares; combine with own share; reconstruct master secret via Lagrange interpolation

**Interval intersection algorithm:**
```python
from math import ceil, floor

def intersect_intervals(intervals, lam, z, q, B):
    """Refine candidate intervals using one (λ, z) observation with noise bound B."""
    out = []
    for lo, hi in intervals:
        if lam > 0:
            kmin = ceil((lam * lo - z - B) / q)
            kmax = floor((lam * hi - z + B) / q)
            for k in range(kmin, kmax + 1):
                a = (z + q * k - B) / lam
                b = (z + q * k + B) / lam
                lo2, hi2 = max(lo, a), min(hi, b)
                if lo2 <= hi2:
                    out.append((lo2, hi2))
    # Merge overlapping intervals
    out.sort()
    merged = [out[0]] if out else []
    for lo, hi in out[1:]:
        if lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged
```

**Key insight:** Threshold signature schemes can leak individual shares when the challenge value is controlled. By querying with different signer subsets, you get different Lagrange coefficient scales for the same unknown share, allowing iterative interval refinement. With enough observations, the interval converges to a unique value.
