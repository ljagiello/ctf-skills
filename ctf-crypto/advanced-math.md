# CTF Crypto - Advanced Mathematical Attacks

## Table of Contents
- [Elliptic Curve Isogenies](#elliptic-curve-isogenies)
- [Pohlig-Hellman Attack (Weak ECC)](#pohlig-hellman-attack-weak-ecc)
- [LLL Algorithm for Approximate GCD](#lll-algorithm-for-approximate-gcd)
- [Coppersmith's Method (Close Private Keys)](#coppersmiths-method-close-private-keys)
- [Coppersmith's Method (Structured Primes, LACTF 2026)](#coppersmiths-method-structured-primes-lactf-2026)
- [Clock Group (x²+y²≡1 mod p) DLP (LACTF 2026)](#clock-group-xy1-mod-p-dlp-lactf-2026)
- [Quaternion RSA](#quaternion-rsa)
- [Monotone Function Inversion with Partial Output](#monotone-function-inversion-with-partial-output)
- [Polynomial Arithmetic in GF(2)[x]](#polynomial-arithmetic-in-gf2x)
- [RSA Signing Bug](#rsa-signing-bug)
- [Non-Permutation S-box Collision Attack (Nullcon 2026)](#non-permutation-s-box-collision-attack-nullcon-2026)
- [Polynomial CRT in GF(2)[x] (Nullcon 2026)](#polynomial-crt-in-gf2x-nullcon-2026)
- [Manger's RSA Padding Oracle Attack (Nullcon 2026)](#mangers-rsa-padding-oracle-attack-nullcon-2026)
- [Affine Cipher over Non-Prime Modulus (Nullcon 2026)](#affine-cipher-over-non-prime-modulus-nullcon-2026)

---

## Elliptic Curve Isogenies

Isogeny-based crypto challenges are often **graph traversal problems in disguise**:

**Key concepts:**
- j-invariant uniquely identifies curve isomorphism class
- Curves connected by isogenies form a graph (often tree-like)
- Degree-2 isogenies: each node has ~3 neighbors (2 children + 1 parent)

**Modular polynomial approach:**
- Connected j-invariants j₁, j₂ satisfy Φ₂(j₁, j₂) = 0
- Find neighbors by computing roots of Φ₂(j, Y) in the finite field
- Much faster than computing actual isogenies

**Pathfinding in isogeny graphs:**
```python
# Height estimation via random walks to leaves
def estimate_height(j, neighbors_func, trials=100):
    min_depth = float('inf')
    for _ in range(trials):
        depth, curr = 0, j
        while True:
            nbrs = neighbors_func(curr)
            if len(nbrs) <= 1:  # leaf node
                break
            curr = random.choice(nbrs)
            depth += 1
        min_depth = min(min_depth, depth)
    return min_depth

# Find path between two nodes via LCA
def find_path(start, end):
    # Ascend from both nodes tracking heights
    # Find least common ancestor
    # Concatenate: path_up(start) + reversed(path_up(end))
```

**Complex multiplication (CM) curves:**
- Discriminant D = f² · D_K where D_K is fundamental discriminant
- Conductor f determines tree depth
- Look for special discriminants: -163, -67, -43, etc. (class number 1)

## Pohlig-Hellman Attack (Weak ECC)

For elliptic curves with smooth order (many small prime factors):

```python
from sage.all import *

# Factor curve order
E = EllipticCurve(GF(p), [a, b])
n = E.order()
factors = factor(n)

# Solve DLP in each small subgroup
partial_logs = []
for (prime, exp) in factors:
    # Compute subgroup generator
    cofactor = n // (prime ** exp)
    G_sub = cofactor * G
    P_sub = cofactor * P  # Target point

    # Solve small DLP
    d_sub = discrete_log(P_sub, G_sub, ord=prime**exp)
    partial_logs.append((d_sub, prime**exp))

# Combine with CRT
from sympy.ntheory.modular import crt
moduli = [m for (_, m) in partial_logs]
residues = [r for (r, _) in partial_logs]
private_key, _ = crt(moduli, residues)
```

## LLL Algorithm for Approximate GCD

**Pattern (Grinch's Cryptological Defense):** Server gives hints `h_i = f * p_i + n_i` where f is the flag, p_i are small primes, n_i is small noise.

**Lattice construction:**
```python
from sage.all import *

# Collect 3 hints from server
# h_i = f * p_i + n_i (noise is small)
# Construct lattice where short vector reveals primes

M = matrix(ZZ, [
    [1, 0, 0, h1],
    [0, 1, 0, h2],
    [0, 0, 1, h3],
    [0, 0, 0, -1]  # Scaling factor
])

reduced = M.LLL()
# Short vector contains p1, p2, p3
# Recover f = (h1 - n1) / p1
```

## Coppersmith's Method (Close Private Keys)

**Pattern (Duality of Key):** Two RSA key pairs with d1 ≈ d2 (small difference).

**Attack:**
```python
# From e1*d1 ≡ 1 mod φ and e2*d2 ≡ 1 mod φ:
# d2 - d1 ≡ (e1*e2)^(-1) * (e1 - e2) mod p

# Construct polynomial f(x) = (r - x) mod p where x = d2-d1
# Use Coppersmith small_roots() to find x

R.<x> = PolynomialRing(Zmod(N))
r = inverse_mod(e1*e2, N) * (e1 - e2) % N
f = r - x
roots = f.small_roots(X=2^128, beta=0.5)  # Adjust bounds
# x = d2 - d1, recover p from gcd(f(x), N)
```

## Coppersmith's Method (Structured Primes, LACTF 2026)

**Pattern (six-seven-again):** p = base + 10^k · x where base is fully known, x is small.

**Condition:** x < N^{1/e} for degree-e polynomial (≈ N^0.25 for linear).

**Attack:**
```python
# p = base + 10^k * x, so x ≡ -base * (10^k)^{-1} (mod p)
# Since p | N, construct polynomial with root x mod N
R.<x> = PolynomialRing(Zmod(N))
inv_10k = inverse_mod(10^k, N)
f = x + (base * inv_10k) % N  # Must be monic!
roots = f.small_roots(X=2^70, beta=0.5)
if roots:
    x_val = int(roots[0])
    p = base + 10^k * x_val
    q = N // p
```

**Key details:**
- Polynomial MUST be monic (leading coefficient 1)
- `beta=0.5` means we're looking for a factor ≥ N^0.5
- `X` parameter is upper bound on root size
- Works for any "partially known prime" pattern

## Clock Group (x²+y²≡1 mod p) DLP (LACTF 2026)

**Pattern (the-clock):** Diffie-Hellman on the unit circle group.

**Group structure:**
```python
# Group law: (x1,y1) * (x2,y2) = (x1*y2 + y1*x2, y1*y2 - x1*x2)
# Identity: (0, 1)
# Inverse of (x, y): (-x, y)
# Group order: p + 1 (NOT p - 1!)

def clock_mul(P, Q, p):
    x1, y1 = P
    x2, y2 = Q
    return ((x1*y2 + y1*x2) % p, (y1*y2 - x1*x2) % p)

def clock_pow(P, n, p):
    result = (0, 1)  # identity
    base = P
    while n > 0:
        if n & 1:
            result = clock_mul(result, base, p)
        base = clock_mul(base, base, p)
        n >>= 1
    return result
```

**Recovering hidden prime p:**
```python
# Given points on the curve, p divides (x^2 + y^2 - 1)
from math import gcd
vals = [x**2 + y**2 - 1 for x, y in known_points]
p = reduce(gcd, vals)
# May need to remove small factors
```

**Pohlig-Hellman when p+1 is smooth:**
```python
order = p + 1
factors = factor(order)
# Standard Pohlig-Hellman in the clock group
# Solve d in each prime-power subgroup, CRT combine
```

**CRITICAL:** The order is p+1, isomorphic to norm-1 elements of GF(p²)*. This is different from multiplicative group (order p-1) and elliptic curves (order ≈ p).

## Quaternion RSA

**Pattern:** RSA encryption using Hamilton quaternion algebra over Z/nZ. The plaintext is embedded into quaternion components that are linear combinations of m, p, q, then the quaternion matrix is raised to power e mod n.

**Key structure:**
```python
# Quaternion q = a0 + a1*i + a2*j + a3*k
# Components are linear in m, p, q:
a0 = m
a1 = m + α1*p + β1*q  # e.g., m + 3p + 7q
a2 = m + α2*p + β2*q  # e.g., m + 11p + 13q
a3 = m + α3*p + β3*q  # e.g., m + 17p + 19q

# 4x4 matrix representation:
# Row 0: [a0, -a1, -a2, -a3]
# Row 1: [a1,  a0, -a3,  a2]
# Row 2: [a2,  a3,  a0, -a1]
# Row 3: [a3, -a2,  a1,  a0]

# Ciphertext = first row of matrix^e mod n
```

**Critical property:** For quaternion `q = s + v` (scalar + vector), `q^k = s_k + t_k*v` — the vector part stays **proportional** under exponentiation. This means the ratios of imaginary components are preserved:

`c1 : c2 : c3 = a1 : a2 : a3 (mod n)`

**Factoring n (the attack):**

```python
import math

# Extract quaternion components from ciphertext row [ct0, ct1, ct2, ct3]
# Row 0 = [c0, -c1, -c2, -c3], so negate last 3:
c0, c1, c2, c3 = ct[0], (-ct[1]) % n, (-ct[2]) % n, (-ct[3]) % n

# From ratio preservation: c1*a2 = c2*a1 (mod n), c1*a3 = c3*a1 (mod n)
# Substituting a_i = m + αi*p + βi*q and eliminating m between two equations:
# Result: A*p + B*q ≡ 0 (mod n=pq) => q|A, p|B

# For components a1=m+α1p+β1q, a2=m+α2p+β2q, a3=m+α3p+β3q:
# Eliminate m from (c1*a2=c2*a1) and (c1*a3=c3*a1):
A = (-(α1*c1 - α2*c2)*(c1-c3) + (α1*c1 - α3*c3)*(c1-c2)) % n
B = (-(β1*c1 - β2*c2)*(c1-c3) + (β1*c1 - β3*c3)*(c1-c2)) % n

# More concretely for coefficients [3,7], [11,13], [17,19]:
A = (-(11*c1-3*c2)*(c1-c3) + (17*c1-3*c3)*(c1-c2)) % n
B = (-(13*c1-7*c2)*(c1-c3) + (19*c1-7*c3)*(c1-c2)) % n

q_factor = math.gcd(A, n)  # gives q
p_factor = math.gcd(B, n)  # gives p
```

**Decryption after factoring:**

Over F_p, the quaternion algebra H_p ≅ M_2(F_p) (Wedderburn theorem), so the quaternion's multiplicative order divides p²-1. Decrypt using:

```python
# Group order for quaternions over F_p divides p²-1
d_p = pow(e, -1, p**2 - 1)
d_q = pow(e, -1, q**2 - 1)

# Decrypt mod p and mod q separately, then CRT
enc_mod_p = [[x % p for x in row] for row in enc_matrix]
enc_mod_q = [[x % q for x in row] for row in enc_matrix]
dec_p = matrix_pow(enc_mod_p, d_p, p)
dec_q = matrix_pow(enc_mod_q, d_q, q)

# CRT combine: dec_matrix[0][0] = m (the flag)
m = CRT(dec_p[0][0], dec_q[0][0], p, q)
flag = long_to_bytes(m)
```

**Why it works:** The "reduced dimension" is that 4D quaternion exponentiation reduces to a 2D recurrence (scalar + magnitude of vector), and the direction of the vector part is invariant. This leaks the ratio a1:a2:a3 directly from the ciphertext, enabling factorization.

**References:** SECCON CTF 2023 "RSA 4.0", 0xL4ugh CTF "Reduced Dimension"

---

## Monotone Function Inversion with Partial Output

**Pattern:** A flag is converted to a real number, pushed through an invertible/monotone function (e.g., iterated map, spiral), then some output digits are masked/erased. Recover the masked digits to invert and get the flag.

**Identification:**
- Output is a high-precision decimal number with some digits replaced by `?`
- The transformation is smooth/monotone (invertible via root-finding)
- Flag format constrains the input to a narrow range
- Challenge hints like "brute won't cut it" or "binary search"

**Key insight:** For a monotone function `f`, knowing the flag format (e.g., `0xL4ugh{...}`) constrains the output to a tiny interval. Many "unknown" output digits are actually **fixed** across all valid inputs and can be determined immediately.

**Attack: Hierarchical Digit Recovery**

1. **Determine fixed digits:** Compute `f(flag_min)` and `f(flag_max)` for all valid flags. Digits that are identical in both outputs are fixed regardless of flag content.

2. **Sequential refinement:** Determine remaining unknown digits one at a time (largest contribution first). For each candidate value (0-9), invert `f` and check if the result is a valid flag (ASCII, correct format).

3. **Validation:** The correct digit produces readable ASCII text; wrong digits produce garbage bytes in the flag.

```python
import mpmath

# Match SageMath's RealField(N) precision exactly:
# RealField(256) = 256-bit MPFR mantissa
mpmath.mp.prec = 256  # BINARY precision (not decimal!)
# For decimal: mpmath.mp.dps = N sets decimal places

phi = (mpmath.mpf(1) + mpmath.sqrt(mpmath.mpf(5))) / 2

def forward(x0):
    """The challenge's transformation (e.g., iterated spiral)."""
    x = x0
    for i in range(iterations):
        r = mpmath.mpf(i) / mpmath.mpf(iterations)
        x = r * mpmath.sqrt(x*x + 1) + (1 - r) * (x + phi)
    return x

def invert(y_target, x_guess):
    """Invert via root-finding (Newton's method)."""
    def f(x0):
        return forward(x0) - y_target
    return mpmath.findroot(f, x_guess, tol=mpmath.mpf(10)**(-200))

# Hierarchical search: determine unknown digits sequentially
masked = "?7086013?3756162?51694057..."
unknown_positions = [0, 8, 16, 25, 33, ...]

# Step 1: Fix digits that are constant across all valid flags
# (compute forward for min/max valid flag, compare)

# Step 2: For each remaining unknown (largest positional weight first):
for pos in remaining_unknowns:
    for digit in range(10):
        # Set this digit, others to middle value (5)
        output_val = construct_number(known_digits | {pos: digit})
        x_inv = invert(output_val, x_guess=0.335)
        flag_int = int(x_inv * mpmath.power(10, flag_digits))
        flag_bytes = flag_int.to_bytes(30, 'big')

        # Check: starts with prefix? Ends with suffix? All ASCII?
        if is_valid_flag(flag_bytes):
            known_digits[pos] = digit
            break
```

**Why it works:** Each unknown digit affects a different decimal scale in the output number. The largest unknown (earliest position) shifts the inverted value by the most, determining several bytes of the flag. Fixing it and moving to the next unknown reveals more bytes. Total work: `10 * num_unknowns` inversions (linear, not exponential).

**Precision matching:** SageMath's `RealField(N)` uses MPFR with N-bit mantissa. In mpmath, set `mp.prec = N` (NOT `mp.dps`). The last few output digits are precision-sensitive and will only match with the correct binary precision.

**Derivative analysis:** For the spiral-type map `x → r*sqrt(x²+1) + (1-r)*(x+φ)`, the per-step derivative is `r*x/sqrt(x²+1) + (1-r) ≈ 1`, so the total derivative stays near 1 across all 81 iterations. This means precision is preserved through inversion — 67 known output digits give ~67 digits of input precision.

**References:** 0xL4ugh CTF "SpiralFloats"

---

## Polynomial Arithmetic in GF(2)[x]

**Key operations for CTF crypto:**
```python
def poly_add(a, b):
    """Addition in GF(2)[x] = XOR of coefficient integers."""
    return a ^ b

def poly_mul(a, b):
    """Carry-less multiplication in GF(2)[x]."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        b >>= 1
    return result

def poly_divmod(a, b):
    """Division with remainder in GF(2)[x]."""
    if b == 0:
        raise ZeroDivisionError
    deg_a, deg_b = a.bit_length() - 1, b.bit_length() - 1
    q = 0
    while deg_a >= deg_b and a:
        shift = deg_a - deg_b
        q ^= (1 << shift)
        a ^= (b << shift)
        deg_a = a.bit_length() - 1
    return q, a  # quotient, remainder
```

**Applications:** CRT in GF(2)[x] for recovering secrets from polynomial remainders, Reed-Solomon-like error correction.

---

## RSA Signing Bug

**Vulnerability:** Using wrong exponent for signing
- Correct: `sign = m^d mod n` (private exponent)
- Bug: `sign = m^e mod n` (public exponent)

**Exploitation:**
```python
# If signature is m^e mod n, we can "encrypt" to verify
# and compute e-th root to forge signatures
from sympy import integer_nthroot

# For small e (e.g., 3), take e-th root if m^e < n
forged_sig, exact = integer_nthroot(message, e)
if exact:
    print(f"Forged signature: {forged_sig}")
```

---

## Non-Permutation S-box Collision Attack (Nullcon 2026)

**Detection:** Check if S-box is a permutation:
```python
sbox = [...]  # 256 entries
if len(set(sbox)) < 256:
    from collections import Counter
    counts = Counter(sbox)
    for val, cnt in counts.items():
        if cnt > 1:
            colliders = [i for i in range(256) if sbox[i] == val]
            delta = colliders[0] ^ colliders[1]
            print(f"S[{hex(colliders[0])}] = S[{hex(colliders[1])}] = {hex(val)}, delta = {hex(delta)}")
```

**Attack:** For each key byte position k (0-15):
1. Try all 256 values v: encrypt two plaintexts differing by `delta` at position k
2. When `ct1 == ct2`: S-box input at position k was in the collision set `{c0, c1}`
3. Deduce: `key[k] = v ^ round_const` OR `key[k] = v ^ round_const ^ delta`
4. 2-way ambiguity per byte -> 2^16 = 65,536 candidates, brute-force locally

**Total oracle queries:** 16 x 256 + 1 = 4,097 (reference ciphertext + probes).

**Key lessons:**
- SAT/SMT solvers time out on 15+ rounds of symbolic AES even with simplified S-box
- Integral/square attacks fail because non-permutation S-box breaks balance property
- Always check S-box for non-permutation FIRST before attempting complex cryptanalysis

---

## Polynomial CRT in GF(2)[x] (Nullcon 2026)

**Pattern:** Server gives `r = flag mod f` where `f` is a random polynomial over GF(2).

**Attack:** Chinese Remainder Theorem in polynomial ring GF(2)[x]:
1. Collect ~20 pairs `(r_i, f_i)` from server (each `f_i` is ~32-bit random polynomial)
2. Filter for coprime pairs using polynomial GCD
3. Apply CRT to combine: `flag = r_i (mod f_i)` for all i
4. With ~13-20 coprime 32-bit moduli (>= 400 bits combined), flag is unique

```python
def poly_crt(remainders, moduli):
    """CRT in GF(2)[x]: combine (r_i, f_i) pairs."""
    result, mod = remainders[0], moduli[0]
    for i in range(1, len(remainders)):
        g, s, t = poly_xgcd(mod, moduli[i])
        combined_mod = poly_mul(mod, moduli[i])
        result = poly_add(poly_mul(poly_mul(remainders[i], s), mod),
                         poly_mul(poly_mul(result, t), moduli[i]))
        result = poly_mod(result, combined_mod)
        mod = combined_mod
    return result, mod
```

---

## Manger's RSA Padding Oracle Attack (Nullcon 2026)

**Setup:**
- Key `k < 2^64` (small), RSA modulus `n` is large (1337+ bits)
- Oracle: "invalid padding" = `decrypt < threshold`, "error" = `decrypt >= threshold`
- No modular wrap-around because `k << n`

**Attack (simplified Manger's):**
```python
# Phase 1: Find f1 where k * f1 >= threshold
f1 = 1
while oracle(encrypt(f1)) == "below":  # multiply ciphertext by f1^e mod n
    f1 *= 2
# f1/2 < threshold/k <= f1, so k is in [threshold/f1, threshold/(f1/2)]

# Phase 2: Binary search for exact key
lo, hi = 0, threshold
while lo < hi:
    mid = (lo + hi) // 2
    f_test = ceil(threshold, mid + 1)  # f such that k*f >= threshold iff k > mid
    if oracle(encrypt(f_test)) == "above":
        hi = mid
    else:
        lo = mid + 1
key = lo  # ~64 queries for 64-bit key
```

**Total queries:** ~128 (64 for phase 1 + 64 for phase 2).

---

## Affine Cipher over Non-Prime Modulus (Nullcon 2026)

**Pattern:** `c = A @ p + b (mod m)` where A is nxn matrix, m may not be prime (e.g., 65).

**Chosen-plaintext attack:**
1. Send n+1 crafted inputs to get n+1 ciphertext blocks
2. Difference attack: `c_i - c_0 = A @ (p_i - p_0) (mod m)`
3. Build difference matrices D (plaintext) and E (ciphertext)
4. Solve: `A = E @ D^{-1} (mod m)` using Gauss-Jordan with GCD invertibility checks
5. Recover: `b = c_0 - A @ p_0 (mod m)`

**CRT approach for composite modulus (preferred):**
```python
def crt2(r1, m1, r2, m2):
    """CRT: x = r1 (mod m1) and x = r2 (mod m2)"""
    m1_inv = pow(m1, m2 - 2, m2)  # Fermat's little theorem
    t = ((r2 - r1) * m1_inv) % m2
    return (r1 + m1 * t) % (m1 * m2)

# For m=65=5x13: Gaussian elimination in GF(5) and GF(13) separately
A5, b5 = A % 5, rhs % 5
A13, b13 = A % 13, rhs % 13
x5 = gauss_elim(A5, b5, mod=5)
x13 = gauss_elim(A13, b13, mod=13)
x = [crt2(x5[i], 5, x13[i], 13) for i in range(len(x5))]
```
