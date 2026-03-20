# CTF Crypto - Exotic Algebraic Structures

## Table of Contents
- [Braid Group DH — Alexander Polynomial Multiplicativity (DiceCTF 2026)](#braid-group-dh--alexander-polynomial-multiplicativity-dicectf-2026)
- [Monotone Function Inversion with Partial Output](#monotone-function-inversion-with-partial-output)
- [Tropical Semiring Residuation Attack (BearCatCTF 2026)](#tropical-semiring-residuation-attack-bearcatctf-2026)
- [Paillier Cryptosystem Attack (SECCON 2015)](#paillier-cryptosystem-attack-seccon-2015)
- [Hamming Code Error Correction with Helical Interleaving (Sharif CTF 2016)](#hamming-code-error-correction-with-helical-interleaving-sharif-ctf-2016)
- [ElGamal Universal Re-encryption (Sharif CTF 2016)](#elgamal-universal-re-encryption-sharif-ctf-2016)
- [Paillier Oracle Size Bypass via Ciphertext Factoring (BSidesSF 2025)](#paillier-oracle-size-bypass-via-ciphertext-factoring-bsidessf-2025)

---

## Braid Group DH — Alexander Polynomial Multiplicativity (DiceCTF 2026)

**Pattern (Plane or Exchange):** Diffie-Hellman key exchange built over mathematical braids. Public keys are derived by connecting a private braid to public info, then scrambled with Reidemeister-like moves. Shared secret = `sha256(normalize(calculate(connect(my_priv, their_pub))))`. The `calculate()` function computes the Alexander polynomial of the braid.

**Protocol structure:**
```python
import sympy as sp
import hashlib

t = sp.Symbol('t')

def compose(p1, p2):
    return [p1[p2[i]] for i in range(len(p1))]

def inverse(p):
    inv = [0] * len(p)
    for i, j in enumerate(p):
        inv[j] = i
    return inv

def connect(g1, g2):
    """Concatenate two braids with a swap at the junction."""
    x1, o1 = g1
    x2, o2 = g2
    l = len(x1)
    new_x = list(x1) + [v + l for v in x2]
    new_o = list(o1) + [v + l for v in o2]
    # Swap at junction
    new_x[l-1], new_x[l] = new_x[l], new_x[l-1]
    return (new_x, new_o)

def sweep(ap):
    """Compute winding number matrix from arc presentation."""
    l = len(ap)
    current_row = [0] * l
    matrix = []
    for pair in ap:
        c1, c2 = sorted(pair)
        diff = pair[1] - pair[0]
        s = 1 if diff > 0 else (-1 if diff < 0 else 0)
        for c in range(c1, c2):
            current_row[c] += s
        matrix.append(list(current_row))
    return matrix

def mine(point):
    x, o = point
    return sweep([*zip(x, o)])

def calculate(point):
    """Compute Alexander polynomial from braid."""
    mat = sp.Matrix([[t**(-x) for x in y] for y in mine(point)])
    return mat.det(method='bareiss') * (1 - t)**(1 - len(point[0]))

def normalize(calculation):
    """Convert Laurent polynomial to standard form."""
    poly = sp.expand(sp.simplify(calculation))
    all_exp = [term.as_coeff_exponent(t)[1] for term in poly.as_ordered_terms()]
    min_exp = min(all_exp)
    poly = sp.expand(sp.simplify(poly * t**(-min_exp)))
    if poly.coeff(t, 0) < 0:
        poly *= -1
    return poly

# Key exchange:
# alice_pub = scramble(connect(pub_info, alice_priv), 1000)
# bob_pub = scramble(connect(pub_info, bob_priv), 1000)
# shared = sha256(str(normalize(calculate(connect(alice_priv, bob_pub)))))
```

**The fatal vulnerability — Alexander polynomial multiplicativity:**

The Alexander polynomial satisfies `Δ(β₁·β₂) = Δ(β₁) × Δ(β₂)` under braid concatenation. This makes the scheme abelian:

```python
# Eve computes shared secret from public values only:
calc_pub = normalize(calculate(pub_info))
calc_alice = normalize(calculate(alice_pub))
calc_bob = normalize(calculate(bob_pub))

# Recover Alice's private polynomial
calc_alice_priv = sp.cancel(calc_alice / calc_pub)  # exact division

# Shared secret = calc(alice_priv) * calc(bob_pub) = calc(bob_priv) * calc(alice_pub)
shared_poly = normalize(sp.expand(calc_alice_priv * calc_bob))
shared_hex = hashlib.sha256(str(shared_poly).encode()).hexdigest()

# Decrypt XOR stream cipher
key = bytes.fromhex(shared_hex)
while len(key) < len(ciphertext):
    key += hashlib.sha256(key).digest()
plaintext = bytes(a ^ b for a, b in zip(ciphertext, key))
```

**Computational trick for large matrices:**

Direct sympy Bareiss on rational-function matrices (e.g., 30×30 with entries `t^(-w)`) is extremely slow. Clear denominators first:

```python
# Winding numbers range from w_min to w_max (e.g., -1 to 5)
# Multiply all entries by t^w_max to get polynomial matrix
k = max(abs(w) for row in winding_matrix for w in row)
n = len(winding_matrix)

# Original: M[i][j] = t^(-w[i][j])
# Scaled:   M'[i][j] = t^(k - w[i][j])  (all non-negative powers)
mat_poly = sp.Matrix([[t**(k - w) for w in row] for row in winding_matrix])
det_scaled = mat_poly.det(method='bareiss')  # Much faster!

# Recover true determinant: det(M) = det(M') / t^(k*n)
det_true = sp.cancel(det_scaled / t**(k * n))
# Then: (1-t)^(n-1) divides det_true (topological property)
result = sp.cancel(det_true * (1 - t)**(1 - n))
```

**Validation — palindromic property:**
All valid Alexander polynomials are palindromic (coefficients read the same forwards and backwards). Use this as a sanity check on intermediate results:
```python
def is_palindromic(poly, var=t):
    coeffs = sp.Poly(poly, var).all_coeffs()
    return coeffs == coeffs[::-1]
```

**When to recognize:** Challenge mentions braids, knots, permutation pairs, winding numbers, Reidemeister moves, or "topological key exchange." The key mathematical insight is that the Alexander polynomial — while a powerful knot/braid invariant — is multiplicative, making it fundamentally unsuitable as a one-way function for Diffie-Hellman.

**Key lessons:**
- **Diffie-Hellman requires non-abelian hardness.** If the invariant used for the shared secret is multiplicative/commutative under the group operation, Eve can compute it from public values.
- **Scrambling (Reidemeister moves) doesn't help** — the Alexander polynomial is an invariant, so scrambled braids produce the same polynomial.
- **Large symbolic determinants** need the denominator-clearing trick: multiply by `t^k` to get polynomials, compute det, divide back.

**References:** DiceCTF 2026 "Plane or Exchange"

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

## Tropical Semiring Residuation Attack (BearCatCTF 2026)

**Pattern (Tropped):** Diffie-Hellman key exchange using tropical matrices (min-plus algebra). Per-character shared secret XOR'd with encrypted flag.

**Tropical algebra:**
- Addition = `min(a, b)`
- Multiplication = `a + b`
- Matrix multiply: `(A*B)[i,j] = min_k(A[i,k] + B[k,j])`

**Tropical residuation recovers shared secret from public data:**
```python
def tropical_residuate(M, Mb, aM, n):
    """Recover shared secret from public matrices.
    M = public matrix, Mb = M*b (Bob's public), aM = a*M (Alice's public)
    """
    # Right residual: b*[j] = max_i(Mb[i] - M[i][j])
    b_star = [max(Mb[i] - M[i][j] for i in range(n)) for j in range(n)]
    # Shared secret: aMb = min_j(aM[j] + b*[j])
    aMb = min(aM[j] + b_star[j] for j in range(n))
    return aMb

# Decrypt per-character: key = aMb % 32; plaintext = key ^ ciphertext
for i, enc_char in enumerate(encrypted):
    key = shared_secret % 32
    plaintext_char = chr(key ^ ord(enc_char))
```

**Key insight:** Tropical DH is broken because the min-plus semiring lacks cancellation — given `M` and `M*b`, the "residual" `b*` can be computed directly via `max(Mb[i] - M[i][j])`. Unlike standard DH where recovering `b` from `g^b` is hard, tropical residuation recovers enough of `b`'s effect to compute the shared secret. This makes tropical matrix DH insecure for any matrix size.

**Detection:** Challenge mentions "tropical", "min-plus", "exotic algebra", or defines custom matrix multiplication using `min` and `+`.

---

## Paillier Cryptosystem Attack (SECCON 2015)

The Paillier cryptosystem is a homomorphic encryption scheme where `c = g^m * r^n mod n^2`. When given oracle equations involving c, o, h values:

1. **Recover n:** Compute lower bound `sqrt(max(c, o, h))` to approximate n, then brute-force nearby values
2. **Validate n:** Check equation `h = (c * o) % (n^2)` for correctness
3. **Factor n:** Use standard methods (e.g., factordb) to find p, q
4. **Decrypt:** Apply Paillier decryption:

```python
from sympy import lcm, mod_inverse

# n = p * q (factored)
lam = lcm(p - 1, q - 1)  # Carmichael function
n2 = n * n

def L(x):
    return (x - 1) // n

# Compute mu
g_lam = pow(g, lam, n2)
mu = mod_inverse(L(g_lam), n)

# Decrypt
c_lam = pow(c, lam, n2)
m = (L(c_lam) * mu) % n
```

**Key insight:** Paillier operates mod n^2, so ciphertext values are much larger than RSA. The homomorphic property `E(m1) * E(m2) = E(m1 + m2)` can leak relationships between plaintexts.

---

## Hamming Code Error Correction with Helical Interleaving (Sharif CTF 2016)

When data is protected by Hamming(31,26) codes with helical scan interleaving:

1. **Determine matrix dimensions:** Brute-force width/height (30x30 search space) by testing which dimensions produce valid Hamming codewords
2. **Read data in helical pattern:** Extract bits diagonally from the interleaved matrix
3. **Apply Hamming parity check:** Multiply codeword by parity check matrix H to detect/correct errors

```python
import numpy as np

def check_hamming(codeword, H):
    """Syndrome = H * c^T; zero syndrome means valid codeword"""
    syndrome = np.dot(H, codeword) % 2
    return np.all(syndrome == 0)

# Brute-force dimensions
for w in range(1, 31):
    for h in range(1, 31):
        # Reshape data into w x h matrix
        matrix = data[:w*h].reshape(h, w)
        # Read diagonals (helical scan)
        bits = read_helical(matrix)
        # Check if bits form valid Hamming codewords
        if validate_hamming_stream(bits, H):
            print(f"Dimensions: {w}x{h}")
```

**Key insight:** Try 8 different bit alignment offsets when the start position is unknown. Valid Hamming codewords have zero syndrome under multiplication by the parity check matrix.

---

## ElGamal Universal Re-encryption (Sharif CTF 2016)

Given an ElGamal-like ciphertext tuple (a, b, c, d) = (g^r, h^r, g^s, m*h^s), produce a different valid ciphertext decrypting to the same message without knowing the private key:

Transform exponents r -> 2r, s -> r+s:

```python
def reencrypt(a, b, c, d, p):
    return [
        (a * a) % p,    # g^(2r)
        (b * b) % p,    # h^(2r)
        (a * c) % p,    # g^(r+s)
        (d * b) % p     # m*h^(r+s)
    ]
```

**Key insight:** ElGamal's homomorphic property allows re-randomizing ciphertexts by multiplying components. The relationship between exponents must remain consistent: both pairs must share the same exponent offset.

---

## Paillier Oracle Size Bypass via Ciphertext Factoring (BSidesSF 2025)

When a Paillier decryption oracle rejects messages exceeding a size limit (e.g., >2000 bits), exploit the homomorphic property to factor the encrypted flag into smaller pieces:

1. **Paillier additive homomorphism:** `E(m1) * E(m2) mod n^2 = E(m1 + m2 mod n)`
2. **Multiplicative (scalar):** `E(m)^k mod n^2 = E(k*m mod n)`
3. **Factoring ciphertext:** Divide n into small ranges, query oracle with `E(flag) * E(-offset)^1` to determine which range contains the flag
4. **Chunk extraction:** Split the flag value into pieces that each fit within the oracle's size limit, decrypt individually, sum to recover original

```python
from Crypto.Util.number import inverse

def paillier_sub(c, plaintext_sub, n):
    """Compute E(m - plaintext_sub) from E(m) using homomorphic property"""
    n2 = n * n
    # E(-plaintext_sub) = E(n - plaintext_sub) = (n+1)^(n-plaintext_sub) * r^n mod n^2
    neg_enc = pow(n + 1, n - plaintext_sub, n2)
    return (c * neg_enc) % n2

# Binary search for flag value using oracle
def recover_flag(enc_flag, n, oracle_decrypt):
    low, high = 0, n
    while high - low > 1:
        mid = (low + high) // 2
        test_ct = paillier_sub(enc_flag, mid, n)
        result = oracle_decrypt(test_ct)
        if result < n // 2:  # Positive (flag > mid)
            low = mid
        else:  # Negative (flag < mid, wraps around)
            high = mid
    return low
```

**Key insight:** Paillier's additive homomorphism allows computing `E(flag - offset)` without decryption. If the oracle reveals whether the decrypted value is "small" (within limit) or "large" (rejected/wraps), binary search recovers the flag in O(log n) queries.
