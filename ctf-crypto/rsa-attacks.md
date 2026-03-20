# CTF Crypto - RSA Attacks

## Table of Contents
- [Small Public Exponent (Cube Root)](#small-public-exponent-cube-root)
- [Common Modulus Attack](#common-modulus-attack)
- [Wiener's Attack (Small Private Exponent)](#wieners-attack-small-private-exponent)
- [Pollard's p-1 Factorization](#pollards-p-1-factorization)
- [Hastad's Broadcast Attack](#hastads-broadcast-attack)
- [RSA with Consecutive Primes (Fermat Factorization)](#rsa-with-consecutive-primes-fermat-factorization)
- [Multi-Prime RSA](#multi-prime-rsa)
- [RSA with Restricted-Digit Primes (LACTF 2026)](#rsa-with-restricted-digit-primes-lactf-2026)
- [Coppersmith for Structured RSA Primes (LACTF 2026)](#coppersmith-for-structured-rsa-primes-lactf-2026)
- [Manger's RSA Padding Oracle Attack (Nullcon 2026)](#mangers-rsa-padding-oracle-attack-nullcon-2026)
- [Manger's Attack on RSA-OAEP via Timing Oracle (HTB Early Bird)](#mangers-attack-on-rsa-oaep-via-timing-oracle-htb-early-bird)
- [Polynomial Hash with Trivial Root (Pragyan 2026)](#polynomial-hash-with-trivial-root-pragyan-2026)
- [Polynomial CRT in GF(2)[x] (Nullcon 2026)](#polynomial-crt-in-gf2x-nullcon-2026)
- [Affine Cipher over Non-Prime Modulus (Nullcon 2026)](#affine-cipher-over-non-prime-modulus-nullcon-2026)
- [RSA p=q Validation Bypass (BearCatCTF 2026)](#rsa-pq-validation-bypass-bearcatctf-2026)
- [RSA Cube Root CRT when gcd(e, phi) > 1 (BearCatCTF 2026)](#rsa-cube-root-crt-when-gcde-phi--1-bearcatctf-2026)
- [Factoring n from Multiple of phi(n) (BearCatCTF 2026)](#factoring-n-from-multiple-of-phin-bearcatctf-2026)
- [RSA Signature Forgery via Multiplicative Homomorphism (MMA CTF 2015)](#rsa-signature-forgery-via-multiplicative-homomorphism-mma-ctf-2015)
- [Weak RSA Key Generation via Base Representation (Sharif CTF 2016)](#weak-rsa-key-generation-via-base-representation-sharif-ctf-2016)
- [RSA with gcd(e, phi(n)) > 1 (CSAW 2015)](#rsa-with-gcde-phin--1-csaw-2015)
- [Batch GCD for Shared Prime Factoring (BSidesSF 2025)](#batch-gcd-for-shared-prime-factoring-bsidessf-2025)

---

## Small Public Exponent (Cube Root)

**Pattern:** Small `e` (typically 3) with small message. When `m^e < n`, the ciphertext is just `m^e` without modular reduction — take the integer eth root.

```python
import gmpy2

def small_e_attack(c, e):
    """Recover plaintext when m^e < n (no modular wrap)."""
    m, exact = gmpy2.iroot(c, e)
    if exact:
        return int(m)
    return None

# Usage
m = small_e_attack(c, e=3)
print(bytes.fromhex(hex(m)[2:]))
```

**When it fails:** If `m^e > n` (message padded or large), the modular reduction destroys the simple root. In that case, try Hastad's broadcast attack or Coppersmith's short-pad attack.

---

## Common Modulus Attack

**Pattern:** Same message encrypted with same `n` but two different public exponents `e1`, `e2` where `gcd(e1, e2) = 1`. Recover plaintext without factoring `n`.

```python
from math import gcd

def common_modulus_attack(c1, c2, e1, e2, n):
    """Recover plaintext from two encryptions with same n, coprime e1/e2."""
    # Extended GCD: find a, b such that a*e1 + b*e2 = 1
    def extended_gcd(a, b):
        if a == 0: return b, 0, 1
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

    g, a, b = extended_gcd(e1, e2)
    assert g == 1, "e1 and e2 must be coprime"

    # m = c1^a * c2^b mod n
    # Handle negative exponent by using modular inverse
    if a < 0:
        c1 = pow(c1, -1, n)
        a = -a
    if b < 0:
        c2 = pow(c2, -1, n)
        b = -b
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return m
```

**Key insight:** Two encryptions of the same message under the same modulus but different exponents leak the plaintext via Bezout's identity. No factoring required.

---

## Wiener's Attack (Small Private Exponent)

**Pattern:** Private exponent `d` is small (d < N^0.25). The continued fraction expansion of `e/n` reveals `d`.

```python
def wiener_attack(e, n):
    """Recover d when d < N^0.25 using continued fraction expansion of e/n."""
    def continued_fraction(num, den):
        cf = []
        while den:
            q, r = divmod(num, den)
            cf.append(q)
            num, den = den, r
        return cf

    def convergents(cf):
        convs = []
        h0, h1 = 0, 1
        k0, k1 = 1, 0
        for a in cf:
            h0, h1 = h1, a * h1 + h0
            k0, k1 = k1, a * k1 + k0
            convs.append((h1, k1))
        return convs

    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        # Check if d is valid: phi = (e*d - 1) / k must be integer
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # phi = (p-1)(q-1) = n - p - q + 1, so p+q = n - phi + 1
        s = n - phi + 1
        # p and q are roots of x^2 - s*x + n = 0
        discriminant = s * s - 4 * n
        if discriminant < 0:
            continue
        from math import isqrt
        t = isqrt(discriminant)
        if t * t == discriminant:
            return d
    return None

# Usage
d = wiener_attack(e, n)
m = pow(c, d, n)
```

**When to use:** Very large `e` (close to `n`) often indicates small `d`. Also try `owiener` Python package: `pip install owiener`.

---

## Pollard's p-1 Factorization

**Pattern:** One prime factor `p` has a smooth `p-1` (all prime factors of `p-1` are small). Compute `a^(B!) mod n`; GCD with `n` reveals `p`.

```python
from math import gcd

def pollard_p1(n, B=100000):
    """Factor n when p-1 is B-smooth for some prime factor p."""
    a = 2
    for j in range(2, B + 1):
        a = pow(a, j, n)
        d = gcd(a - 1, n)
        if 1 < d < n:
            return d, n // d
    return None

# Usage
result = pollard_p1(n)
if result:
    p, q = result
```

**Key insight:** By Fermat's little theorem, if `p-1` divides `B!`, then `a^(B!) ≡ 1 (mod p)`, so `gcd(a^(B!) - 1, n)` gives `p`. Increase `B` for larger smooth bounds. CTF primes generated with `getStrongPrime()` or similar are resistant.

---

## Hastad's Broadcast Attack

**Pattern:** Same plaintext `m` encrypted with `e` different public keys (all with exponent `e`, typically `e=3`). Use CRT to reconstruct `m^e`, then take the eth root.

```python
from functools import reduce

def hastad_broadcast(ciphertexts, moduli, e):
    """Recover m from e encryptions with the same exponent e."""
    assert len(ciphertexts) >= e and len(moduli) >= e

    # Chinese Remainder Theorem
    def crt(remainders, moduli):
        N = reduce(lambda a, b: a * b, moduli)
        result = 0
        for r, m in zip(remainders, moduli):
            Ni = N // m
            Mi = pow(Ni, -1, m)
            result += r * Ni * Mi
        return result % N

    # CRT gives m^e (mod N1*N2*...*Ne)
    # Since m < each Ni, m^e < N1*N2*...*Ne, so no modular reduction occurred
    me = crt(ciphertexts[:e], moduli[:e])

    import gmpy2
    m, exact = gmpy2.iroot(me, e)
    if exact:
        return int(m)
    return None

# Usage (e=3, three encryptions)
m = hastad_broadcast([c1, c2, c3], [n1, n2, n3], e=3)
print(bytes.fromhex(hex(m)[2:]))
```

**Key insight:** CRT reconstructs `m^e` exactly (no modular reduction) because `m < min(n_i)` and therefore `m^e < n_1 * n_2 * ... * n_e`. Taking the integer eth root recovers `m`.

---

## RSA with Consecutive Primes (Fermat Factorization)

**Pattern (Loopy Primes):** q = next_prime(p), making p ~ q ~ sqrt(N). Also known as Fermat factorization — works whenever `|p - q|` is small.

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

---

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

---

## RSA with Restricted-Digit Primes (LACTF 2026)

**Pattern (six-seven):** RSA primes p, q composed only of digits {6, 7}, ending in 7.

**Digit-by-digit factoring from LSB:**
```python
# At each step k, we know p mod 10^k -> compute q mod 10^k = n * p^{-1} mod 10^k
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

---

## Coppersmith for Structured RSA Primes (LACTF 2026)

**Pattern (six-seven-again):** p = base + 10^k * x where base is fully known and x is small (x < N^0.25).

**Attack via SageMath:**
```python
# Construct f(x) such that f(x_secret) = 0 (mod p) and thus (mod N)
# p = base + 10^k * x -> x + base * (10^k)^{-1} = 0 (mod p)
R.<x> = PolynomialRing(Zmod(N))
f = x + (base * inverse_mod(10**k, N)) % N
roots = f.small_roots(X=2**70, beta=0.5)  # x < N^0.25
```

**When to use:** Whenever part of a prime is known and the unknown part is small enough for Coppersmith bounds (< N^{1/e} for degree-e polynomial, approximately N^0.25 for linear).

---

## Manger's RSA Padding Oracle Attack (Nullcon 2026)

**Pattern (TLS, Nullcon 2026):** RSA-encrypted key with threshold oracle. Phase 1: double f until `k*f >= threshold`. Phase 2: binary search. ~128 total queries for 64-bit key.

See [advanced-math.md](advanced-math.md) for full implementation.

---

## Manger's Attack on RSA-OAEP via Timing Oracle (HTB Early Bird)

**Pattern:** Flask app implements RSA-OAEP with custom hash (PBKDF2, 2M iterations). Python's short-circuit `or` evaluation creates a timing oracle: if the first byte Y != 0, PBKDF2 is never called (~0.6s). If Y == 0, PBKDF2 runs (~2s).

**Vulnerable code pattern:**
```python
if Y != 0 or not self.H_verify(self.L, DB[:self.hLen]) or self.os2ip(PS) != 0:
    return {"ok": False, "error": "decryption error"}
```

**Oracle mapping:** Fast response → Y != 0 (decrypted message >= B). Slow response → Y == 0 (decrypted message < B = 2^(8*(k-1))).

**Calibration for network reliability:**
```python
def calibrate(n, e, k):
    B = pow(2, 8 * (k - 1))
    slow_times, fast_times = [], []
    for i in range(5):
        # Known-slow: encrypt values < B
        enc = pow(B - 1 - i*100, e, n).to_bytes(k, 'big')
        slow_times.append(measure(enc))
        # Known-fast: encrypt values > B
        enc = pow(B + 1 + i*100, e, n).to_bytes(k, 'big')
        fast_times.append(measure(enc))
    FAST_UPPER = max(fast_times) * 1.5
    SLOW_LOWER = min(slow_times) * 0.9
```

**Oracle with retry for ambiguous results:**
```python
def padding_oracle(c_int):
    while True:
        total = measure_response_time(c_int)
        if SLOW_LOWER < total < SLOW_UPPER:
            return True   # Y == 0 (below B)
        elif total < FAST_UPPER:
            return False  # Y != 0 (above B)
        # Ambiguous: retry
```

**Full 3-step Manger's attack (~1024 iterations for 1024-bit RSA):**
```python
# Step 1: Find f1 where f1 * m >= B
f1 = 2
while oracle((pow(f1, e, n) * c) % n):
    f1 *= 2

# Step 2: Find f2 where n <= f2 * m < n + B
f2 = (n + B) // B * f1 // 2
while not oracle((pow(f2, e, n) * c) % n):
    f2 += f1 // 2

# Step 3: Binary search narrowing m to exact value
mmin, mmax = ceil_div(n, f2), floor_div(n + B, f2)
while mmin < mmax:
    f = floor_div(2 * B, mmax - mmin)
    i = floor_div(f * mmin, n)
    f3 = ceil_div(i * n, mmin)
    if oracle((pow(f3, e, n) * c) % n):
        mmax = floor_div(i * n + B, f3)
    else:
        mmin = ceil_div(i * n + B, f3)
m = mmin
```

**Post-recovery OAEP decode:**
```python
from Crypto.Signature.pss import MGF1
maskedSeed = EM[1:hLen+1]
maskedDB = EM[hLen+1:]
seed = bytes(a ^ b for a, b in zip(maskedSeed, MGF1(maskedDB, hLen, HF)))
DB = bytes(a ^ b for a, b in zip(maskedDB, MGF1(seed, k - hLen - 1, HF)))
# DB[:hLen] should match lHash; rest is 0x00...0x01 || message
```

**Key insight:** Python's `or` short-circuits left-to-right. When expensive operations (PBKDF2, bcrypt, argon2) appear in chained conditions, the first condition becomes a timing oracle. RFC 8017 explicitly warns implementations must not let attackers distinguish error conditions — timing differences violate this.

**Detection:** RSA-OAEP with custom hash or slow KDF. Flask/Python backend. `/verify-token` or similar decryption endpoint returning generic errors. Timing differences between responses.

---

## Polynomial Hash with Trivial Root (Pragyan 2026)

**Pattern (!!Cand1esaNdCrypt0!!):** RSA signature scheme using polynomial hash `g(x,a,b) = x(x^2 + ax + b) mod P`.

**Vulnerability:** `g(0) = 0` for all parameters `a,b`. RSA signature of 0 is always 0 (`0^d mod n = 0`).

**Exploitation:** Craft message suffix so `bytes_to_long(prefix || suffix) = 0 (mod P)`:
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

---

## Polynomial CRT in GF(2)[x] (Nullcon 2026)

**Pattern (Going in Circles, Nullcon 2026):** `r = flag mod f` where f is random GF(2) polynomial. Collect ~20 pairs, filter coprime, CRT combine.

See [advanced-math.md](advanced-math.md) for GF(2)[x] polynomial arithmetic and CRT implementation.

---

## Affine Cipher over Non-Prime Modulus (Nullcon 2026)

**Pattern (Matrixfun, Nullcon 2026):** `c = A @ p + b (mod m)` with composite m. Chosen-plaintext difference attack. For composite modulus, solve via CRT in each prime factor field separately.

See [advanced-math.md](advanced-math.md) for CRT approach and Gauss-Jordan implementation.

---

## RSA p=q Validation Bypass (BearCatCTF 2026)

**Pattern (Pickme):** Server validates user-submitted RSA key (checks `n`, `e`, `d`, `p*q=n`, `e*d ≡ 1 mod phi`), encrypts the flag, then tries test decryption. If decryption fails, leaks ciphertext in error message.

**Exploit:** Set `p = q`. The server computes `phi = (p-1)*(q-1) = (p-1)^2` (incorrect — real totient of `p^2` is `p*(p-1)`). All validation checks pass, but decryption with the wrong `d` fails, leaking the ciphertext.

```python
from Crypto.Util.number import getPrime, inverse

p = getPrime(512)
q = p  # p = q!
n = p * q  # = p^2
e = 65537
wrong_phi = (p - 1) * (q - 1)  # = (p-1)^2
d = inverse(e, wrong_phi)  # passes server validation

# Server encrypts flag with our key, test decryption fails → leaks ciphertext c
# Decrypt with correct totient:
real_phi = p * (p - 1)
real_d = inverse(e, real_phi)
flag = pow(c, real_d, n)
```

**Key insight:** `phi(p^2) = p*(p-1)`, NOT `(p-1)^2`. When a server validates RSA parameters but uses `(p-1)*(q-1)` without checking `p != q`, setting `p=q` creates a working key that the server will miscompute the private exponent for, causing decryption failure and error-path data leakage.

---

## RSA Cube Root CRT when gcd(e, phi) > 1 (BearCatCTF 2026)

**Pattern (Kidd's Crypto):** RSA with `e=3`, modulus composed of many small primes all ≡ 1 (mod 3). Since each `p-1` is divisible by 3, `gcd(e, phi(n)) = 3^k` and the standard modular inverse `d = e^-1 mod phi` doesn't exist.

**Solution:** Compute cube roots per-prime via CRT:
```python
from sympy.ntheory.residues import nthroot_mod
from sympy.ntheory.modular import crt

primes = [p1, p2, ..., p13]  # All ≡ 1 mod 3

# For each prime, find all 3 cube roots of c mod p
roots_per_prime = []
for p in primes:
    roots = nthroot_mod(c % p, 3, p, all_roots=True)
    roots_per_prime.append(roots)

# Try all 3^13 = 1,594,323 combinations
from itertools import product
for combo in product(*roots_per_prime):
    result, mod = crt(primes, list(combo))
    try:
        text = long_to_bytes(result).decode('ascii')
        if text.isprintable():
            print(f"Flag: {text}")
            break
    except:
        continue
```

**Key insight:** When `gcd(e, phi(n)) > 1`, standard RSA decryption fails. Factor `n`, compute eth roots modulo each prime separately (each prime ≡ 1 mod e gives `e` roots), then enumerate all CRT combinations. Feasible when the number of primes is small (3^13 ≈ 1.6M combinations).

---

## Factoring n from Multiple of phi(n) (BearCatCTF 2026)

**Pattern (Twisted Pair):** Given RSA `n` and a leaked pair `(re, rd)` where `re * rd ≡ 1 (mod k*phi(n))`. The value `re*rd - 1` is a multiple of `phi(n)`, enabling probabilistic factoring.

```python
import random
from math import gcd

def factor_from_phi_multiple(n, phi_multiple):
    """Factor n given any multiple of phi(n) using Miller-Rabin variant."""
    # Write phi_multiple = 2^s * d where d is odd
    s, d = 0, phi_multiple
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(100):  # 100 attempts
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            prev = x
            x = pow(x, 2, n)
            if x == n - 1:
                break
            if x == 1:
                # prev is non-trivial square root of 1
                p = gcd(prev - 1, n)
                if 1 < p < n:
                    return p, n // p
        # Check final
        if x != n - 1:
            p = gcd(x - 1, n)
            if 1 < p < n:
                return p, n // p
    return None

phi_mult = re * rd - 1
p, q = factor_from_phi_multiple(n, phi_mult)
```

**Key insight:** Any multiple of `phi(n)` — not just `phi(n)` itself — enables factoring via the Miller-Rabin square root technique. If a server leaks `e*d` for any key pair, or if `re*rd - 1` is given, compute `gcd(a^(m/2) - 1, n)` for random `a` values. Succeeds with probability ≥ 1/2 per attempt.

---

## RSA Signature Forgery via Multiplicative Homomorphism (MMA CTF 2015)

**Pattern:** Signing oracle refuses to sign the target message `m` but will sign other values. Unpadded RSA is multiplicatively homomorphic: `S(a) * S(b) mod n == S(a * b) mod n`.

```python
# Factor target message and sign each factor separately
divisor = 2
assert target_msg % divisor == 0
sig_a = sign_oracle(target_msg // divisor)
sig_b = sign_oracle(divisor)
forged_sig = (sig_a * sig_b) % n
```

**Key insight:** Textbook RSA signatures are homomorphic: `m^d mod n` preserves multiplication. If the oracle blacklists `m` but signs its factors, multiply the partial signatures. To find a suitable factorization, try small divisors (2, 3, ...) until `m / divisor` also passes the blacklist check. This is why PKCS#1 padding is essential — padded messages cannot be factored into other valid padded messages.

---

## Weak RSA Key Generation via Base Representation (Sharif CTF 2016)

When RSA primes are generated as `p = kp * B + tp` where B = product_of_small_primes * 2^400 and kp is small (< 2^12):

1. **Compute n mod B^2:** Since n = p*q and both p,q have form k*B + t, expansion gives: `n = kp*kq*B^2 + (kp*tq + kq*tp)*B + tp*tq`
2. **Recover kp*kq:** Brute-force 2^24 possibilities for (kp, kq) where each < 2^12
3. **Solve quadratic:** From known kp*kq and the middle coefficient, recover tp and tq

```python
B = product_of_first_443_primes * (2**400)
B2 = B * B

# n = A*B^2 + C*B + D where A=kp*kq, D=tp*tq
A = n // B2
D = n % B

# Brute-force kp, kq such that kp*kq == A
for kp in range(1, 2**12):
    if A % kp == 0:
        kq = A // kp
        # Solve for tp, tq from remaining equations
```

**Key insight:** Structured prime generation creates a mixed-radix representation of n, allowing efficient factorization by reducing the search space from exponential to polynomial.

---

## RSA with gcd(e, phi(n)) > 1 (CSAW 2015)

When `gcd(e, phi(n)) = g > 1`, standard RSA decryption fails because `d = e^(-1) mod phi(n)` doesn't exist. Instead:

1. Compute `e' = e / g` (reduced exponent)
2. Compute `d' = e'^(-1) mod phi(n)` (now coprime)
3. Compute `m^g = pow(c, d', n)` (partial decryption)
4. Take g-th root: iterate candidate m values where `pow(m, g, n) == m^g`

```python
from sympy import factorint, mod_inverse
from gmpy2 import iroot

g = gcd(e, phi_n)
e_prime = e // g
d_prime = mod_inverse(e_prime, phi_n)
m_g = pow(c, d_prime, n)

# For small g, try integer root first
m, is_exact = iroot(m_g, g)
if is_exact:
    plaintext = int(m)
else:
    # Brute-force: m_g + k*n for small k
    for k in range(10000):
        m, exact = iroot(m_g + k * n, g)
        if exact:
            plaintext = int(m)
            break
```

**Key insight:** Reduce e by the GCD to make decryption possible, then recover the g-th root. Filter candidates by checking plaintext length or ASCII validity.

---

## Batch GCD for Shared Prime Factoring (BSidesSF 2025)

When multiple RSA moduli share a common prime factor (due to faulty hardware RNG, smartcard bugs, or weak seeding):

```python
from math import gcd
from functools import reduce

def batch_gcd(moduli):
    """Find shared factors among a list of RSA moduli"""
    # Product tree
    product = reduce(lambda a, b: a * b, moduli)

    factors = {}
    for n in moduli:
        g = gcd(n, product // n)
        if g != 1 and g != n:
            p = g
            q = n // p
            factors[n] = (p, q)
    return factors

# Usage: given list of public keys from smartcards
moduli = [key.n for key in public_keys]
shared = batch_gcd(moduli)
for n, (p, q) in shared.items():
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)  # Private exponent
```

For keys with patterned primes (hardware RNG faults producing primes with fixed bit patterns), combine with Coppersmith's method to recover remaining random bits. See [advanced-math.md](advanced-math.md) for Coppersmith.

**Key insight:** A single shared prime compromises both keys. Batch GCD runs in O(n log n) time via product/remainder trees, making it feasible for thousands of keys. Real-world incidents: Taiwanese citizen smartcards (2013), many IoT device certificates.
