# CTF Crypto - RSA Attacks (Part 2: Specialized Techniques)

## Table of Contents
- [RSA p=q Validation Bypass (BearCatCTF 2026)](#rsa-pq-validation-bypass-bearcatctf-2026)
- [RSA Cube Root CRT when gcd(e, phi) > 1 (BearCatCTF 2026)](#rsa-cube-root-crt-when-gcde-phi--1-bearcatctf-2026)
- [Factoring n from Multiple of phi(n) (BearCatCTF 2026)](#factoring-n-from-multiple-of-phin-bearcatctf-2026)
- [RSA Signature Forgery via Multiplicative Homomorphism (MMA CTF 2015)](#rsa-signature-forgery-via-multiplicative-homomorphism-mma-ctf-2015)
- [Weak RSA Key Generation via Base Representation (Sharif CTF 2016)](#weak-rsa-key-generation-via-base-representation-sharif-ctf-2016)
- [RSA with gcd(e, phi(n)) > 1 (CSAW 2015)](#rsa-with-gcde-phin--1-csaw-2015)
- [Batch GCD for Shared Prime Factoring (BSidesSF 2025)](#batch-gcd-for-shared-prime-factoring-bsidessf-2025)
- [RSA Partial Key Recovery from dp dq qinv (0CTF 2016)](#rsa-partial-key-recovery-from-dp-dq-qinv-0ctf-2016)
- [RSA-CRT Fault Attack / Bit-Flip Recovery (CSAW CTF 2016)](#rsa-crt-fault-attack--bit-flip-recovery-csaw-ctf-2016)
- [RSA Homomorphic Decryption Oracle Bypass (ECTF 2016)](#rsa-homomorphic-decryption-oracle-bypass-ectf-2016)
- [RSA with Small Prime Factors and CRT Decomposition (Hack The Vote 2016)](#rsa-with-small-prime-factors-and-crt-decomposition-hack-the-vote-2016)
- [RSA Timing Attack on Montgomery Reduction (DEF CON 2017)](#rsa-timing-attack-on-montgomery-reduction-def-con-2017)
- [Bleichenbacher Low-Exponent RSA Signature Forgery (Google CTF 2017)](#bleichenbacher-low-exponent-rsa-signature-forgery-google-ctf-2017)

See also: [rsa-attacks.md](rsa-attacks.md) for foundational RSA attacks (small e, Wiener, Fermat, Pollard, Hastad, common modulus, Manger oracle, Coppersmith).

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

---

## RSA Partial Key Recovery from dp dq qinv (0CTF 2016)

**Pattern:** Given only the CRT (Chinese Remainder Theorem) exponents (dp, dq, qinv) from a partial PEM (Privacy Enhanced Mail) key leak (e.g., bottom portion of private key file), recover the full key. Since `dp = d mod (p-1)`, iterate k and check if `p = (dp * e - 1) / k + 1` is prime.

```python
import gmpy2
# dp, dq, qinv extracted from partial PEM; e is known (usually 65537)
for k in range(3, e):
    p_candidate = (dp * e - 1) // k + 1
    if gmpy2.is_prime(p_candidate):
        p = p_candidate
        break
# Similarly recover q from dq; verify qinv * q % p == 1
```

**Key insight:** Leaking just the CRT exponents from an RSA private key is sufficient to fully recover p and q. Recovery is O(e) -- essentially instant for e=65537.

---

## RSA-CRT Fault Attack / Bit-Flip Recovery (CSAW CTF 2016)

RSA signing service with intermittent single-bit errors in private exponent d during CRT computation. Collect valid and faulty signatures, then detect which bit flipped.

```python
from Crypto.Util.number import inverse

def recover_d_bits(n, e, valid_sig, faulty_sigs, msg):
    """Recover private key d bit-by-bit from CRT fault signatures"""
    d_bits = [0] * 1024
    m = pow(msg, 1, n)
    s_good = valid_sig
    for s_bad in faulty_sigs:
        # ratio reveals which bit was flipped
        ratio = (s_bad * inverse(s_good, n)) % n
        for k in range(1024):
            if ratio == pow(2, pow(2, k, n), n) or ratio == pow(inverse(2, n), pow(2, k, n), n):
                d_bits[k] = 1
                break
    return d_bits
```

**Key insight:** When RSA-CRT has a single-bit fault in d, the ratio `faulty_sig * valid_sig^(-1) mod n` equals `2^(2^k) mod n` for the flipped bit position k, enabling bit-by-bit private key recovery.

---

## RSA Homomorphic Decryption Oracle Bypass (ECTF 2016)

Service decrypts any ciphertext except the target flag ciphertext. Exploit RSA's multiplicative homomorphism: `Dec(a * b mod n) = Dec(a) * Dec(b) mod n`.

```python
from Crypto.Util.number import long_to_bytes, inverse

# Server refuses to decrypt enc_flag directly
# But RSA is homomorphic: Dec(A*B) = Dec(A) * Dec(B) mod n
enc_2 = pow(2, e, n)  # encrypt the number 2
enc_flag_times_2 = (enc_flag * enc_2) % n  # = Enc(flag * 2)

dec_flag_times_2 = oracle_decrypt(enc_flag_times_2)  # server allows this
dec_2 = oracle_decrypt(enc_2)                         # server allows this

# Recover flag: (flag * 2) * inverse(2) mod n = flag
flag = (dec_flag_times_2 * inverse(dec_2, n)) % n
print(long_to_bytes(flag))
```

**Key insight:** RSA without padding is multiplicatively homomorphic. Multiply the forbidden ciphertext by `Enc(r)` for any `r`, decrypt the product, then divide by `r` to recover the original plaintext.

---

## RSA with Small Prime Factors and CRT Decomposition (Hack The Vote 2016)

RSA modulus composed of many small prime factors (primes < 251, each appearing ~1500 times). Factor n, then use CRT to decompose decryption.

```python
from sympy import factorint
from sympy.ntheory.residues import primitive_root
from functools import reduce

n = ...  # modulus with small factors
e = 65537
c = ...  # ciphertext

factors = factorint(n)  # {p1: k1, p2: k2, ...} where pi are small primes

# Decrypt modulo each prime power, then combine with CRT
from sympy.ntheory.modular import crt as chinese_remainder_theorem

remainders = []
moduli = []
for p, k in factors.items():
    pk = p ** k
    phi_pk = (p - 1) * p ** (k - 1)  # Euler's totient for prime power
    d_pk = pow(e, -1, phi_pk)
    m_pk = pow(c, d_pk, pk)
    remainders.append(m_pk)
    moduli.append(pk)

# Combine using CRT
m = chinese_remainder_theorem(moduli, remainders)[0]
```

**Key insight:** When n has many small prime factors, compute `d mod phi(p^k)` for each prime power independently, decrypt mod each, then combine via CRT. Much faster than computing `d mod phi(n)` directly.

---

## RSA Timing Attack on Montgomery Reduction (DEF CON 2017)

**Pattern:** Recover RSA private key bits via Kocher's timing attack when the number of modular subtractions during Montgomery reduction is leaked.

```python
# Montgomery multiplication: extra subtraction when result >= modulus
# Leaked: count of extra subtractions per signature operation
# Attack: predict subtraction count for each private key bit guess

# For each bit position i (MSB to LSB):
#   Guess bit = 0: predict timing for square only
#   Guess bit = 1: predict timing for square + multiply
#   Compare predictions against observed timing data
#   Correct guess produces statistically significant correlation

# ~200K signatures needed for 768-bit key recovery
# Attacking squaring reduction is more effective than multiply
import numpy as np
for bit_pos in range(key_bits):
    for guess in [0, 1]:
        predicted = predict_reductions(known_bits + [guess], messages)
        correlation = np.corrcoef(predicted, observed)[0, 1]
    known_bits.append(0 if corr_0 > corr_1 else 1)
```

**Key insight:** Montgomery multiplication performs an extra conditional subtraction when the intermediate result exceeds the modulus. If this count leaks (via timing, power, or as in this CTF -- directly), each bit of the private exponent can be determined by comparing predicted vs. observed subtraction patterns across many operations.

**References:** DEF CON 2017

---

## Bleichenbacher Low-Exponent RSA Signature Forgery (Google CTF 2017)

**Pattern:** Forge PKCS#1 v1.5 RSA signatures when e=3 by constructing a value whose cube root produces valid padding without knowing the private key.

```python
# PKCS#1 v1.5 signature format:
# 00 01 FF FF ... FF 00 [DigestInfo] [Hash]
# With e=3, forge signature s where s^3 has correct prefix

# Construct target block (2048-bit key, SHA-256):
# 00 01 FF ... FF 00 [SHA-256 DigestInfo] [hash] [garbage]
import gmpy2
prefix = b'\x00\x01' + b'\xff' * padding_len + b'\x00' + digest_info + hash_value
# Convert to integer, append zeros for garbage bytes
target = int.from_bytes(prefix + b'\x00' * garbage_len, 'big')
# Cube root (rounds down, garbage absorbs the remainder)
forged_sig = gmpy2.iroot(target, 3)[0] + 1  # +1 to round up
# Verify: forged_sig^3 starts with correct PKCS#1 prefix
```

**Key insight:** PKCS#1 v1.5 signature verification checks that `sig^e mod n` starts with `00 01 FF...FF 00 DigestInfo Hash`. With e=3, an attacker computes the cube root of a carefully constructed value with the correct prefix and ignores trailing bytes. Implementations that don't verify the padding extends to the full block length (CVE-2006-4339) accept the forgery.

**References:** Google CTF 2017
