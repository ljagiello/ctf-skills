# Common Modulus Attack

## When this applies

- The same plaintext `m` is encrypted with two different public exponents `e1, e2` under the **same modulus** `n`: `c1 = m^e1 mod n`, `c2 = m^e2 mod n`.
- `gcd(e1, e2) = 1` (coprime exponents).
- Trigger keywords: "common modulus", "two encryptions same modulus", "shared n".

## Technique

By Bezout's identity, find integers `(u, v)` such that `u·e1 + v·e2 = 1`. Then:

```
c1^u · c2^v = m^(u·e1) · m^(v·e2) = m^(u·e1 + v·e2) = m^1 = m  (mod n)
```

One of `u`, `v` is negative; use modular inverse for that side.

## Steps

### 1. Confirm preconditions

- Same `n` for both ciphertexts.
- `gcd(e1, e2) == 1`. If not coprime, attack fails — but the gcd reveals a factor of the structure.

### 2. Compute Bezout coefficients

```python
from math import gcd

def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

g, u, v = egcd(e1, e2)
assert g == 1
```

### 3. Combine ciphertexts

```python
if u < 0:
    c1 = pow(c1, -1, n)
    u = -u
if v < 0:
    c2 = pow(c2, -1, n)
    v = -v

m = (pow(c1, u, n) * pow(c2, v, n)) % n
plaintext = m.to_bytes((m.bit_length()+7)//8, 'big')
```

### 4. Decode

The plaintext is recovered modulo `n`. Since `m < n` for legitimate encryption, the integer value is exact. Bytes-decode and look for expected format.

## Verifying success

- `pow(plaintext_int, e1, n) == c1` and `pow(plaintext_int, e2, n) == c2`.
- Decoded bytes match expected structure (UTF-8 string, JSON, flag wrapper).

## Common pitfalls

- **Different moduli.** If `n` differs between the two ciphertexts, this isn't common modulus — it's broadcast (see `low-public-exponent.md`).
- **`gcd(e1, e2) > 1`.** Attack fails directly. If `g > 1`, you'd recover `m^g mod n` instead of `m`. Sometimes useful (small `g`, take a `g`-th root) but not the same attack.
- **Padded ciphertexts.** If each encryption applies fresh randomized padding, the underlying "plaintext" is actually `(padding_i, m)` — different per encryption. Attack fails. Only works on textbook RSA / deterministic padding.
- **Sign of `u, v`.** Be careful: pure-Python `pow(x, -1, n)` requires `gcd(x, n) == 1`. For RSA ciphertexts that's almost always true; if not, you've found a factor of `n`.

## Tools

- Pure Python; ~20 lines including extended Euclidean.
- `gmpy2` only if `n` is huge and Python's built-in `pow` is too slow (rare).
- No SageMath needed.
