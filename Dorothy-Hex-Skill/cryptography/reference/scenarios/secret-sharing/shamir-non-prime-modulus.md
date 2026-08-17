# Shamir Secret Sharing over Non-Prime Modulus (2-adic Lagrange)

## When this applies

- A challenge implements Shamir Secret Sharing where the modulus `N` is **not prime** — typically `N = 2^k` (e.g. `2^256`, `2^1024`).
- You have access to multiple shares `(x_i, y_i)` where `y_i = f(x_i) mod N` for some polynomial `f` of degree `t-1`, and want to recover `f(0)` (the secret).
- Some shares may be fake (random) instead of real polynomial evaluations.
- Trigger keywords: "Shamir", "secret sharing", "non-prime modulus", "2^k modulus", "ring" (vs field).

## Technique

Standard Lagrange interpolation requires inverting `(x_i - x_j)` mod the modulus. Over `Z/2^k`, even integers are non-invertible — direct interpolation fails when the denominator product is even (almost always).

**Two complementary tricks:**

1. **Identify real shares via low-bit leakage.** For real shares with even `x`, all monomial terms `x^j` for `j ≥ 1` are even, so `y mod 2 = a_0 mod 2`. Encrypt a known message `m` many times; positions with consistent parity are real, random parity are fake.
2. **2-adic Lagrange interpolation.** Compute numerator and denominator as exact integers, factor out powers of 2 (the 2-adic valuation `v_2`), invert the odd residue mod `N`, and rescale.

## Steps

### 1. Distinguish real vs fake shares (when applicable)

```python
# Encrypt known odd message m many times, watch parity at each share position
trials = 30
parities = [[] for _ in range(num_shares)]
for _ in range(trials):
    shares = encrypt_oracle(m)  # m chosen with m % 2 == 1
    for i, (x, y) in enumerate(shares):
        if x % 2 == 0:   # only even-x positions leak
            parities[i].append(y % 2)

# real share with even x: y % 2 == m % 2 always
real_positions = [i for i, p in enumerate(parities)
                  if p and all(b == m % 2 for b in p)]
```

### 2. 2-adic Lagrange at x=0

For a polynomial of degree `t-1`, pick `t` real shares. Compute:

```python
def v2(n):
    """2-adic valuation of nonzero integer n"""
    if n == 0: return float('inf')
    v = 0
    while n % 2 == 0:
        n //= 2; v += 1
    return v

def odd_part(n):
    return n // (1 << v2(n))

def modinv_odd(a, mod):
    # a must be odd; mod = 2^k
    return pow(a, -1, mod)

# Lagrange basis at x = 0:
# L_i(0) = prod_{j!=i} (-x_j) / (x_i - x_j)
# Sum y_i * L_i(0) mod N
N = 1 << K
secret = 0
for i, (xi, yi) in enumerate(real):
    num = 1
    den = 1
    for j, (xj, _) in enumerate(real):
        if j == i: continue
        num *= -xj
        den *= (xi - xj)
    # combine: contribution = yi * num / den, but den may be even
    # track 2-adic valuations
    v_num = v2(num) + v2(yi)
    v_den = v2(den)
    if v_num < v_den:
        # underflow: the term's 2-adic value is negative — means this set of shares is unsolvable as-is
        raise ValueError("scale up by lifting more shares or pick different subset")
    # contribution mod N (after canceling 2^v_den from numerator)
    odd_num = odd_part(num) * odd_part(yi)
    odd_den = odd_part(den)
    inv = modinv_odd(odd_den % N, N)
    term = (odd_num * inv) % N
    term = (term << (v_num - v_den)) % N
    secret = (secret + term) % N
```

### 3. Handle 2-adic deficiency

If individual terms have `v_num < v_den`, no single term is well-defined mod `2^k`. The **sum** may still be — track maximum deficiency `D = max(v_den - v_num)` across terms. Compute the full sum mod `2^(k+D)` (extend precision), then divide out `2^D` if the result is divisible.

### 4. Validate

If you have an extra real share `(x_test, y_test)` not used in the interpolation, evaluate the recovered polynomial at `x_test` and confirm `f(x_test) mod N == y_test`.

For a flag-bearing secret, decode bytes and look for the expected wrapper.

## Verifying success

- Polynomial reconstructed from `t` shares predicts a held-out `(x, y)` exactly mod `N`.
- Recovered constant term decodes to expected format (printable ASCII, flag wrapper, key length).
- Recompute share `y_i = sum(a_j · x_i^j) mod N` from recovered coefficients — match all real shares.

## Common pitfalls

- **Trying field-style interpolation.** `pow(den, -1, N)` raises when `den` is even — that's the whole point. Do not silently use `gcd(den, N)` and proceed.
- **Skipping real/fake separation.** Mixing one fake share into the interpolation gives a wrong but plausible-looking answer.
- **Even-x leak only works for even x.** If all `x_i` are odd, parity oracle gives no info — need a different identifier (e.g. server reveals real positions, or different low-bit modulus).
- **Coefficient overflow.** Lagrange numerators grow like `(max(x_i))^t` integer-valued; for 1024-bit `N` and `t=32`, intermediate ints reach ~10000 bits. `gmpy2.mpz` highly recommended.
- **Off-by-one on degree.** Threshold `t` shares define a degree `t-1` polynomial. Using `t-1` shares underdetermines.

## Tools

- Pure Python with `gmpy2.mpz` for big-integer arithmetic.
- No SageMath needed; `Z/2^k` is just integer arithmetic with care.
- Optional: `sympy.ntheory` for factoring small moduli, but for `2^k` direct `pow(x, -1, N)` on odd residues is enough.
