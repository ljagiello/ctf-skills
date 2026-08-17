# Wiener Attack — Low Private Exponent (`d < n^0.25`)

## When this applies

- RSA with public exponent `e` close to `n` (i.e. `e/n` near 1.0) and a small private exponent `d < n^0.25`.
- Often appears when `d` is artificially shrunk for "performance" or in poorly designed key-generation that picks small `d` first.
- Trigger keywords: "Wiener", "low d", "small private exponent", "continued fractions".

## Technique

The relation `e·d - 1 = k·phi(n)` for some small `k` rearranges to:

```
e/n ≈ k/d  (when d is small relative to n)
```

The convergents of the continued fraction expansion of `e/n` produce candidate `(k, d)` pairs. For each candidate, check if `phi = (e·d - 1) / k` factors `n` (the quadratic `x^2 - (n - phi + 1)x + n = 0` has integer roots = `p, q`).

## Steps

### 1. Compute continued fraction of `e/n`

```python
def cf_expand(num, den):
    cf = []
    while den:
        q, r = divmod(num, den)
        cf.append(q)
        num, den = den, r
    return cf

def convergents(cf):
    h0, h1 = 1, cf[0]
    k0, k1 = 0, 1
    yield (h1, k1)
    for q in cf[1:]:
        h2 = q*h1 + h0
        k2 = q*k1 + k0
        yield (h2, k2)
        h0, h1 = h1, h2
        k0, k1 = k1, k2
```

### 2. Test each convergent as `(k, d)`

```python
for k, d in convergents(cf_expand(e, n)):
    if k == 0: continue
    if (e*d - 1) % k != 0: continue
    phi = (e*d - 1) // k
    # solve x^2 - (n - phi + 1)x + n = 0
    s = n - phi + 1
    disc = s*s - 4*n
    if disc < 0: continue
    sq = int(gmpy2.isqrt(disc))
    if sq*sq != disc: continue
    p = (s + sq) // 2
    q = (s - sq) // 2
    if p * q == n:
        print("Found d =", d, "p =", p, "q =", q)
        break
```

### 3. Decrypt with `d`

```python
plaintext = pow(c, d, n)
```

## Verifying success

- `(e * d) % phi(n) == 1`.
- `n == p * q`.
- Test ciphertext decrypts to expected format.

## Common pitfalls

- **Bound is `d < n^0.25 / 3`.** Sometimes called "Wiener bound". For larger `d` up to `n^0.292`, use Boneh-Durfee — see `boneh-durfee-low-d.md`.
- **`e` not large.** If `e` is small (e.g. 65537), there's no constraint forcing `d` to be small. Wiener won't apply.
- **Non-strict-Wiener with small primes close.** When `p, q` are very close (Fermat factoring territory), Wiener may also succeed but Fermat is the right primary tool.
- **`disc` not a perfect square.** Keep iterating convergents — only the correct `(k, d)` produces a square discriminant.

## Tools

- Pure Python; ~50 lines including continued-fraction expansion and quadratic solver.
- `gmpy2.isqrt` for the integer square root check.
- `RSA-and-LLL-attacks/wiener_attack.py` (mimoo) — drop-in implementation.
- `pycryptodome.PublicKey.RSA` to import the public key from PEM.
