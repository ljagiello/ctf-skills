# Boneh-Durfee — Low Private Exponent RSA

## When this applies

- RSA with public modulus `n` and a private exponent `d` significantly smaller than `n^0.292`.
- Wiener attack already covers `d < n^0.25`. Boneh-Durfee extends the bound to `d < n^0.292`.
- Public `e` is large (close to `n`), which is the hallmark of artificially-shrunken `d`.
- Trigger keywords: "low private exponent", "small d", "Boneh-Durfee".

## Technique

The key relation is `e·d - 1 = k·phi(n)` for some integer `k` of similar size to `d`. Rearrange:

```
e·d - 1 = k·(n - p - q + 1)
e·d ≡ 1 + k·(s)  (mod n)    where s = -(p+q-1)
```

This becomes a bivariate modular polynomial `f(k, s) = 1 + k·(A + s)` with `A = -n+1` and small bounds on both unknowns. Apply Coppersmith's small-roots in two variables (Boneh-Durfee 2000).

## Steps

### 1. Confirm low-d preconditions

Compute `e/n`. If `e ≈ n` (close to 1.0 ratio), low `d` is likely. Larger `e` ⇒ more reduction pressure on `d`.

### 2. Run Boneh-Durfee solver

```python
# SageMath using public Boneh-Durfee implementations
# e.g. https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/boneh_durfee.sage

delta = 0.28           # bound on d as fraction of n bits
m = 4                  # lattice m parameter (try 3..8)
t = int((1 - 2*delta) * m)
X = 2*floor(N^delta)
Y = floor(N^0.5)

# build the lattice and run
# (see public sage scripts for full setup)
```

If `delta = 0.292` is too tight, try smaller `delta` (lower bound = bigger lattice = slower).

### 3. Recover `d`

The solver outputs `(k0, s0)`; then:

```python
phi = (e*d - 1) // k0
# Or: phi = n - s0 - 1
```

With `phi` known: factor `n` by solving the quadratic `x^2 - (n-phi+1)x + n = 0`.

### 4. Verify

Decrypt the challenge ciphertext with `d` and check structure (PKCS#1, plaintext format).

## Verifying success

- `(e * d) % phi(n) == 1`.
- `n == p * q` from recovered factors.
- A test ciphertext decrypts cleanly.

## Common pitfalls

- **`delta` too aggressive.** Setting `delta = 0.292` requires very tight integer arithmetic. Start at `delta = 0.26` and creep up only if the smaller lattice fails.
- **`m` and `t` parameters.** Larger `m` = bigger lattice = better bound but exponential cost. Most CTFs work at `m ∈ {3, 4}`.
- **Wiener first.** If `d < n^0.25`, run Wiener (continued fractions) — simpler, no lattice. Boneh-Durfee is for the `0.25 ≤ d < 0.292` band.
- **Public `e` not large enough.** If `e` is small (e.g. 3, 65537), there's no reason `d` would be small. Boneh-Durfee assumes `e ≈ n`.

## Tools

- SageMath with public Boneh-Durfee scripts (`mimoo/RSA-and-LLL-attacks`, `defund/coppersmith`).
- For pure Wiener: `pycryptodome.PublicKey.RSA` + custom continued-fraction implementation, ~50 lines.
- `gmpy2` for the final phi/factor recovery arithmetic.
