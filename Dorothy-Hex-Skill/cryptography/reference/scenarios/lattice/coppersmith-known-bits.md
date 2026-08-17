# Coppersmith — Recover Small Unknown from Partial Bits

## When this applies

- An RSA-style modulus `n` is public, plus partial information about a related quantity:
  - High-order bits of one prime (`p`) are known; the low bits are unknown but bounded.
  - Plaintext is mostly known with a small unknown chunk (stereotyped messages).
  - Low-order bits of `d` are leaked by side channel.
- The unknown chunk has size `< n^(1/e)` (rule of thumb for RSA exponent `e`).
- Trigger keywords: "stereotyped message", "partial key exposure", "known high bits", "Coppersmith", "small roots".

## Technique

Build a polynomial `f(x)` over `Z/n` with a small root `x0` corresponding to the unknown bits. Coppersmith's method (via Howgrave-Graham lattice) recovers any root smaller than `n^(1/d - eps)` where `d = deg(f)`.

## Steps

### 1. Express unknown as polynomial

Examples:

- **Stereotyped plaintext**: `m = M0 + x` where `M0` is known prefix, `x` < `2^k` is unknown suffix. `f(x) = (M0 + x)^e - c (mod n)`. Degree `e`, bound `2^k`.
- **High bits of p known**: `p = P0 + x` with `P0` known top half. `f(x) = P0 + x` over `Z/p` with hidden modulus → use Howgrave-Graham factor recovery: the polynomial `f` should evaluate to 0 mod `p` (an unknown divisor of `n`).
- **Low bits of d known**: build polynomial in unknown high bits of `d` constrained by `e·d ≡ 1 (mod phi(n))`.

### 2. Run small-roots solver

```python
# SageMath
n = ...; e = ...; c = ...; M0 = ...; bound = 1 << 64
P.<x> = PolynomialRing(Zmod(n))
f = (M0 + x)^e - c
roots = f.small_roots(X=bound, beta=1.0, epsilon=1/30)
print(roots)
```

Tune `epsilon` smaller for tighter bounds at higher cost.

For factoring with known high bits of `p`:

```python
# beta = 0.5 means the polynomial vanishes mod a divisor of size n^0.5
P.<x> = PolynomialRing(Zmod(n))
f = P0 + x
roots = f.small_roots(X=bound, beta=0.5, epsilon=1/40)
p = int(P0 + roots[0])
q = n // p
```

### 3. Verify

For factoring: `n % p == 0`. For plaintext: re-encrypt and compare to `c`.

## Verifying success

- Reconstructed plaintext encrypts back to the published ciphertext.
- Recovered `p` divides `n`.
- For partial-d recovery: `(e·d_full) % phi(n) == 1` once both factors known.

## Common pitfalls

- **Bound too loose.** If `|x0| > n^(1/d)` Coppersmith finds nothing. Tighten the bound or add more known bits.
- **`beta` parameter.** Use `beta=1.0` for roots mod `n`, `beta=0.5` for roots mod a divisor of size `n^0.5`.
- **High-degree polynomials.** `e=65537` requires huge lattice; only practical for `e ≤ 7` or so without further structure.
- **Multiple roots.** `small_roots` returns all small roots; pick the one matching the expected bit pattern.
- **Don't roll your own.** SageMath's `small_roots` wraps Howgrave-Graham + LLL correctly. Hand-rolled implementations consistently fail bound estimation.

## Tools

- **SageMath** is the practical tool; pure-Python alternatives are 10-100× slower.
- `sage -c "..."` from CLI is enough; no notebook needed.
- For non-Sage: `defund/coppersmith` Python module covers common cases.
- `flatter` for the inner LLL on lattices >300 dim.
