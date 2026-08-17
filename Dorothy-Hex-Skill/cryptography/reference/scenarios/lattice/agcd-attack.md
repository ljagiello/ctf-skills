# Approximate-GCD (AGCD / DGHV) Lattice Attack

## When this applies

- Several public moduli or "primes" share a hidden common factor `r` plus small noise: `p_i = a_i·r + b_i` with `|b_i| ≪ r ≪ a_i`.
- You see hint files that publish many `p_i` values (often labeled "noisy primes", "shifted moduli", or hint values from a DGHV-like FHE construction).
- One of the `p_i` is `p_0` (the "reference"); the others are `p_1 ... p_m`.
- Recovering `r` enables a downstream factoring or key-derivation attack.

## Technique

Build a lattice whose shortest vector encodes `r`. After LLL reduction the first row contains either `r` directly or a multiple thereof.

## Steps

### 1. Collect samples

Need `m ≥ 20`–`30` noisy values. Estimate the bit lengths: `|p_i| ≈ |a_i·r|`, `|b_i| ≪ |r|`.

### 2. Build the AGCD matrix

```
[ ρ   p_1   p_2   ...   p_m ]
[     -p_0                  ]
[          -p_0             ]
[                ...        ]
[                       -p_0]
```

where `ρ ≈ 2^(size of b_i)` (approximate the noise bound). Dimensions: `(m+1) × (m+1)`.

```python
from fpylll import IntegerMatrix, LLL

m = len(noisy) - 1            # noisy[0] = p_0
rho = 1 << (noise_bits + 1)
M = [[rho] + noisy[1:]]
for i in range(m):
    row = [0]*(m+1)
    row[i+1] = -noisy[0]
    M.append(row)

B = IntegerMatrix.from_matrix(M)
LLL.reduction(B)
b = list(B[0])
r = b[0] // rho               # candidate r
```

### 3. Validate

Check `p_i % r` is small for all `i`. If not, try `r = -b[0] // rho`, or expand to next-shortest vector. Sometimes you recover a small multiple `k·r`; gcd a few candidates.

### 4. Use `r` downstream

Common follow-ons:

- Factor `n = p·q` when both are structured: see `scenarios/rsa-quirks/` for discriminant-square sweep.
- Recover symmetric keys derived as `key = f(x, r)`.

## Verifying success

- For each `p_i`, compute `b_i = p_i mod r` and confirm `|b_i| < 2^noise_bits`.
- Recompute `a_i = (p_i - b_i)/r` — should be an integer of the expected bit length.
- If a downstream factoring uses `r`, the recovered factor must satisfy `n % p == 0`.

## Common pitfalls

- **`ρ` too small or too large.** It must roughly equal the noise bound; off by a factor of 4 still works, off by `2^32` does not.
- **Too few samples.** Below ~`bit(r)/bit(b)` samples, the lattice has no advantage over brute force.
- **Sign of `r`.** LLL gives `±r`; both are valid, normalize positive.
- **Partial recovery.** Sometimes the shortest vector encodes `2·r` or `3·r`; gcd-pool the top 2-3 candidates.

## Tools

- `fpylll` — runs in <1s for m≤30 dim 30 lattice on 640-bit `r`.
- `gmpy2.mpz` for big-integer arithmetic during validation.
- Pure Python is enough; SageMath is overkill.
