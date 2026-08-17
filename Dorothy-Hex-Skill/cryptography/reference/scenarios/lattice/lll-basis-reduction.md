# LLL Basis Reduction — Practical Recipe

## When this applies

- A challenge gives you several quantities that are integer linear combinations of an unknown small vector plus large public values.
- The unknown is "small" (bounded) but lives modulo something large; brute force is infeasible.
- Trigger keywords: "subset sum", "knapsack", "AGCD", "hidden number problem", "approximate divisor", "lattice", "shortest vector".
- You see relations like `c_i = a_i·s + e_i (mod N)` with `|e_i|` much smaller than `N`.

## Technique

Build an integer lattice whose **shortest non-zero vector** encodes the secret. Run LLL — fast polynomial-time basis reduction — to recover that short vector. The art is in matrix construction; once the matrix is right, the library does the rest.

## Steps

### 1. State the relation

Write the public/private relationship as `target = sum(c_i · v_i)` where the `v_i` are basis rows you control and the `c_i` (or one of the `v_i`) is short.

### 2. Build the basis

Each row of the basis represents one constraint or one secret-bearing slot. Pad with diagonal blocks scaled to balance row norms — roughly each component should sit around `2^B` for the same `B`. Common skeletons:

- **CVP via Babai**: append a target column.
- **HNP (hidden number problem)**: append `B` weights to enforce that the bias term dominates.
- **Subset sum / low-density knapsack**: identity rows + a final column with the target.

### 3. Reduce

```python
from fpylll import IntegerMatrix, LLL
B = IntegerMatrix.from_matrix(rows)
LLL.reduction(B)
short = list(B[0])  # candidate
```

For larger / harder lattices, use BKZ:

```python
from fpylll import BKZ
BKZ.reduction(B, BKZ.Param(block_size=20))
```

### 4. Decode the short vector

The output row(s) of LLL contain the secret in known coordinate slots. Verify by plugging back into the original relation.

## Verifying success

- Reconstruct the public values from the recovered secret (`expected == observed`).
- Re-derive the short vector via the original protocol (e.g. compute `c_i - a_i·s mod N` and confirm `|e_i|` is small).
- For HNP/RSA-style: confirm `gcd(recovered, n) > 1` factors `n`.

## Common pitfalls

- **Wrong row scaling.** Components differing by 100+ bits make LLL ignore the small-vector slot. Scale slots so all "important" entries sit at similar bit lengths.
- **Too few samples.** AGCD/HNP lattices need m roughly proportional to bitsize/leak; `m=20–30` for 512–640 bit `r` with byte-level leaks.
- **Sign convention.** LLL gives the shortest vector regardless of sign; check `±short` against the relation.
- **Float precision in fplll.** For dimensions >150 use `LLL.reduction(B, method='proved')` or BKZ with high precision.
- **fpylll vs SageMath.** Most CTF lattices fit in fpylll; reach for Sage only when you need lattice-with-Q (rationals) or higher-level small-roots wrappers.

## Tools

- `fpylll` (Python bindings to fplll) — AGCD, knapsack, HNP up to dim ~300.
- `sympy.matrices` for setup; `gmpy2.mpz` for big integers.
- SageMath only when you need built-in `coppersmith_howgrave_graham` or `BKZ.shortest_vectors`.
- `flatter` (https://github.com/keeganryan/flatter) — drop-in faster replacement for LLL on large lattices.
