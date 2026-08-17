# Custom-Hash / Custom-Cipher Linear Collapse (GF(2) Affine Recovery)

## When to apply
Reach for this when the challenge ships a **custom hash or block cipher** that *looks* complicated (multi-round, S-box, bit permutation, round keys) but whose primitives are all individually linear or affine over GF(2). The entire construction collapses to a single matrix equation regardless of round count.

Trigger keywords in challenge tags or hints: `Linear Cryptanalysis`, `Plaintext attack`, `Weak Cryptography`. Title puns like "Always Has Been" / "It's all linear?" / "Affine" are spoilers.

## Detection checklist (read source first)

1. **S-box defined as XOR of a constant table and a key byte** — e.g. `sbox[i] = TABLE[i] ^ key[0]`.
2. **Round operation** is one of: byte-wise XOR with key, bit permutation, table lookup. No nonlinear ops like AND/OR, modular addition, or actual S-box substitution that mixes bits non-linearly.
3. **Affine table check**: verify `TABLE[i ^ j] == TABLE[i] ^ TABLE[j] ^ TABLE[0]` for all `i, j ∈ [0, 256)`. If true, the table is GF(2)-affine and acts as a linear map plus constant.
4. **Round keys derived linearly** from the master key (XOR/permute only).

If all four hold, the round function `R_k(x) = M·x + c(k)` for some fixed binary matrix `M` and key-dependent vector `c(k)`. Composition of affine maps is affine, so the whole cipher is `E_k(x) = A·x + b(k)` over GF(2)^n.

## Attack recipe

Treat the cipher as a black-box `E(data, key)` over GF(2)^n.

```python
n = 256  # block size in bits

def to_bits(b):  # bytes → length-n GF(2) vector
    return [int(c) for B in b for c in f"{B:08b}"]

def from_bits(v):
    return bytes(int("".join(map(str, v[i:i+8])), 2) for i in range(0, n, 8))

# 1. Recover constant term
b = to_bits(E(zero_block, target_key))

# 2. Recover linear part column-by-column: A · e_i = E(e_i) + b
A = [[0]*n for _ in range(n)]
for i in range(n):
    e = [0]*n; e[i] = 1
    col = [(x ^ y) for x, y in zip(to_bits(E(from_bits(e), target_key)), b)]
    for r in range(n):
        A[r][i] = col[r]

# 3. Solve A · flag = H + b for the published digest H
# Gaussian elimination over GF(2) — pure Python, ~1s for n=256.
```

When the challenge sets `data = key = flag` (single-block hash), repeat steps 1–2 with the cipher specialized to `E(F) = E_F(F)`. The result is still affine in `F` because both data and key paths are linear.

## Solving non-full-rank systems
Rank `< n` happens when 1+ bits of the recovered secret are not constrained (typical: 1-bit kernel ⇒ 2 candidates). Enumerate the kernel (≤ 2^k vectors for kernel dim k) and pick the one matching the expected wrapper (e.g. `<FLAG>`-style brace prefix) or printable ASCII.

## Tools
- Pure Python is enough for n≤512. No SageMath needed.
- For n>512 or sparse systems: `numpy` over `bool` dtype with custom XOR row-reduction, or `pyfinite` / `galois` packages.

## Worked example

When you encounter a 100-round "custom hash" with S-box defined as `KEY_SBOX[i] ^ key[0]`, bit permutation, and XOR rounds: it collapses to a GF(2) affine map. Run the recipe above — Gaussian elimination over GF(2) recovers the input in ~1s.

## Anti-pattern: do NOT
- Try to fuzz/brute-force the cipher.
- Implement classical differential/linear cryptanalysis traces — irrelevant when the cipher is *purely* linear.
- Reach for SAT solvers — Gaussian elimination is exact and far faster.
