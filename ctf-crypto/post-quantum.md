# CTF Crypto - Post-Quantum Recognition (ML-KEM / ML-DSA / Estimator)

> Split from `lattice-and-lwe.md` -- PQC tables live here when lattice file exceeds 950 lines.

## Module-LWE / ML-KEM (Kyber) Recognition (G7)

**Standardized:** ML-KEM (Kyber), ML-DSA (Dilithium) -- NIST PQC. CTF gives `q=3329`, `N=256`, rank `k=2/3/4`.

| Scheme | k | q | eta (secret) | du/dv (compression) | ring |
|--------|---|---|---------------|----------------------|------|
| ML-KEM-512 | 2 | 3329 | 3 | du=10, dv=4 | Z_q[x]/(x^256+1) |
| ML-KEM-768 | 3 | 3329 | 2 | du=10, dv=4 | Z_q[x]/(x^256+1) |
| ML-KEM-1024| 4 | 3329 | 2 | du=11, dv=5 | Z_q[x]/(x^256+1) |

**Flattening Ring-LWE to plain LWE:** `A in R_q^{k x k}` -> `A_flat in Z_q^{256k x 256k}` via negacyclic `rot` of each polynomial. Same for `b = A*s + e`. Then LWE is `b_flat = A_flat * s_flat + e_flat` with `s_flat,e_flat` small `eta` (centered binomial).

```python
# flatten Module-LWE to plain LWE for lattice attack (SandboxAQ style)
def flatten_mlkem(A_poly, s_poly, e_poly, q=3329):
    """A_poly: k x k list of polys length 256, s_poly: k polys.
    Returns A_flat (256k x 256k), s_flat (256k), e_flat (256k).
    Each poly -> 256x256 negacyclic matrix.
    """
    k = len(A_poly)
    N = 256
    dim = k * N
    # build A_flat block matrix
    A_flat = [[0]*dim for _ in range(dim)]
    for i in range(k):
        for j in range(k):
            poly = A_poly[i][j]  # length N
            for r in range(N):
                for c in range(N):
                    # negacyclic: if c > r then -(poly[(c-r) mod N]) else poly[c-r]
                    # simplified
                    pass
    return A_flat
```

**FO failure oracle:** ML-KEM uses Fujisaki-Okamoto transform -- decryption failure leaks `e` via `du/dv` compression (lossy). CTF may give failure oracle (yes/no) -> use via BDD.

**NTT misorder:** Kyber NTT is bit-reversed order; challenge may give `A_ntt` without `bitrev` -- reorder before `inv_ntt`.

---

## Kannan / Arora-Ge / LWE Estimator Decision Tree (G10)

**When to use what:**

- **Kannan embedding** (`lambda=1` vs Bai-Galbraith `BDGL16`): Kannan `[[B 0],[t 1]]` is generic CVP -> BDD. Bai-Galbraith tweaks `lambda` to balance `||e||` vs `||s||` when `q` moderate and `secret` small. Use `lambda = q / (2*bound)` heuristic; sweep `1, q/4, q/2`.

- **Arora-Ge:** linearization when error `B < q/4` small and many samples. Build polynomial system `f_i(s) = ( <a_i,s> - b_i )*(...)` over `Z_q`, solve via Gröbner / linearization. Works for `m >> n^d` (e.g. `n=64, B<8`). If `B >= q/4` prefer lattice.

- **Hybrid MITM for sparse secrets:** secret `s` sparse `h=20` in `n=512` -> split `s = s1 + s2`, meet-in-the-middle via `BKZ` on projected lattice.

- **LWE estimator:** use `https://github.com/malb/lattice-estimator` (Albrecht et al.) to choose strategy:

```python
# estimator decision sketch (run offline: python -m estimator ...)
# Input: n=512, q=3329, Xs=CBeta(eta=2), Xe=CBeta(eta=2), m=256k
# Output: cost of BKZ 40 vs Arora-Ge vs hybrid
# In CTF, estimate with: from estimator import LWE
# LWE.estimate(n, q, Xs, Xe, m)
```

**Decision tree:**

```
LWE instance (n,q,m,Xs,Xe)
 ├─ B < q/4 and m > 2n  --> Arora-Ge (linearize, Gröbner)
 ├─ secret sparse (h < 0.1n) --> hybrid MITM + BKZ
 ├─ dim < 80  --> Kannan embedding + LLL then CVP.closest_vector
 ├─ dim 80-150 --> Bai-Galbraith embedding + BKZ 20-30 + GSO.Mat.babai
 └─ dim >150  --> estimator + BKZ 40+ or flatter (dim>100)
```

**Estimator guidance:** `lambda=1` generic; `Bai-Galbraith` when `q` small (`3329`) and `eta` tiny (`2,3`); `estimator` chooses `block_size` vs `hybrid`.

**Cross-link:** For Coppersmith small roots see `advanced-math.md` `hg_matrix(f_coeffs,N,X,beta,m,t) -> IntegerMatrix -> LLL -> sympy Poly` (beta=0.5, monic check, flatter optional).



---

*Back-link: see `lattice-and-lwe.md` NTRU (G1), GGH (G2), Mersenne AJPS (G3) for lattice construction; Coppersmith `hg_matrix` lives in `advanced-math.md`.*

