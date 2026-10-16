# CTF Crypto - Elliptic Curve Attacks

## Table of Contents
- [Small Subgroup Attacks](#small-subgroup-attacks)
- [Invalid Curve Attacks](#invalid-curve-attacks)
- [Singular Curves](#singular-curves)
- [Smart's Attack (Anomalous Curves)](#smarts-attack-anomalous-curves)
- [HNP Cross-Link: ECDSA Truncated Nonces → Lattice (8-sig example)](#hnp-cross-link-ecdsa-truncated-nonces--lattice-8-sig-example)
- [MOV Attack (Weil Pairing, embedding degree k≤6)](#mov-attack-weil-pairing-embedding-degree-k6)
- [Twist Security & Twist Attacks](#twist-security--twist-attacks)
- [GLV / CM Endomorphism Leakage (d=-3/-4)](#glv--cm-endomorphism-leakage-d-3-4)
- [ECC Fault Injection](#ecc-fault-injection)
- [Clock Group DLP via Pohlig-Hellman (LACTF 2026)](#clock-group-dlp-via-pohlig-hellman-lactf-2026)
- [ECDSA Nonce Reuse (BearCatCTF 2026)](#ecdsa-nonce-reuse-bearcatctf-2026)
- [Ed25519 Torsion Side Channel (BearCatCTF 2026)](#ed25519-torsion-side-channel-bearcatctf-2026)
- [DSA Nonce Reuse for Private Key Recovery (VolgaCTF 2016)](#dsa-nonce-reuse-for-private-key-recovery-volgactf-2016)
- [DSA Limited k-Value Brute Force (ASIS CTF Finals 2016)](#dsa-limited-k-value-brute-force-asis-ctf-finals-2016)
- [ECC Shared Prime Factor via GCD (ASIS CTF Finals 2016)](#ecc-shared-prime-factor-via-gcd-asis-ctf-finals-2016)
- [DSA Key Recovery via MD5 Collision on k-Generation (CONFidence CTF 2017)](#dsa-key-recovery-via-md5-collision-on-k-generation-confidence-ctf-2017)
- [Ed25519 Same-Nonce Key Recovery (hxp 2018)](#ed25519-same-nonce-key-recovery-hxp-2018)
- [Singular Curve ECDLP to Additive/Multiplicative Group (hxp 2018)](#singular-curve-ecdlp-to-additivemultiplicative-group-hxp-2018)
- [X25519 Low-Order Points + All-Zero Check (RFC 7748)](#x25519-low-order-points--all-zero-check-rfc-7748)

---

## Small Subgroup Attacks

- Check curve order for small factors
- Pohlig-Hellman: solve DLP (Discrete Logarithm Problem) in small subgroups, combine with CRT (Chinese Remainder Theorem)

```python
from sympy import factorint
# Pure-Python ECC basics via py_ecc / ecdsa (no Sage)
# For curve y^2 = x^3 + a*x + b over GF(p), use ecdsa library:
from ecdsa.ellipticcurve import CurveFp, Point

curve = CurveFp(p, a, b)
G = Point(curve, Gx, Gy, order=None)  # set order if known
# Curve order via brute or Schoof (small p) or known value
# For large p, factor order with sympy if order is known:
# factors = factorint(order)
```

<details><summary>Sage fallback (optional)</summary>

```python
# SageMath ECC basics
E = EllipticCurve(GF(p), [a, b])
G = E.gens()[0]  # generator
order = E.order()
```

</details>

**Key insight:** When the curve order has small prime factors, Pohlig-Hellman decomposes the DLP into small subgroup problems solvable independently, then combines results with CRT. Always factor the curve order first -- if it is smooth (all small factors), the DLP is trivially solvable.

---

## Invalid Curve Attacks

If point validation is missing, send points on weaker curves. Craft points with small-order subgroups to leak secret key bits. Point addition formulas depend on `a` but not `b` (short Weierstrass), so any `b'` yields a usable curve when validation is skipped.

**Key insight:** Invalid curve attacks exploit missing point-on-curve validation. Send crafted points that lie on a different curve with a small-order subgroup, and the server will compute scalar multiplication on the weak curve, leaking secret key bits modulo the small order. Always check `is_on_curve`: if attacker-supplied `(x,y)` passes without verifying `y^2 == x^3 + a*x + b (mod p)`, every `b' = y^2 - x^3 - a*x` is a candidate weak curve.

### 5 Variant Table

| # | Variant | Recognition | Exploit Sketch | Ref |
|---|---------|-------------|----------------|-----|
| 1 | **Classic same-`a` arbitrary `b`** small-order CRT | `a` unchanged, `b'` chosen; `factor(E.order())` has small prime `r`; server oracle returns `[k]P` or MAC/HMAC oracle | Mine `b'` until `N = #E_b'` is smooth; craft `P` of order `r` via `(N/r)*R`; query oracle to learn `k mod r` (try `±r` if x-only); CRT across many `r` | Biehl-Meyer-Müller 2000 / CVE-2015-0204 |
| 2 | **Codegate 2024 Babylogin** `a=-3` → `3q` trick | `a = -3` (NIST P-256 optimized); implementation uses same Jacobian formulas for every `b'`; KDF uses only `x([s]P)` | Search `E_{b'}: y^2 = x^3 -3x + b'` for order with factor `3*q` (small `q`); build point of order `3q` → probe `s mod q` via x-only HMAC verification; CRT with 3-modulus to resolve sign | Codegate 2024 Babylogin (affine.group) |
| 3 | **CUHK 2025 multi-query** `C2 - d*C1` via `C1=-P, C2=O ⇒ dP` + singular fallback `y^2 = x^3` | Protocol returns `R = C2 - d*C1`; no `is_on_curve` on `C1,C2`; discriminant `Δ = 0` candidate accepted | Send `C1 = -P, C2 = O` so `R = dP` directly; choose singular `P=(1,1)` on `y^2=x^3` → `dP=(d^2,d^3)` ⇒ `d = y/x`; generic case: multiple `b'` + CRT fallback | CUHK 2025 Trustworthy Person |
| 4 | **ISCTF 2025 fake generator off-curve** | Curve advertises `y^2 = x^3 + 3x + 27` but generator `G` is secp256k1 `G` (`a=0,b=7`) → `G` not on advertised curve; `b'` computed as `Gy^2 - Gx^3 - a*Gx` | Recompute `b' = Gy^2 - Gx^3 - a*Gx mod p`; solve ECDLP on actual curve `E_{a,b'}` (small `k` → brute/BSGS, else Pohlig-Hellman) | ISCTF 2025 (isc.tf) |
| 5 | **Montgomery/ladder twist** `x-only` lands on twist | Montgomery `Bv^2 = u^3 + Au^2 + u`; server uses x-only ladder (no `v` check); `f(u)/B` is non-residue → point on twist | If twist order `p+1-#E` (`= p+1+t`) is smooth/small factor, supply `u` on twist with small order `r`, learn `k mod r` via oracle (MAC/decryption/contributory check); CRT; mitigations: twist-secure curve, residue test | SafeCurves twist security / RFC 7748 |

**Detection checklist:** (1) `is_on_curve` missing? (2) Does formula use `b`? (no → any `b'` works). (3) Twist order `p+1-#E` smooth? (`factor(p+1-t)`). (4) Discriminant `Δ = -16(4a^3+27b^2) == 0`? → singular. (5) Generator satisfies curve? (`y^2 != x^3+a*x+b` → fake generator).

**Mining `b'` and crafting small-order points + CRT:**

```python
from sympy import factorint
from sympy.ntheory.modular import crt
from ecdsa.ellipticcurve import CurveFp, Point, INFINITY
import random

def is_smooth(n, bound=1_000_000):
    """True if all prime factors of n <= bound."""
    try:
        return max(factorint(n).keys()) <= bound
    except ValueError:  # n==1
        return True

def _mod_sqrt(n, p):
    """sqrt(n) mod odd prime p, or None if non-residue. sympy first, TS fallback."""
    try:
        from sympy.ntheory import sqrt_mod
        r = sqrt_mod(n, p, all_roots=False)  # returns int root or None if non-residue
        return int(r) if r is not None else None
    except (ImportError, ValueError):
        pass
    # Fallback Tonelli-Shanks (no dependency).
    if n == 0:
        return 0
    if pow(n, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    q, s = p - 1, 0  # p-1 = q * 2^s with q odd
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(n, q, p), pow(n, (q + 1) // 2, p)
    while t != 1:
        i, tmp = 1, pow(t, 2, p)
        while tmp != 1:
            tmp = pow(tmp, 2, p)
            i += 1
        b = pow(c, 1 << (m - i - 1), p)
        m, c, t, r = i, pow(b, 2, p), (t * b * b) % p, (r * b) % p
    return r

def point_of_order(E, N, r):
    """Return random point of exact order r on curve E (curve order N, r|N)."""
    # E: ecdsa CurveFp object; need point sampling via brute x
    p = E.p()
    a = E.a()
    b = E.b()
    while True:
        x = random.randrange(p)
        rhs = (pow(x, 3, p) + a * x + b) % p
        if rhs == 0:
            y = 0
        else:
            # Legendre check: gmpy2.legendre (fast C-GMP) with pow Euler fallback
            try:
                import gmpy2
                if gmpy2.legendre(rhs, p) != 1:
                    continue
            except ImportError:
                if pow(rhs, (p - 1) // 2, p) != 1:  # Euler criterion: non-residue
                    continue
            y = _mod_sqrt(rhs, p)  # sympy sqrt_mod first, Tonelli-Shanks fallback
            if y is None:
                continue
        for yy in (y, p - y):
            try:
                P = Point(E, x, yy, order=None)
            except Exception:
                continue
            # The identity is ecdsa.ellipticcurve.INFINITY, NOT Point(E, None, None)
            # -- Point(curve, None, None) trips `assert curve.contains_point(None, None)`.
            # Keep the point on the left: INFINITY.__eq__ compares curves, Q.__eq__
            # short-circuits on `other is INFINITY`.
            Q = P * (N // r)  # cofactor projection N/r * random point
            if Q != INFINITY and (Q * r) == INFINITY:
                # verify exact order r (check no smaller divisor)
                is_exact = True
                for pr in factorint(r):
                    if (Q * (r // pr)) == INFINITY:
                        is_exact = False
                        break
                if is_exact:
                    return Q

def mine_b_prime(p, a, smooth_bound=5000, max_tries=5000):
    """Find b' such that E: y^2=x^3+a*x+b' has smooth order with small prime factor."""
    for _ in range(max_tries):
        b_prime = random.randrange(p)
        # Need curve order N = #E_b'; for small p brute, else use Sage E.order()
        # Demo: small p enumeration; for large p replace with Sage cardinality
        E = CurveFp(p, a, b_prime)
        # For demo with small p, compute order by brute enumeration
        # For real CTF with large p, use: E_sage = EllipticCurve(GF(p), [a, b_prime]); N = E_sage.order()
        N = None  # placeholder: set via Sage or Schoof for large p
        # Example check (fill N when known):
        if N is not None and N % 2 == 0:
            fac = factorint(N)
            small = [pr for pr in fac if pr < smooth_bound]
            if small:
                r = min(small)
                if max(fac.keys()) < smooth_bound * 10:
                    return b_prime, N, r
    return None

def recover_via_crt(residues, moduli):
    """Combine k mod r_i via CRT (pairwise coprime moduli)."""
    res = crt(moduli, residues)
    return int(res[0] % res[1]) if res is not None else None

# Usage sketch (large p requires Sage for E.order()):
# b_prime, N, r = mine_b_prime(p, -3)  # Codegate a=-3 case
# E = CurveFp(p, -3, b_prime)
# P_r = point_of_order(E, N, r)  # N/r * random point of order r
# # Query oracle with P_r to learn k mod r (try both r and -r if x-only)
# # Repeat for many r_i, then k = recover_via_crt([k_mod_r1, ...], [r1, ...])
```

<details><summary>Sage fallback (optional) -- robust for large p</summary>

```python
from sage.all import GF, EllipticCurve
from sympy.ntheory.modular import crt
from sympy import factorint

p = 2**256 - 2**224 + 2**192 + 2**96 - 1  # P-256 example
Fp = GF(p)

def mine_b_prime_sage(a, bound=5000):
    while True:
        b_prime = Fp.random_element()
        E = EllipticCurve(Fp, [a, b_prime])
        N = E.order()
        fac = factorint(int(N))
        # smooth / small factor test
        if max(fac.keys()) < bound * 10 and any(pr < bound for pr in fac):
            # pick smallest prime factor as oracle modulus
            r = min(pr for pr in fac if pr < bound)
            return E, N, r

def point_of_order_sage(E, r):
    N = E.order()
    while True:
        P = E.random_point()
        Q = (N // r) * P  # N/r * random point of order r
        if not Q.is_zero() and r * Q == E(0):
            # ensure exact order r
            if all((r // pr) * Q != E(0) for pr in factorint(r)):
                return Q

# Example: a=-3 case (Codegate Babylogin)
E, N, r = mine_b_prime_sage(Fp(-3), bound=5000)
P = point_of_order_sage(E, r)
# Probe oracle with P (try r and -r for x-only KDF), collect residues, then:
# k, _ = crt(moduli, residues)
```

</details>

---

## Singular Curves

If discriminant delta = 0, curve is singular. DLP becomes easy (maps to additive/multiplicative group).

**Key insight:** Check the discriminant `4a^3 + 27b^2 mod p` first. If it is zero, the curve is singular and the ECDLP reduces to a simple discrete log in the additive group (cusp) or multiplicative group (node) of the field, both solvable in polynomial time.

---

## Smart's Attack (Anomalous Curves)

**When to use:** Curve order equals field characteristic p (anomalous curve). Solves ECDLP in O(1) via p-adic lifting.

**Key insight:** Always check `E.order() == p` first. If the curve order equals the field prime, the ECDLP is solved instantly via p-adic lifting (Smart's attack). SageMath's `discrete_log` handles this automatically, but manual p-adic lift code is needed when the built-in method fails.

**Detection:** `E.order() == p` -- always check this first!

**Pure-Python (py_ecc / ecdsa) for anomalous check:**
```python
from ecdsa.ellipticcurve import CurveFp, Point
from Crypto.Util.number import inverse

curve = CurveFp(p, a, b)
# Anomalous check: compute curve order (for small p brute, else given)
# If order == p, use Smart's p-adic lift below without Sage
```

**Pure-Python Smart's attack (anomalous, order == p):**

Hensel lift is O(1) via Newton; brute `for dy in range(p)` is O(p) and fails for large p.

```python
# pow(x, -1, m) is stdlib Python 3.8+ (use Crypto.Util.number.inverse only for older runtimes).

def lift_point(x, y, p, a, b, mod=None):
    """Hensel lift (x,y) on y^2 = x^3 + a*x + b from mod p to mod p^2. O(1)."""
    if mod is None:
        mod = p * p
    rhs = (pow(x, 3, mod) + a * x + b) % mod
    c = (y * y - rhs) // p                 # exactly divisible by p
    t = (-c * pow(2 * y % p, -1, p)) % p   # solve c + 2*y*t == 0 (mod p)
    return (x % mod, (y + t * p) % mod)

# --- Jacobian coordinates over Z/p^2: (X,Y,Z) <-> (X/Z^2, Y/Z^3) ----------
# Affine arithmetic over Z/p^2 does NOT work here: while computing p*G_hat two
# addends become congruent mod p but not mod p^2, so (x2-x1) is a zero divisor
# and pow(..., -1, mod) raises ValueError -- the `inverse()` fallback raises the
# very same error. Jacobian formulas only add and multiply, nothing to invert.
def j_add(P, Q_, mod, a):
    if P[2] == 0:
        return Q_
    if Q_[2] == 0:
        return P
    X1, Y1, Z1 = P; X2, Y2, Z2 = Q_
    Z1Z1 = Z1 * Z1 % mod; Z2Z2 = Z2 * Z2 % mod
    U1 = X1 * Z2Z2 % mod                    # x1 * Z1^2 * Z2^2
    U2 = X2 * Z1Z1 % mod                    # x2 * Z1^2 * Z2^2
    S1 = Y1 * Z2 % mod * Z2Z2 % mod         # y1 * Z1^3 * Z2^3
    S2 = Y2 * Z1 % mod * Z1Z1 % mod         # y2 * Z1^3 * Z2^3
    u = (S2 - S1) % mod                     # (y2-y1)*Z1^3*Z2^3
    v = (U2 - U1) % mod                     # (x2-x1)*Z1^2*Z2^2
    if v == 0:                              # lambda = u/(v*Z1*Z2) blows up
        return j_double(P, mod, a) if u == 0 else (0, 1, 0)
    uu = u * u % mod; vv = v * v % mod
    X3 = (uu - vv * ((U1 + U2) % mod)) % mod
    Y3 = (u * ((vv * U1 - X3) % mod) - v * vv % mod * (Z2 * Z2Z2 % mod) * Y1) % mod
    Z3 = v * Z1 % mod * Z2 % mod
    return (X3, Y3, Z3)

def j_double(P, mod, a):
    if P[2] == 0 or P[1] == 0:
        return (0, 1, 0)
    X1, Y1, Z1 = P
    XX = X1 * X1 % mod; YY = Y1 * Y1 % mod; YYYY = YY * YY % mod; ZZ = Z1 * Z1 % mod
    S = 2 * ((X1 + YY) * (X1 + YY) % mod - XX - YYYY) % mod
    M = (3 * XX + a * ZZ % mod * ZZ) % mod
    T = (M * M - 2 * S) % mod
    X3 = T
    Y3 = (M * ((S - T) % mod) - 8 * YYYY) % mod
    Z3 = ((Y1 + Z1) * (Y1 + Z1) - YY - ZZ) % mod
    return (X3, Y3, Z3)

def j_mul(P, k, mod, a):
    R = (0, 1, 0); Q_ = P
    while k:
        if k & 1:
            R = j_add(R, Q_, mod, a)
        Q_ = j_double(Q_, mod, a)
        k >>= 1
    return R

def psi_jac(P, mod):
    """x/y for a Jacobian point: (X/Z^2)/(Y/Z^3) == X*Z/Y. None if Y is a zero divisor."""
    X, Y, Z = P
    try:
        return X * Z % mod * pow(Y, -1, mod) % mod
    except ValueError:
        return None

def mul_affine(P, k, p, a):
    """Reference scalar multiplication over GF(p) - used only to verify a candidate."""
    def add(P_, Q_):
        if P_ is None:
            return Q_
        if Q_ is None:
            return P_
        x1, y1 = P_; x2, y2 = Q_
        if x1 == x2 and (y1 + y2) % p == 0:
            return None
        if P_ == Q_:
            lam = (3 * x1 * x1 + a) * pow(2 * y1 % p, -1, p) % p
        else:
            lam = (y2 - y1) * pow((x2 - x1) % p, -1, p) % p
        x3 = (lam * lam - x1 - x2) % p
        return (x3, (lam * (x1 - x3) - y1) % p)
    R = None; Q__ = P
    while k:
        if k & 1:
            R = add(R, Q__)
        Q__ = add(Q__, Q__)
        k >>= 1
    return R

def smart_attack(p, a, b, G, Q):
    """Recover d with Q = d*G on an anomalous curve (#E == p). None if this curve's
    canonical lift has order p in E(Z/p^2) (then p*G_hat == O and psi is undefined);
    for those curves use Sage, whose discrete_log handles anomalous curves itself."""
    mod = p * p
    gx, gy = G; qx, qy = Q
    # two y-roots per x (negation); try both signs
    for sg in (1, -1):
        for sq in (1, -1):
            try:
                Gl = lift_point(gx, sg * gy % p, p, a, b)
                Ql = lift_point(qx, sq * qy % p, p, a, b)
                sG = psi_jac(j_mul((Gl[0], Gl[1], 1), p, mod, a), mod)
                sQ = psi_jac(j_mul((Ql[0], Ql[1], 1), p, mod, a), mod)
            except ValueError:
                continue
            if sG is None or sQ is None:
                continue
            # Satoh-Skjernaa-Taguchi: psi(p*P_hat) must be divisible by p
            if sG % p or sQ % p:
                continue
            vg = (sG // p) % p; vq = (sQ // p) % p
            if vg == 0:
                continue
            secret = (vq * pow(vg, -1, p)) % p
            if mul_affine(G, secret, p, a) == Q:
                return secret
            if mul_affine(G, (-secret) % p, p, a) == Q:
                return (-secret) % p
    return None
```

<details><summary>Sage fallback (optional)</summary>

```python
E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy)
Q = E(Qx, Qy)
# Sage's discrete_log handles anomalous curves automatically
secret = G.discrete_log(Q)
```

**Manual p-adic lift (when Sage's auto method fails):**
```python
def smart_attack(p, a, b, G, Q):
    E = EllipticCurve(GF(p), [a, b])
    Qp = pAdicField(p, 2)  # p-adic field with precision 2
    Ep = EllipticCurve(Qp, [a, b])

    # Lift points to p-adics
    Gp = Ep.lift_x(ZZ(G[0]), all=True)  # try both lifts
    Qp_point = Ep.lift_x(ZZ(Q[0]), all=True)

    for gp in Gp:
        for qp in Qp_point:
            try:
                # Multiply by p to get points in kernel of reduction
                pG = p * gp
                pQ = p * qp
                # Extract p-adic logarithm
                x_G = ZZ(pG[0] / pG[1]) / p  # or pG.xy()
                x_Q = ZZ(pQ[0] / pQ[1]) / p
                secret = ZZ(x_Q / x_G) % p
                if E(G) * secret == E(Q):
                    return secret
            except (ZeroDivisionError, ValueError):
                continue
    return None
```

</details>

**Multi-layer decryption after key recovery:** Challenge may wrap flag in AES-CBC + DES-CBC or similar -- just busywork once the ECC key is recovered. Derive keys with SHA-256 of shared secret.

---

## HNP Cross-Link: ECDSA Truncated Nonces → Lattice (8-sig example)

> **Cross-link:** Full HNP lattice construction lives in `lattice-and-lwe.md:144` -- this box gives the minimal ECC wiring.

**When to use:** ECDSA/Schnorr signatures leak truncated nonces `k_i = leaked_i * 2^t + delta_i` where `delta_i` is small (low `t` bits unknown). Classic CTF: 8 signatures, top bits leaked, brute remaining 2 bits after LLL.

**Lattice:** `(n+2)×(n+2)` `IntegerMatrix.from_matrix(rows) + LLL.reduction + verify d + brute last 2 bits`

```python
from fpylll import IntegerMatrix, LLL
from Crypto.Util.number import inverse

# 8-sig truncated-nonce example: k_i = leaked_i*2^t + delta_i, delta_i in [0, 2^t)
# ECDSA: s_i*k_i - h_i == r_i*d (mod q)  =>  r_i*d - s_i*delta_i == s_i*leaked_i*2^t - h_i (mod q)
def build_hnp_8sig_lattice(q, rs, ss, hs, leaked, t):
    n = len(rs)  # n=8 typical
    assert n == 8
    rows = [[0]*(n+2) for _ in range(n+2)]
    for i in range(n):
        rows[i][i] = int(q)
    for i in range(n):
        rows[n][i] = int(ss[i] % q)
        rows[n+1][i] = int((hs[i] - ss[i]*leaked[i]*(1<<t)) % q)
    rows[n][n] = 1
    rows[n+1][n+1] = int(q // (1<<t))  # scaling: bounds on delta_i
    M = IntegerMatrix.from_matrix(rows)
    LLL.reduction(M)
    return M

def recover_d_from_hnp(M, q, rs, ss, hs, t):
    # Inspect short rows for candidate d = |M[row][n]|, try sign + brute last 2 bits
    for row in M:
        for cand in (row[-2] % q, (-row[-2]) % q):
            if cand == 0:
                continue
            ok = True
            for r, s, h in zip(rs, ss, hs):
                # verify ECDSA equation exists k with leaked form
                # we have delta = leaked*2^t + ?; check via s*k - h == r*d
                pass  # full verify below
            # Quick verify: recompute delta_i and check bounds
            valid = True
            for i in range(len(rs)):
                # k_i = s_i^{-1}(h_i + r_i*d) mod q; check low t bits match delta range
                k_i = (inverse(int(ss[i]), int(q)) * (int(hs[i]) + int(rs[i])*cand)) % int(q)
                # delta = k_i - leaked*2^t  mod q, expect in [0, 2^t)
                delta = (k_i - leaked[i]*(1<<t)) % int(q)
                if delta >= (1<<t) and delta <= int(q)-(1<<t):
                    # allow wrap: delta should be small, also try q-delta
                    if min(delta, int(q)-delta) >= (1<<t):
                        valid = False
                        break
            if valid:
                # brute last 2 bits if off by 1-3
                for tweak in range(4):
                    for sign in (1, -1):
                        d_try = (cand + sign*tweak) % int(q)
                        if all(pow(1,1,1)==1 for _ in []):  # placeholder for full sig verify
                            pass
                        # real verify: s_i*k_i == h_i + r_i*d_try mod q with bounded delta
                        good = True
                        for i in range(len(rs)):
                            k_i = (inverse(int(ss[i]), int(q)) * (int(hs[i]) + int(rs[i])*d_try)) % int(q)
                            delta = (k_i - leaked[i]*(1<<t)) % int(q)
                            if min(delta, int(q)-delta) >= (1<<t):
                                good = False
                                break
                        if good:
                            return d_try
    return None

# After LLL, if candidate is off by 1-2 bits, brute-force last 2 bits:
# for tweak in range(4): test d ^ tweak or d +/- tweak
```

<details><summary>Sage fallback (optional)</summary>

```python
from sage.all import Matrix, ZZ

def build_hnp_8sig_lattice_sage(q, rs, ss, hs, leaked, t):
    n = len(rs)
    M = Matrix(ZZ, n+2, n+2)
    for i in range(n):
        M[i,i] = q
    for i in range(n):
        M[n,i] = ss[i] % q
        M[n+1,i] = (hs[i] - ss[i]*leaked[i]*(1<<t)) % q
    M[n,n] = 1
    M[n+1,n+1] = q // (1<<t)
    return M.LLL()
```

</details>

**Key insight:** `HNP lattice (n+2)×(n+2) IntegerMatrix.from_matrix(rows) + LLL.reduction + verify d + brute last 2 bits` -- when `delta_i = k_i - leaked_i*2^t` is small, LLL finds `d` even with imperfect scaling. See `lattice-and-lwe.md:144` for full derivation and CVP/Babai details. Use 8+ sigs, `t >= 4` leaked top bits; if LLL row is near-miss, brute last 2 bits covers rounding.

---

## MOV Attack (Weil Pairing, embedding degree k≤6)

**When to use:** Curve order has small embedding degree `k = ord_r(p)` where `r` is the prime subgroup order. If `k ≤ 6` and `p^k - 1` factors with small primes (or `F_{p^k}` DLP is subexponential), ECDLP reduces to finite-field DLP via Weil/Tate pairing.

**Test:** For subgroup order `r` (prime factor of `#E`), compute `k = min i>0 s.t. r | p^i - 1`. Try `k=1..6` first -- supersingular curves have `k ≤ 6` always.

```python
def embedding_degree(p, r, kmax=6):
    """Embedding degree k = ord_r(p). SymPy n_order first, bounded loop fallback."""
    if r <= 1:
        return None
    try:
        from sympy.ntheory import n_order
        k = n_order(p % r, r)
        return k if k <= kmax else None
    except (ImportError, ValueError):
        pass
    cur = p % r
    for k in range(1, kmax + 1):
        if cur == 1:
            return k
        cur = (cur * p) % r
    return None

def is_mov_vulnerable(p, r):
    k = embedding_degree(p, r, kmax=6)
    if k is None:
        return False, None
    # Optional: check p^k -1 smoothness / field size feasibility
    # For CTF, k<=6 + p^k bitlen < ~2048 often already broken
    return True, k
```

**Exploit (Weil pairing):** Given `P, Q = dP` in `E[r]`, pick `R ∈ E[r]` independent of `P`, compute `a = e_r(P,R)`, `b = e_r(Q,R)` in `F_{p^k}^*`, solve `b = a^d` (finite-field DLP via `discrete_log` / NFS / Pohlig-Hellman if smooth).

**Pure-Python note:** No efficient pure-Python Weil pairing for large `p` -- use Sage `P.weil_pairing(Q, r)` over `GF(p^k)`. Detection + Sage fallback is the CTF path.

<details><summary>Sage fallback (optional) -- MOV via Weil pairing</summary>

```python
from sage.all import GF, EllipticCurve

def mov_attack(p, a, b, Gx, Gy, Qx, Qy, r):
    Fp = GF(p)
    E = EllipticCurve(Fp, [a, b])
    G = E(Gx, Gy)
    Q = E(Qx, Qy)
    k = 1
    while (pow(p, k, r) - 1) % r != 0 and k <= 6:
        k += 1
    if k > 6:
        return None  # MOV not applicable for large embedding degree
    Fpk = GF(p**k, 'alpha')
    Ek = EllipticCurve(Fpk, [a, b])
    Gk = Ek(Gx, Gy)
    Qk = Ek(Qx, Qy)
    R = None
    cofactor = Ek.order() // r
    for _ in range(100):
        pt = Ek.random_point() * cofactor
        if pt != Ek(0) and pt.weil_pairing(Gk, r) != Fpk(1):
            R = pt
            break
    if R is None:
        return None
    a_pair = Gk.weil_pairing(R, r)
    b_pair = Qk.weil_pairing(R, r)
    # finite-field DLP: b = a^d
    d = b_pair.discrete_log(a_pair)
    return int(d % r)
```

</details>

**References:** Menezes-Okamoto-Vanstone 1993; Frey-Rück (Tate) variant; `crypto.stanford.edu/pbc/notes/elliptic/movattack.html`.

---

## Twist Security & Twist Attacks

**Twist order:** If `#E = p + 1 - t` (trace `t`), quadratic twist has `#E' = p + 1 + t = p + 1 - #E + (p+1) ???` concretely `p+1+t`. Check `twist_order = p + 1 + t = 2*(p+1) - #E`.

```python
def twist_order(p, E_order):
    # #E = p+1 - t => t = p+1 - #E => #E' = p+1 + t = 2*(p+1) - #E
    return 2*(p+1) - E_order
```

**When vulnerable:** Implementation uses Montgomery `x-only` ladder (e.g., X25519) without validating `f(u)/B` is QR -- input may land on twist. If `twist_order` is smooth or has small factor `r`, send twist point of order `r` and learn `k mod r`.

**Check:** `factor(twist_order)` -- if smooth or has factor `< 1e6`, and protocol gives oracle (MAC/validity), attack as invalid-curve variant 5.

**Mitigations:** Use twist-secure curve (both `#E` and `#E'` have large prime factor, e.g., Curve25519), validate `is_on_curve` or QR check, reject zero shared secret (`RFC 7748`).

**References:** SafeCurves `safecurves.cr.yp.to/twist.html`; Bernstein 2006 twist attacks.

---

## GLV / CM Endomorphism Leakage (d=-3/-4)

**Pattern:** Curve has CM discriminant `d = -3` (`j=0`, `a=0`, `y^2=x^3+b`, sextic twists, `E: y^2=x^3+b` has `p ≡ 1 mod 3` gives endomorphism `phi: (x,y)->(zeta*x, y)`) or `d=-4` (`j=1728`, `a=...`, `y^2=x^3+a*x`, quartic twists, `phi: (x,y)->(-x, i*y)` when `p ≡ 1 mod 4`). GLV uses `phi` to decompose scalar: `kP = k1*P + k2*phi(P)` with `|k1|,|k2| ~ sqrt(n)`.

**CTF relevance:**
- If challenge leaks `k1` or `k2` timing/side-channel, or uses biased GLV decomposition, lattice recovers `k`.
- If `d=-3` curve reuses `zeta` endomorphism with small constants, check for weak `b` (small `b` → extra automorphisms).
- Detection: `j==0` → `d=-3`; `j==1728` → `d=-4`; `a==0 and p%3==1` or `b==0 and p%4==1`.

```python
def has_glv_endomorphism(p, a, b):
    # j=0 => d=-3, j=1728 => d=-4
    if a == 0 and b != 0:
        # y^2 = x^3 + b, j=0
        return p % 3 == 1, "-3 (j=0, sextic)"
    if b == 0 and a != 0:
        # y^2 = x^3 + a*x, j=1728
        return p % 4 == 1, "-4 (j=1728, quartic)"
    # generic: compute j
    j = 1728 * (4*a**3) * pow(4*a**3 + 27*b*b, -1, p) % p if (4*a**3+27*b*b)%p!=0 else None
    if j == 0:
        return True, "-3"
    if j == 1728 % p:
        return True, "-4"
    return False, None
```

**References:** Gallant-Lambert-Vanstone 2001; GLV endomorphism for `d=-3/-4`.

---

## ECC Fault Injection

**Pattern (Faulty Curves):** Bit flip during ECC computation reveals private key bits.

**Attack:** Compare correct vs faulty ciphertext, recover key bit-by-bit:
```python
# Bit flip simulation: gmpy2.bit_flip(scalar, bit_i) or scalar ^ (1 << bit_i)
# For each key bit position:
# If fault at bit i changes output -> key bit i affects computation
# Binary distinguisher: faulty_output == correct_output -> bit is 0
```

---

## Clock Group DLP via Pohlig-Hellman (LACTF 2026)

**Pattern (the-clock):** Diffie-Hellman on unit circle group: x^2 + y^2 = 1 (mod p).

**Key facts:**
- Group law: (x1,y1) * (x2,y2) = (x1*y2 + y1*x2, y1*y2 - x1*x2)
- **Group order = p + 1 if p ≡ 3 (mod 4)**, and **p - 1 if p ≡ 1 (mod 4)** — i.e. `#E = p + 1` exactly when `-1` is a quadratic non-residue mod p. Do not assume `p+1`; try both (a point (x,y) ↔ z = y + i·x, so this is the norm-1 subgroup of `GF(p^2)^*`)
- Isomorphic to GF(p^2)* elements of norm 1

**Group operations:**
```python
def clock_mul(P, Q, p):
    x1, y1 = P
    x2, y2 = Q
    return ((x1*y2 + y1*x2) % p, (y1*y2 - x1*x2) % p)

def clock_pow(P, n, p):
    result = (0, 1)  # identity
    base = P
    while n > 0:
        if n & 1:
            result = clock_mul(result, base, p)
        base = clock_mul(base, base, p)
        n >>= 1
    return result
```

**Recovering hidden prime p:**
```python
# Given points on the curve, p divides (x^2 + y^2 - 1)
from math import gcd
from functools import reduce
vals = [x**2 + y**2 - 1 for x, y in known_points]
p = reduce(gcd, vals)
# May need to remove small factors
```

**Attack when p+1 is smooth:**
```python
# 1. Recover p from points: gcd(x^2 + y^2 - 1) across known points
# 2. Factor p+1 into small primes
# 3. Pohlig-Hellman: solve DLP in each small subgroup, CRT combine
# 4. Compute shared secret, derive AES key (e.g., via MD5)
```

**Identification:** Challenge mentions "clock", "circle", or gives points satisfying x^2+y^2=1. Check **both** `p+1` and `p-1` for smoothness (`p ≡ 3 mod 4` gives `p+1`, `p ≡ 1 mod 4` gives `p-1`) — asserting "p+1 not p-1" silently breaks the `p ≡ 1 (mod 4)` case.

---

## Ed25519 Torsion Side Channel (BearCatCTF 2026)

**Pattern (Curvy Wurvy):** Ed25519 signing oracle derives per-user keys as `user_key = MASTER_KEY * uid mod l` (where `l` is the Ed25519 subgroup order). Goal: recover `MASTER_KEY` from oracle queries.

**The attack exploits Ed25519's cofactor h=8:**
- Full curve order = `8*l`, but scalars are reduced mod `l`
- When `MASTER_KEY * 2^t` wraps around `l`, multiplication produces a torsion component visible as y-coordinate change

**Key extraction via binary decomposition:**
```python
# Query sign(uid=3, 2^t) for t = 0..255
# S_t = (MASTER_KEY * 2^t mod l) * P3
# Check: does doubling S_t match S_{t+1}?

bits = []
for t in range(255):
    S_t = query_sign(3, 2**t)
    S_t1 = query_sign(3, 2**(t+1))
    doubled = point_double(S_t)
    # Wrap occurred if doubled.y != S_{t+1}.y (torsion shift)
    bits.append(0 if doubled.y == S_t1.y else 1)

# Reconstruct: MASTER_KEY ≈ l * (0.bit0 bit1 bit2 ...)_binary
# Try all 8 torsion corrections for exact value
```

**Key insight:** Ed25519's cofactor creates an observable side channel: when scalar multiplication wraps around the subgroup order `l`, the result shifts by a torsion element (one of 8 points). By querying powers of 2 and checking y-coordinate consistency, each bit of the secret scalar is leaked. Libraries like `ecpy` that reduce mod `l` are vulnerable to this when used in multi-user key derivation schemes.

**Detection:** Ed25519 signing oracle with user-controlled UID or multiplier. Key derivation formula `key = master * uid mod l`.

---

## ECDSA Nonce Reuse (BearCatCTF 2026)

**Pattern (Chatroom):** ECDSA signatures on secp256k1 with constant nonce `k`. When two signatures share the same `r` value, the nonce and private key are recoverable.

**Recovery:**
```python
from hashlib import sha256
from Crypto.Util.number import inverse

# Two signatures (r, s1) and (r, s2) with same r → same nonce k
h1 = int(sha256(msg1).hexdigest(), 16)
h2 = int(sha256(msg2).hexdigest(), 16)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # secp256k1 order

# pow(a, -1, n) is stdlib Python 3.8+; Crypto.Util.number.inverse is fallback
k = ((h1 - h2) * pow(s1 - s2, -1, n)) % n
d = ((s1 * k - h1) * pow(r, -1, n)) % n  # private key
```

**Key insight:** Same `r` value across multiple ECDSA signatures means the nonce `k` was reused. This is the same class of bug that compromised the PlayStation 3 signing key. Always check for repeated `r` values in signature datasets.

**Detection:** Multiple ECDSA signatures with identical `r` component. Challenge mentions "nonce", "deterministic signing", or provides a signing oracle.

---

## DSA Nonce Reuse for Private Key Recovery (VolgaCTF 2016)

**Pattern:** Two DSA (Digital Signature Algorithm) signatures sharing the same nonce k (same r value) leak the private key. Identical in principle to ECDSA nonce reuse but uses DSA-specific group parameters.

```python
from Crypto.Util.number import inverse

# Two signatures (r, s1, H(m1)) and (r, s2, H(m2)) with same r
# pow(..., -1, q) is stdlib; Crypto.Util.number.inverse is fallback
k = ((H_m1 - H_m2) * pow(s1 - s2, -1, q)) % q
x = ((s1 * k - H_m1) * pow(r, -1, q)) % q  # private key
# Then forge signatures for arbitrary messages
```

**Key insight:** DSA nonce reuse is identical in principle to ECDSA nonce reuse. Look for repeated r values in any DSA/ECDSA signature set. The same recovery formula applies to both.

---

## DSA Limited k-Value Brute Force (ASIS CTF Finals 2016)

DSA implementation generates k from a restricted space (e.g., only 1024 possibilities). Given multiple signatures, brute-force k values and solve for the private key.

```python
from Crypto.Util.number import inverse

def recover_dsa_key(signatures, q, g, p):
    """Recover DSA private key when k has limited possible values"""
    (r1, s1, h1), (r2, s2, h2) = signatures[0], signatures[1]

    # From DSA: s = k^-1 * (h + x*r) mod q, so x*r = k*s - h and
    # x = (k*s - h) * r^-1 mod q -- per signature, no linear system needed.
    for k1 in range(1, 1024):
        # Verify: r1 == (g^k1 mod p) mod q -- only depends on k1, so hoist it
        # out of the inner loop instead of re-running a modexp per (k1, k2).
        if pow(g, k1, p) % q != r1:
            continue
        x = ((k1 * s1 - h1) * pow(r1, -1, q)) % q  # stdlib pow; inverse() fallback
        # Confirm against the second signature before returning
        k2 = (h2 + x * r2) * pow(s2, -1, q) % q
        if pow(g, k2, p) % q == r2:
            return x
    return None
```

**Key insight:** Standard DSA nonce reuse attacks require `k1 == k2`. When k values are drawn from a small space, you do not need a 2×2 linear system: cross-multiplying the two instances of `x = (k*s - h)*r^-1` only gives the *consistency* condition `(k1*s1 - h1)*r2 == (k2*s2 - h2)*r1`. Each `k1` that satisfies `r1 == (g^k1 mod p) mod q` already pins `x` directly, so brute-force `k1` alone (1024 modexps), not all `(k1,k2)` pairs (2^20 modexps).

---

## ECC Shared Prime Factor via GCD (ASIS CTF Finals 2016)

Multiple ECC public keys generated with a flawed prime generator that filters `prime % 3 == 2`, reducing the keyspace enough for shared factors to appear.

```python
from math import gcd
from Crypto.Util.number import inverse

# Collect moduli from multiple ECC public keys
moduli = [key.n for key in public_keys]

# Find shared factors via pairwise GCD
for i in range(len(moduli)):
    for j in range(i + 1, len(moduli)):
        g = gcd(moduli[i], moduli[j])
        if 1 < g < moduli[i]:
            p = g
            q = moduli[i] // p
            print(f"Key {i} factored: p={p}, q={q}")
            # Now decrypt using recovered factors
```

**Key insight:** When a prime generator excludes primes based on modular conditions (e.g., `p % 3 == 2`), the reduced keyspace makes GCD collisions between independently generated keys much more likely. Always try pairwise GCD across multiple public keys.

---

## DSA Key Recovery via MD5 Collision on k-Generation (CONFidence CTF 2017)

**Pattern:** When DSA nonce `k` is derived from `MD5(prefix + counter)`, generate MD5 prefix collisions to force two different counter values to produce the same `k`, enabling the standard nonce-reuse private key recovery.

```python
# k = int(MD5("K = {n: " + str(counter) + ...))
# Use fastcoll to find MD5 collision on prefix "K = {n: "
# Two different counter values -> same MD5 -> same k -> nonce reuse

import subprocess
# Generate collision pair
subprocess.run(["fastcoll", "-p", prefix_file, "-o", "col1", "col2"])

# Get two signatures with same k (same r value)
sig1 = sign(msg1, counter1)  # uses MD5(prefix + counter1)
sig2 = sign(msg2, counter2)  # uses MD5(prefix + counter2) = same hash!

from Crypto.Util.number import inverse

# Standard DSA nonce reuse recovery (stdlib pow or Crypto.Util.number.inverse)
k = (hash1 - hash2) * pow(sig1.s - sig2.s, -1, q) % q
private_key = (sig1.s * k - hash1) * pow(sig1.r, -1, q) % q
```

**Key insight:** MD5 collision generators like `fastcoll` produce pairs of inputs with identical hashes from a chosen prefix. When a signature scheme derives its nonce from an MD5 hash of controllable data, manufacturing a collision produces nonce reuse, enabling standard private key recovery.

**References:** CONFidence CTF 2017

---

## Ed25519 Same-Nonce Key Recovery (hxp 2018)

**Pattern:** An Ed25519 signer reuses the same private-key scalar with deterministic nonce derivation, but the public key changes between signatures (fault injection or swapped key material). Two signatures `(R1, S1, h1)` and `(R2, S2, h2)` share `a`, so `a = (S1 - S2) * inverse(h1 - h2) mod L`.

```python
from Crypto.Util.number import inverse

L = 2**252 + 27742317777372353535851937790883648493
# pow(..., -1, L) is stdlib; Crypto.Util.number.inverse is fallback
a = (S1 - S2) * pow(h1 - h2, -1, L) % L   # recovered scalar
```

**Key insight:** Ed25519 is deterministic, but any implementation bug that desyncs `(r, k)` from `(H(privkey, msg))` produces classical nonce-reuse. Check implementations that sign across key rotations -- the scalar often survives rekey.

**References:** hxp CTF 2018 -- writeup 12561

---

## Singular Curve ECDLP to Additive/Multiplicative Group (hxp 2018)

**Pattern:** Challenge publishes an "elliptic curve" that is actually singular -- its discriminant is zero. Compute the singularity by finding the double root of `f(x) = x^3 + ax + b`. Map the curve to either the additive group `(GF(p), +)` (cusp) or the multiplicative group `GF(p)^*` (node) where DLP is easy.

```python
# Find singular point r
P.<x> = PolynomialRing(GF(p))
f = x^3 + a*x + b
r = (f.derivative()).roots()[0][0]
# Shift curve so singularity is at origin
# Then map (x, y) -> (x - r) / y  for nodal singularity
```

**Key insight:** Discriminant `-16(4a^3 + 27b^2)` zero means singular. Singular curves are either cusps (map to `(GF(p), +)`) or nodes (map to `GF(p)^*`) -- both with polynomial-time DLP.

**References:** hxp CTF 2018 -- writeup 12563

---

## X25519 Low-Order Points + All-Zero Check (RFC 7748)

Curve25519 has cofactor 8: group order `8q`. X25519 clamps the scalar (clears low 3 bits, sets high bit) so a small-order peer point always yields the all-zero shared secret regardless of private key. RFC 7748 §6 says implementations MAY reject all-zero `K` (OR all bytes, abort if zero); many do not. CTF pattern: server skips the check, attacker sends low-order `u`, forces predictable `K`.

```python
def x25519_clamped(sk: bytes) -> int:
    assert len(sk) == 32
    b = bytearray(sk)
    b[0] &= 0xF8   # clear low 3 bits -> multiple of cofactor 8
    b[31] &= 0x7F  # clear high bit
    b[31] |= 0x40  # set second-high bit
    return int.from_bytes(bytes(b), "little")

def is_all_zero(shared: bytes) -> bool:
    r = 0
    for byte in shared:
        r |= byte
    return r == 0  # constant-time shape, same as RFC 7748

# Triage: u = 0 and u = 1 are always small-order (orders 4 and 4).
# Full low-order set has 8 points of order dividing 8; enumerate others by
# scanning small u and keeping inputs whose X25519 output is all-zero for
# two independent clamped scalars (Sage: E = EllipticCurve(GF(2^255-19), [0,486662,0,1,0])).
LOW_ORDER_PROBES = (0, 1)
```

**Workflow:** send each probe `u` (LE 32-byte encoding), derive `KDF(K)` candidates for the ≤8 possible outputs (usually just all-zero), match server MAC/ciphertext/success. If server accepts all-zero `K`, key is known with 1-2 queries. If it aborts, the check exists: pivot to twist/invalid-curve on a non-Montgomery path instead.

**References:** RFC 7748 §6-7; Kleppmann curve25519 notes (cofactor/small-subgroup); Valenta et al. ePrint 2016/995 (measuring small-subgroup DH).
