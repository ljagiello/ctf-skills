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
from ecdsa.ellipticcurve import CurveFp, Point
import random

def is_smooth(n, bound=1_000_000):
    """True if all prime factors of n <= bound."""
    try:
        return max(factorint(n).keys()) <= bound
    except ValueError:  # n==1
        return True

def point_of_order(E, N, r):
    """Return random point of exact order r on curve E (curve order N, r|N)."""
    # E: ecdsa CurveFp object; need point sampling via brute x
    p = E.p()
    a = E.a()
    b = E.b()
    while True:
        x = random.randrange(p)
        rhs = (pow(x, 3, p) + a * x + b) % p
        # Tonelli-Shanks via pow if p %4==3 else generic; use simple Legendre
        if pow(rhs, (p - 1) // 2, p) != 1:
            continue
        y = pow(rhs, (p + 1) // 4, p) if p % 4 == 3 else None
        if y is None:
            continue  # skip generic case for brevity; use Sage for p%4!=3
        for yy in (y, p - y):
            try:
                P = Point(E, x, yy, order=None)
            except Exception:
                continue
            Q = P * (N // r)  # cofactor projection N/r * random point
            if Q != Point(E, None, None, order=None) and (Q * r) == Point(E, None, None, order=None):
                # verify exact order r (check no smaller divisor)
                is_exact = True
                for pr in factorint(r):
                    if (Q * (r // pr)) == Point(E, None, None, order=None):
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
    x, M = crt(moduli, residues)
    return int(x % M)

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
from Crypto.Util.number import inverse
# pow(..., -1, mod) exists Python 3.8+; Crypto.Util.number.inverse is fallback when not coprime or older runtime

def lift_point(x, y, p, a, b):
    # lift (x,y) on y^2 = x^3 + a*x + b from mod p to mod p^2 via Hensel: y' = y - (y^2 - rhs)/(2y) mod p
    mod = p*p
    rhs = (pow(x,3,mod) + a*x + b) % mod
    try:
        inv2y = pow(2*y % p, -1, p)  # inverse mod p, then lift: could also use pow(2*y % mod, -1, mod) if gcd=1
    except ValueError:
        inv2y = inverse(2*y % p, p)  # fallback via Crypto.Util.number.inverse
    # Newton step: dy = (y*y - rhs)/p * inv(2y) mod p, then yc = y - dy*p
    # (y*y - rhs) is divisible by p because y^2 == rhs (mod p); integer divide before mod
    dy = ((y*y - rhs) // p) * inv2y % p
    yc = (y - dy * p) % mod  # single lift, two roots are yc and mod-yc (i.e. yc and (-yc % mod))
    # return both candidates or choose one; Satoh-Skjernaa-Taguchi uses lifted points pG,pQ
    return (x % mod, yc)

def smart_attack(p, a, b, G, Q):
    # G, Q as (x,y) tuples over GF(p); p odd prime, anomalous => order == p
    # Note: for toy p<1e4 both brute `for dy in range(p): yc=y+dy*p` and Newton work, but Newton is O(1)
    mod = p * p

    def ec_add(P, Q_, mod_):
        if P is None:
            return Q_
        if Q_ is None:
            return P
        x1, y1 = P; x2, y2 = Q_
        if x1 == x2 and (y1 + y2) % mod_ == 0:
            return None
        if P == Q_:
            try:
                inv = pow(2*y1 % mod_, -1, mod_)
            except ValueError:
                inv = inverse(2*y1 % mod_, mod_)
            lam = (3*x1*x1 + a) * inv % mod_
        else:
            try:
                inv = pow((x2 - x1) % mod_, -1, mod_)
            except ValueError:
                inv = inverse((x2 - x1) % mod_, mod_)
            lam = (y2 - y1) * inv % mod_
        x3 = (lam*lam - x1 - x2) % mod_
        y3 = (lam*(x1 - x3) - y1) % mod_
        return (x3, y3)

    def ec_mul(P_, k, mod_):
        R = None; Q__ = P_
        while k:
            if k & 1:
                R = ec_add(R, Q__, mod_)
            Q__ = ec_add(Q__, Q__, mod_)
            k >>= 1
        return R

    def psi(Pt, mod_):
        try:
            inv = pow(Pt[1] % mod_, -1, mod_)
        except ValueError:
            inv = inverse(Pt[1] % mod_, mod_)
        return (-Pt[0] * inv) % mod_

    # Hensel lift G, Q to mod p^2 -- O(1) Newton step (not brute O(p))
    gx, gy = G
    qx, qy = Q
    gx_lift, gy_lift = lift_point(gx, gy, p, a, b)
    qx_lift, qy_lift = lift_point(qx, qy, p, a, b)
    # two y-roots per x: yc and mod-yc (negation); try both signs
    candidates_G = [(gx_lift, gy_lift), (gx_lift, (-gy_lift) % mod)]
    candidates_Q = [(qx_lift, qy_lift), (qx_lift, (-qy_lift) % mod)]

    for g_lift in candidates_G:
        for q_lift in candidates_Q:
            try:
                pG = ec_mul(g_lift, p, mod)
                pQ = ec_mul(q_lift, p, mod)
                # Standard p-torsion test: p*P in kernel iff pP is None (identity) or y % p == 0
                # Bug was `if y%p==0: continue` (skipped torsion); correct is to require torsion
                if pG is None or pQ is None:
                    continue
                if pG[1] % p != 0 or pQ[1] % p != 0:
                    # not in kernel of reduction -> wrong lift sign, try other
                    continue
                psi_G = psi(pG, mod)
                psi_Q = psi(pQ, mod)
                # Satoh-Skjernaa-Taguchi: psi(pP) divisible by p; integer-divide after confirming
                if psi_G % p != 0 or psi_Q % p != 0:
                    continue
                val_G = (psi_G // p) % p
                val_Q = (psi_Q // p) % p
                if val_G == 0:
                    continue
                try:
                    inv_val = pow(val_G, -1, p)
                except ValueError:
                    inv_val = inverse(val_G, p)
                secret = (val_Q * inv_val) % p

                def verify(k):
                    return ec_mul(G, k, p) == Q

                if verify(secret):
                    return secret
                # sign flip can give p-secret if we chose opposite y-root
                if verify((-secret) % p):
                    return (-secret) % p
            except Exception:
                continue
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
    # k = ord_r(p); return k if <=kmax else None
    if r == 1:
        return None
    cur = p % r
    for k in range(1, kmax+1):
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
# For each key bit position:
# If fault at bit i changes output -> key bit i affects computation
# Binary distinguisher: faulty_output == correct_output -> bit is 0
```

---

## Clock Group DLP via Pohlig-Hellman (LACTF 2026)

**Pattern (the-clock):** Diffie-Hellman on unit circle group: x^2 + y^2 = 1 (mod p).

**Key facts:**
- Group law: (x1,y1) * (x2,y2) = (x1*y2 + y1*x2, y1*y2 - x1*x2)
- **Group order = p + 1** (not p - 1!)
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

**Identification:** Challenge mentions "clock", "circle", or gives points satisfying x^2+y^2=1. Always check if p+1 (not p-1) is smooth.

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

# Two signatures (r, s1) and (r, s2) with same r → same nonce k
h1 = int(sha256(msg1).hexdigest(), 16)
h2 = int(sha256(msg2).hexdigest(), 16)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # secp256k1 order

k = ((h1 - h2) * pow(s1 - s2, -1, n)) % n
d = ((s1 * k - h1) * pow(r, -1, n)) % n  # private key
```

**Key insight:** Same `r` value across multiple ECDSA signatures means the nonce `k` was reused. This is the same class of bug that compromised the PlayStation 3 signing key. Always check for repeated `r` values in signature datasets.

**Detection:** Multiple ECDSA signatures with identical `r` component. Challenge mentions "nonce", "deterministic signing", or provides a signing oracle.

---

## DSA Nonce Reuse for Private Key Recovery (VolgaCTF 2016)

**Pattern:** Two DSA (Digital Signature Algorithm) signatures sharing the same nonce k (same r value) leak the private key. Identical in principle to ECDSA nonce reuse but uses DSA-specific group parameters.

```python
# Two signatures (r, s1, H(m1)) and (r, s2, H(m2)) with same r
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

    for k1 in range(1, 1024):
        for k2 in range(1, 1024):
            # From DSA: s = k^-1 * (h + x*r) mod q
            # With two signatures: x = (s2*k2*h1 - s1*k1*h2) / (s1*k1*r2 - s2*k2*r1) mod q
            num = (s2 * k2 * h1 - s1 * k1 * h2) % q
            den = (s1 * k1 * r2 - s2 * k2 * r1) % q
            if den == 0:
                continue
            x = (num * inverse(den, q)) % q
            # Verify: check if r1 == (g^k1 mod p) mod q
            if pow(g, k1, p) % q == r1:
                return x
    return None
```

**Key insight:** Standard DSA nonce reuse attacks require k1 == k2. When k values are drawn from a small space (e.g., 1024 values), brute-force all (k1, k2) pairs across two signatures to solve the linear system for private key x.

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

# Standard DSA nonce reuse recovery
k = (hash1 - hash2) * modinv(sig1.s - sig2.s, q) % q
private_key = (sig1.s * k - hash1) * modinv(sig1.r, q) % q
```

**Key insight:** MD5 collision generators like `fastcoll` produce pairs of inputs with identical hashes from a chosen prefix. When a signature scheme derives its nonce from an MD5 hash of controllable data, manufacturing a collision produces nonce reuse, enabling standard private key recovery.

**References:** CONFidence CTF 2017

---

## Ed25519 Same-Nonce Key Recovery (hxp 2018)

**Pattern:** An Ed25519 signer reuses the same private-key scalar with deterministic nonce derivation, but the public key changes between signatures (fault injection or swapped key material). Two signatures `(R1, S1, h1)` and `(R2, S2, h2)` share `a`, so `a = (S1 - S2) * inverse(h1 - h2) mod L`.

```python
L = 2**252 + 27742317777372353535851937790883648493
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
