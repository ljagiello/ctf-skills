# Binary-GCD Transcript → Operand Recovery (masked-ECDSA mask cancellation)

## When this applies

- A signing oracle (ECDSA/DSA/Schnorr) exposes a **per-operation side-channel transcript** of the binary-GCD inside its modular inverse/division — e.g. a `track`/debug mode that emits the ordered `half` / `sub` / `add` symbols of `div(a, b, n)` computing `s = a·b⁻¹ mod n`, or a timing/branch trace of Stein's algorithm.
- The signer "masks" the nonce **multiplicatively**: a random `nonce_mask` is folded into BOTH operands, e.g. `denominator = nonce_mask·k`, `numerator = nonce_mask·(h + r·d)`. (Marketed as "projective"/"masked" signatures; Ledger-Donjon class.)
- Trigger keywords: "masked ECDSA", "projective signature", "constant-time inversion trace", `half`/`sub` symbols, a `track` argument naming the inversion routine.

This is **distinct from HNP/Minerva** (which needs a nonce bit-length/MSB bias and a lattice). Here there is no bias and no lattice — recovery is exact integer arithmetic from one signature.

## Technique

1. The ordered binary-GCD symbol stream of ONE `div(num, den, n)` call **determines the operand `den`** — reconstruct it via the procedure in *"Reconstructing the operands from the transcript"* below (resolve per-round direction with the reverse-replay / cofactor-lookahead, then solve the affine system). When both operands are unreduced you likewise recover `num`.
2. If both operands are the **unreduced products** `den = nonce_mask·k` and `num = nonce_mask·(h + r·d)`, then
   `g = gcd(num, den) = nonce_mask · gcd(h+r·d, k) = nonce_mask · e`, where `e` is small (usually 1–4).
3. Recover the nonce: `base_k = den/g`, `base_term = num/g`; for small `e` (search to ~1e5): `k = base_k·e`, `d = (base_term·e − h)·r⁻¹ mod n`; accept when `(h + r·d)·k⁻¹ mod n == s` and `d·G == public_key`. **One signature**, no lattice.

### Variant: only `den = mask·k` is leaked (numerator reduced) — factor + verify via `r`
When `div` reduces the numerator (so the `gcd(num,den)` trick is dead, below), recover `k` from `den = mask·k` alone (Ledger-Donjon / IACR ePrint **2020/055**, the mbedTLS gcd-countermeasure bypass): **factor `den`, enumerate divisors `δ < n`, and test each against the PUBLIC `r`: the true nonce satisfies `x(δ·G) mod n == r`.** No cross-signature, no lattice, no unreduced numerator needed — one signature suffices. Then `d = (s·k − h)·r⁻¹ mod n`. Cost = factoring `den` (a ~`2·log₂n`-bit product of two uniform factors): request many signatures and factor the smoothest `den` (ECM for factors ≲2⁹⁰, NFS otherwise).

## Reconstructing the operands from the transcript

The transcript collapses each GCD round to a halving count `htot_i` with an `ss` round delimiter. Two facts simplify the reverse:

- **No cu/cv split (R1).** Each round halves *exactly one* operand: after a same-parity subtraction of two odd numbers, exactly one operand becomes even, the other stays odd. So `htot_i` is entirely `cu_i` *or* entirely `cv_i` — there is **no split ambiguity**. The operand is determined by `v`'s parity (track `v`/its affine form). (Verify: 0/200 rounds halve both.)
- **`reverse_replay` is exact given the full `(cu,cv,dir)` per round** (linear forms in the single terminal unknown, anchored by `v_start == n`): 200/200. So the *entire* reconstruction problem reduces to recovering the **`dir` (subtraction-direction `u≥v`) bit per round** — nothing else is missing.

### The working forward reconstructor (affine 2-adic, GIVEN dir)
Track `u,v` as affine forms `c + k·Yhi` where `Yhi` is `den`'s unpinned high part; pin `den`'s bits LSB-first.
- `halve` gates readability on `v₂(coefficient)` (NOT a global pinned-bit count): commit `den` bits until the operand's low bits are `Yhi`-independent, forcing each committed bit to zero the trailing-zero positions.
- At the end solve `Yhi` from the terminal equation `u==1` or `v==1` (`(1−uc)/uk`). This reconstructs `den` **50/50 with oracle dir**.
- **CRITICAL BUG to avoid:** do the interval/halving bookkeeping in **exact integer arithmetic**. `math.ceil((ylo-b)/2)` / `math.floor(...)` on 256-bit ints silently lose precision (float mantissa is 53 bits) and corrupt the interval after ~200 rounds — this silently breaks the whole reconstructor (a prior session's "validated" forward reconstructor failed live for exactly this reason). Use `-((-(p))//q)` for ceil, `p//q` for floor.
- **Validate on a small modulus first** (500/500), then at full bit-length against a known-nonce harness with **exact-int** arithmetic, BEFORE trusting any live capture.

### How `dir` IS resolved from the symbolic trace (SOLVED — earlier "blocked" was WRONG)
The subtraction-direction `dir` per round **is fully recoverable** from the symbolic `{div,half,add,sub}` trace alone. Two independent methods, both validated to ~100% on a known-nonce harness AND end-to-end on the live HTB "Surprise Factor" oracle:

- **Forward, 1-round cofactor-parity lookahead.** At a `dir`-ambiguous round, fork `{u,v}`; for each fork apply the subtraction and *predict the NEXT round's observable* — operand identity, `htot`, and cofactor-parity (`a`-path) bits — using the invariant `x1 ≡ s·u`, `x2 ≡ s·v (mod n)` (`s` known). Accept the fork whose prediction matches the observed next round; **exactly one survives (10935/10935 ambiguous rounds).** The forced phase (`u ≫ v`, ~`124` of ~`320` rounds) needs no lookahead — `dir='u'` is deterministic.
- **Reverse replay (cleaner; the `x2=0` razor).** KEY FACT (F2): the cofactor recursion `(x1,x2)` depends ONLY on the `(op, dir, parity)` sequence — **never on the `u,v` magnitudes** — so replay it independently of den's bits. Walk the GCD BACKWARD from the terminal state (winner `==1`, small even loser, cofactor `≡ s mod n`), undoing each subtraction (`u+=v,x1+=x2` / `v+=u,x2+=x1`) and halving (`x*=2` / `x=2x−n`). The anchor `x2_start == 0` exactly (plus `|x1|,|x2| < ~4n`) is razor-sharp → exactly one `dir` path survives, `den = u_start`. ~18–20/20 sigs, median <0.3s, **no false positives** (returns `None` or the correct `den`; self-checks `trace_div(num,den,n)==seg`).

Why the prior "75/75 undetected / blocked" claim was WRONG: it used a *shallow* cofactor tracker committing `x1`'s low bits as free unknowns. Fix = either predict the cofactor via the `x1≡s·u` invariant (1-round lookahead), or replay the cofactor recursion independently (F2) anchored by `x2=0`. A power trace is NOT required.

## Verifying success

- Recovered `d` satisfies `d·G == public_key` (check locally with the challenge's own EC code).
- The oracle's `submit{d}` (or equivalent) returns the flag. Never submit a `d` you have not locally verified against `public_key`.

## Common pitfalls / preconditions

- **The `gcd(num,den)` mask-cancellation (step 1–3) needs BOTH operands UNREDUCED.** Many `div(a, b, n)` run `a = a mod n` *before* the Euclidean loop, so the transcript leaks only `den = nonce_mask·k` and `num mod n` (`= s·den mod n`, already public) — the `gcd` trick is dead. **This does NOT block recovery** — use the *factor-and-verify-via-`r`* variant above. Recovering `k` from `den` alone is NOT "factoring two large primes": `den = nonce_mask·k` is a product of two uniform ~256-bit **composites**, so `Ω(den)` (prime-factor count w/ multiplicity) has median ~9 (`<14` w.p. 99.4%) → only ~`2⁹–2¹³` divisors, and the largest prime factor is usually ECM-reachable. **Sample-select across many signatures and factor the smoothest `den`** (escalating GMP-ECM `B1 ∈ {2e3..1.1e7}`; skip ones that don't finish in a small budget). Live result: 60 sigs, **first 10s/den pass solved it** (Ω(den)=11). The earlier "infeasible" verdict was WRONG — this is the *intended* path (CVE-2019-18222 / IACR 2020/055: "reduces ECDSA to integer factorization"). Enumerate divisors `δ` with `den/n < δ < n` and `den/δ < n`, test `x(δ·G) mod n == r`.
- A signing call often runs the inversion **twice** (e.g. `inv(z mod P, P)` for the affine Z-coordinate plus the target `div(.,.,n)` for `s`). Track only the modulus-`n` division; identify it by its round count (or by `inv` vs `div` symbols if the API distinguishes them).
- **Symbolic call-traces vs power traces — still fully sufficient.** A function-call-sequence oracle (you choose which functions to log) emits identical symbols for both subtraction directions (`u≥v` vs `u<v`) and for `u`/`v` halvings, so `dir`/operand are not *directly* in the symbol names. This is NOT a blocker: track `{div,half,add,sub}`, include `add` so the cofactor `a`-path (parity bits) is visible, and resolve `dir` via the reverse-replay (`x2=0` anchor) or 1-round lookahead above. The early-round anchor (`v=n` odd, `x2=0` → no `x2` add-markers) plus the magnitude-independent cofactor recursion make it deterministic. A power trace is a convenience, not a requirement.
- **Projective-coordinate variant (Donjon "Projective Signatures").** A related leak recovers the ladder's affine-conversion `Z` and walks nonce bits via 4th/cube-root existence → HNP. It is defeated if the signer **re-randomizes the point's coordinates *after* `scalar_mul`** (and/or randomizes the base point) — then the recovered `Z` carries unknown masks and root-existence is no longer invariant. If you see a post-multiply coordinate randomization, pivot to the `den`-factoring variant above.

## See also
- [ecdsa-nonce-reuse.md](ecdsa-nonce-reuse.md) — the simpler shared-`r` recovery.
- [lll-basis-reduction.md](../lattice/lll-basis-reduction.md) — the HNP/Minerva path when the leak is a nonce-bit bias instead.

## Anti-Patterns

- Validating a recovery PoC against a harness that **hand-feeds an operand the real routine reduces away** (e.g. `rec_num = num  # placeholder`). It yields a false "proven 2000/2000" that collapses on live data. Reconstruct every operand from the actual leak end-to-end before claiming the attack works.
