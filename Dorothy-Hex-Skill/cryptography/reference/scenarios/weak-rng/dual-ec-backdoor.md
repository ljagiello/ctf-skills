# Dual_EC_DRBG Backdoor

## When this applies

- Code uses Dual_EC_DRBG (NIST SP 800-90A, withdrawn) for random number generation — typically in old RSA BSAFE, Juniper ScreenOS, or hand-rolled crypto referencing two NIST P-256 points `P` and `Q`.
- You suspect (or know) the backdoor: an attacker who knows `e` such that `Q = e·P` can predict all future outputs from a few consecutive output blocks.
- Trigger keywords: "Dual_EC", "DRBG", "P-256 with second point", "Juniper", "backdoor".

## Technique

Dual_EC_DRBG generates output by computing `r = x(s·P)`, output = `low30bytes(x(r·Q))`, then `s = x(r·P)`. If `e` is known, an observer with one full output block can compute `s_next` directly:

```
output_lo = low30(x(r·Q))           # observed (after stripping high 16 bits)
candidate r·Q = (output, y) with output = high16(?) || output_lo
since Q = e·P, we have r·Q = e·(r·P) = e·s_next
so s_next = e^{-1} · r·Q
```

The attack: brute-force the 16 missing high-order bits, recover `r·Q` candidates, multiply by `e^{-1}` to get `s_next` candidates, predict next output, match against observed.

## Steps

### 1. Confirm Dual_EC usage

Look for:
- Two hardcoded P-256 points in the binary or source.
- Output rate of 30 bytes per call (240 bits, instead of full 256).
- Reference to NIST SP 800-90A in comments / docs.

### 2. Recover or estimate `e`

The **historical** backdoor (Snowden documents): NSA selected `Q` such that `e` was known to them. For CTF-style challenges, `e` is given (the puzzle reveals it) or has to be inferred from a leaked test vector.

If `e` is hardcoded as a constant in the binary, just extract it.

### 3. Predict next output

```python
from ecpy.curves import Curve  # or pycryptodome elliptic
P256 = Curve.get_curve('P-256')

def x_to_point(x_lo, x_hi):
    x = (x_hi << 240) | x_lo
    # compute y from curve eq
    return P256.lift(x)

obs_block = ...  # 30 bytes from output

for x_hi in range(1 << 16):
    try:
        rQ = x_to_point(int.from_bytes(obs_block, 'big'), x_hi)
    except ValueError:
        continue
    s_next_pt = e_inv * rQ
    s_next = s_next_pt.x
    # compute predicted next output
    r = (s_next * P).x
    pred = low30(((r * Q).x))
    if pred == next_obs_block:
        print("Hit:", s_next)
        break
```

### 4. Roll forward

Once `s_next` is recovered, all subsequent outputs follow deterministically.

## Verifying success

- Predicted block matches a held-out observed output.
- Subsequent prediction also matches.
- For TLS Juniper-style: recovered RNG state lets you re-derive premaster / session keys.

## Common pitfalls

- **30-byte vs 32-byte output.** Dual_EC outputs only the low 240 bits of `x(r·Q)`. Forgetting this drops you into the wrong x-coordinate.
- **Wrong curve.** Original spec uses P-256; Juniper used the same. Hand-rolled implementations may use other curves — confirm.
- **`e` inversion mod curve order.** `e^{-1}` is mod `n` (curve order), not mod `p` (field).
- **Re-seeding.** Some implementations reseed every `M` blocks; your predicted state expires at reseed.

## Tools

- `pycryptodome` for P-256 arithmetic.
- `ecpy` (pure Python) for cleaner Curve API.
- Reference: Shumow & Ferguson 2007, "On the Possibility of a Back Door in the NIST SP800-90 Dual EC PRNG" — public attack paper from CRYPTO rump session.
- Real-world: Juniper's 2015 backdoor disclosure — public IoCs and patches.
