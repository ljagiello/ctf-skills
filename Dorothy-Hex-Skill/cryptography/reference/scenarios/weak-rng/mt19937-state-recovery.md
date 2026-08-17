# MT19937 (Mersenne Twister) State Recovery

## When this applies

- Outputs come from MT19937 (default RNG of Python `random`, glibc `random_r`, PHP `mt_rand`, Ruby `rand`, classic V8 in older Node, MATLAB).
- You can observe **624 consecutive 32-bit outputs** (or somewhat fewer with bit-tricks).
- Trigger keywords: "Mersenne Twister", `random.randint`, `np.random` (older default), `mt_rand`.
- Outputs may be 32-bit integers, hex strings, or large integers split across multiple outputs.

## Technique

MT19937's output transform `temper(state[i])` is bijective and invertible bit-by-bit. Given 624 consecutive outputs, invert each through `untemper` to recover the 624-word internal state. Reseed an MT19937 instance with that state and predict all future (and past) values.

## Steps

### 1. Collect 624 consecutive outputs

The outputs must come from contiguous calls to the same RNG instance with no skipped values. If the service exposes a "give me a random number" endpoint, call it 624 times.

If outputs are larger than 32 bits (e.g. `random.getrandbits(64)`), each call consumes 2 internal words — you need 312 such outputs.

### 2. Untemper and rebuild state

Use `randcrack`:

```python
# pip install randcrack
from randcrack import RandCrack
rc = RandCrack()
for v in outputs_32bit:
    rc.submit(v)            # must be exactly 624 values
predicted = rc.predict_randint(0, 100)
```

Alternative — pure-Python untemper:

```python
def untemper(y):
    y ^= (y >> 18)
    y ^= (y << 15) & 0xefc60000
    # un-shift-left-and-mask 0x9d2c5680, 7 bits
    a = y; res = 0
    for i in range(0, 32, 7):
        part = ((res << 7) & 0x9d2c5680) ^ a
        a = part & ((1 << (i + 7)) - 1)
        res = (res & ~((1 << (i + 7)) - 1)) | a
    y = res
    # un-shift-right 11
    z = 0
    for i in range(32):
        if i < 11:
            bit = (y >> (31 - i)) & 1
        else:
            bit = ((y >> (31 - i)) ^ (z >> (31 - i + 11))) & 1
        z |= bit << (31 - i)
    return z
```

(Verify against a known input — every line is a sign error away from being wrong.)

### 3. Reseed Python `random`

```python
import random
state = (3, tuple(untempered + [624]), None)
random.setstate(state)
random.getrandbits(32)  # = next output
```

### 4. Predict / rewind

You can predict forward arbitrarily. Rewinding is also possible: there's an inverse permutation `untwist` that given the current state computes the previous one.

## Verifying success

- The first prediction matches the next observed output exactly.
- A few subsequent predictions also match — confirms state, not luck.
- For RNG-derived keys: derive and decrypt a known ciphertext.

## Common pitfalls

- **Off-by-one on output count.** MT19937 mixes after each 624-call cycle. If you collect during a "twist" boundary, the state derived may be one cycle off — collect a few extra and verify.
- **Output narrowing.** Functions like `randint(0, 100)` discard bits; you can't directly untemper. Use `getrandbits(32)` if available, or a separate scenario that doesn't fully consume.
- **Multiple RNG instances.** Web servers may use a per-request RNG seeded from `os.urandom` — un-trackable. Confirm a single global instance.
- **Java `SecureRandom`.** Despite being a Java class, this is **not** MT19937 — it uses SHA1PRNG or NativePRNG (CSPRNG). Won't yield to this attack.

## Tools

- `randcrack` (Python, pip) — drop-in for MT19937 state recovery.
- `mersenne-twister-predictor` (Python) — same idea, slightly older API.
- For PHP `mt_rand`: `php_mt_seed` recovers seed from a few outputs.
- For 32-bit Java `Random`: see `lcg-state-recovery.md` (it's a 48-bit LCG).
