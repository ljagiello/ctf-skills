# Bleichenbacher PKCS#1 v1.5 Padding Oracle (Million Message Attack)

## When this applies

- A server decrypts RSA ciphertexts using **PKCS#1 v1.5 padding** and reveals (via different responses) whether the decrypted plaintext starts with `\x00\x02` (the PKCS#1 v1.5 leading bytes for an encryption block).
- The signal can be: response code, error message, response time, TLS alert difference (classic ROBOT attack), or any side channel.
- Trigger keywords: "PKCS1.5", "RSA decryption", "ROBOT", "Bleichenbacher", "BB98".

## Technique

Bleichenbacher 1998: given an oracle `O(c)` that returns whether `c^d mod n` starts with `0x0002`, recover the plaintext `m = c^d mod n` of any target ciphertext `c0`. The oracle is multiplicative (RSA homomorphism): `O(c0 * s^e mod n)` answers about `m * s mod n`.

The attack iteratively narrows an interval `[a, b]` containing `m` by finding multipliers `s` for which the modified ciphertext is also "PKCS#1 conforming". After each successful query, the interval halves.

## Steps

### 1. Confirm oracle

Submit a random ciphertext, then submit an obviously-conforming one (encrypt a fresh PKCS#1 padded plaintext under the public key). Oracle should distinguish. Measure timing if no obvious signal.

### 2. Run Bleichenbacher (publicly available implementations)

This attack is non-trivial to implement correctly — use a vetted tool unless you have weeks. Public implementations:

- `tls-attacker` (Java, includes ROBOT and BB98).
- `bleichenbacher.py` reference implementations on GitHub.
- `rsa-bleichenbacher` Python package.

Inputs the tool needs:
- Public key `(n, e)`.
- Target ciphertext `c0`.
- An oracle callable `O(c) -> bool`.

### 3. Phases of the attack

1. **Blinding.** Find `s0` such that `c0' = c0 * s0^e mod n` is conforming. Often `s0 = 1` works if `c0` is itself a TLS ClientKeyExchange.
2. **Search for first `s1`.** Linearly scan `s1` starting from `n / (3·2^(k-16))` until oracle accepts.
3. **Narrow intervals.** Subsequent `s_i` are derived analytically; intervals halve each iteration.
4. **Single interval.** Once interval is unique, perform a final binary-search-style narrowing.

Total: ~10^6 queries for 1024-bit RSA, ~10^4 for cleverer variants ("Manger" attack on OAEP-broken implementations).

### 4. Verify

The final `m` should encrypt back to `c0`: `pow(m, e, n) == c0`.

## Verifying success

- Recovered plaintext `m` re-encrypts to original ciphertext.
- Plaintext structure matches expected (premaster secret length 48 for TLS, etc.).
- For TLS: subsequent session decryption using recovered premaster works.

## Common pitfalls

- **Implementing from scratch.** The interval arithmetic has signed/edge-case bugs that consume days. Use a proven library.
- **Slow oracle.** ~10^6 queries means even 100ms per query = 28 hours. Parallelize if possible; ROBOT-style timing oracles often allow parallel TLS sessions.
- **Mistaking OAEP for PKCS1.5.** OAEP uses Manger's attack (different math). Read the protocol spec to confirm.
- **Padding leak via timing only.** Measure thousands of samples per query; the difference between conforming and non-conforming is often microseconds.

## Tools

- `tls-attacker` (Java) — for TLS-specific Bleichenbacher / ROBOT.
- `BB98.py` Python implementations on GitHub (search "Bleichenbacher Python").
- `pycryptodome` for RSA arithmetic; oracle wiring is bespoke per target.
