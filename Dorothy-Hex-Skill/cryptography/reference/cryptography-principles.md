# Cryptography Principles

Entry point for cryptography scenarios. Use `INDEX.md` to pick a scenario by trigger; this file holds the decision tree and cross-cutting guidance.

## Decision tree

Read source first (when accessible). The structure of the cryptosystem points directly to the right attack. Match the most specific fingerprint:

| Fingerprint | Scenario family | First read |
|---|---|---|
| RSA `e=3` and small plaintext, or same plaintext to multiple recipients | `scenarios/rsa-quirks/low-public-exponent.md` | Cube root / Hastad CRT |
| Same plaintext, same `n`, two `e` | `scenarios/rsa-quirks/common-modulus.md` | Bezout combine |
| `e` close to `n` (large e, suspect small d) | `scenarios/rsa-quirks/wiener-attack.md` | Continued fractions |
| `d` slightly above Wiener bound (`< n^0.292`) | `scenarios/lattice/boneh-durfee-low-d.md` | Bivariate Coppersmith |
| Primes look "close" (factor diff < `n^0.25`) | `scenarios/rsa-quirks/fermat-close-primes.md` | Fermat iteration |
| Many published moduli, suspect shared primes | `scenarios/rsa-quirks/small-prime-factorization.md` | Batch GCD |
| Modulus has small factor or known structure (Infineon/Roca) | `scenarios/rsa-quirks/small-prime-factorization.md` | factordb / ECM / Roca |
| Multiple `p_i = a_i·r + b_i` published | `scenarios/lattice/agcd-attack.md` | AGCD lattice |
| Partial known bits of plaintext or prime | `scenarios/lattice/coppersmith-known-bits.md` | small_roots |
| Custom hash / cipher built from XOR + permute + table | (cross-link `linear-secret-recovery.md`) | GF(2) affine recovery |
| CBC + distinguishable padding error | `scenarios/padding-oracle/cbc-padding-oracle.md` | Vaudenay byte-by-byte |
| RSA-PKCS#1 v1.5 decrypt + valid/invalid signal | `scenarios/padding-oracle/pkcs1-v1.5-bleichenbacher.md` | BB98 / ROBOT |
| ECB + chosen-prefix oracle | `scenarios/padding-oracle/ecb-prefix-oracle.md` | Byte-at-a-time |
| Java/PHP/glibc `rand()` outputs visible | `scenarios/weak-rng/lcg-state-recovery.md` | LCG state recovery |
| Python/PHP MT19937 outputs visible | `scenarios/weak-rng/mt19937-state-recovery.md` | randcrack untemper |
| Two NIST P-256 points + 30-byte outputs | `scenarios/weak-rng/dual-ec-backdoor.md` | Backdoor predict |
| Two ECDSA sigs share `r` | `scenarios/signature-forgery/ecdsa-nonce-reuse.md` | k recovery, then d |
| RSA sig verifier with `e=3` and loose padding | `scenarios/signature-forgery/rsa-pkcs1-v1.5-bleichenbacher.md` | Cube-root forgery |
| JWT validator dispatches on `alg` header | `scenarios/signature-forgery/jwt-alg-confusion.md` | none / HS256 swap |
| Shamir SSS over `2^k` modulus | `scenarios/secret-sharing/shamir-non-prime-modulus.md` | 2-adic Lagrange |

## Sequencing principles

1. **Read source / spec first.** A 5-minute read of the cryptosystem reveals which family fits — saves hours of guessing.
2. **factordb before factoring.** Always look up modulus on factordb.com; CTF moduli are frequently pre-factored.
3. **Identify primitives, not protocols.** A "secure messenger" challenge is just RSA + AES + signature underneath — attack the weakest primitive.
4. **Prefer algebraic over brute-force.** If the structure admits a small lattice or algebraic identity, it's almost always faster than search.
5. **Linear collapses first.** Custom hashes/ciphers built only from XOR + table + permute usually collapse to GF(2) affine — verify the linearity assumption before doing differential cryptanalysis.
6. **Validate with re-encryption.** Recovered plaintext must re-encrypt to the original ciphertext under the published public key — the only reliable correctness check.
7. **Pure Python is enough for most patterns.** Reach for SageMath only for Coppersmith small-roots, Boneh-Durfee, and bivariate lattices — `fpylll + gmpy2 + pycryptodome` covers AGCD, Hastad, Wiener, ECDSA-k-reuse, Fermat, batch-GCD, common modulus, padding oracles, and weak-RNG.
8. **Custom != complex.** "Custom hash with 100 rounds and bit permutations" usually means linear collapse; the complexity is theatre.

## Cross-cutting gotchas

- **Modular inverse mod even moduli.** `pow(x, -1, 2^k)` requires `x` odd. Check before calling.
- **Curve order vs field prime.** ECDSA inversions are mod `n` (curve order), never mod `p` (field prime).
- **Hash truncation in ECDSA.** Hash is truncated to `bitlen(n)` bits, not `bitlen(p)`.
- **PEM whitespace.** Public key bytes for HMAC-confusion attacks must be exactly as the server stores them — try with/without trailing newline, DER vs PEM.
- **Padding randomization.** Real-world RSA uses OAEP/PSS — Hastad and common-modulus do not apply. Confirm "textbook RSA" first.
- **Nonce vs IV.** AES-CTR with reused nonce → keystream reuse → XOR ciphertexts to cancel keystream. CBC reused IV is less catastrophic but still leaks.
- **Constant-time vs not.** Timing oracles often hide where the spec promises constant-time but the implementation isn't; measure with thousands of samples.
