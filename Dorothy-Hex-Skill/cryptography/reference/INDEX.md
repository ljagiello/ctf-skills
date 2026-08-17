# Cryptography — Scenario Index

Read `cryptography-principles.md` first for the decision tree. This index maps fingerprints to scenario files.

## Lattice / Algebraic

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Need to set up an LLL-based attack from scratch | `scenarios/lattice/lll-basis-reduction.md` | Build matrix, scale rows, reduce |
| `p_i = a_i·r + b_i` with small `b_i`, many samples | `scenarios/lattice/agcd-attack.md` | LLL reveals shared `r` |
| Stereotyped plaintext / known high bits of `p` | `scenarios/lattice/coppersmith-known-bits.md` | small_roots polynomial |
| Low private exponent `n^0.25 < d < n^0.292` | `scenarios/lattice/boneh-durfee-low-d.md` | Bivariate Coppersmith |

## RSA Quirks

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| `e=3`, `m^e < n` or broadcast | `scenarios/rsa-quirks/low-public-exponent.md` | Cube root / Hastad CRT |
| Same plaintext, same `n`, two `e` | `scenarios/rsa-quirks/common-modulus.md` | Bezout combine |
| Low `d`, `e` close to `n` | `scenarios/rsa-quirks/wiener-attack.md` | Continued fractions |
| Primes close in value | `scenarios/rsa-quirks/fermat-close-primes.md` | Fermat iteration |
| Small or shared prime factors | `scenarios/rsa-quirks/small-prime-factorization.md` | factordb, ECM, batch GCD |

## Padding Oracles

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| CBC + valid/invalid padding signal | `scenarios/padding-oracle/cbc-padding-oracle.md` | Vaudenay byte-by-byte |
| RSA-PKCS#1 v1.5 decrypt oracle | `scenarios/padding-oracle/pkcs1-v1.5-bleichenbacher.md` | BB98 million-message |
| ECB + chosen prefix oracle | `scenarios/padding-oracle/ecb-prefix-oracle.md` | Byte-at-a-time recovery |

## Weak RNG

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| LCG outputs visible (Java Random, MS rand) | `scenarios/weak-rng/lcg-state-recovery.md` | gcd-based recovery, brute low bits |
| MT19937 outputs (Python/PHP/Ruby random) | `scenarios/weak-rng/mt19937-state-recovery.md` | 624 outputs → state via untemper |
| Dual_EC_DRBG with two P-256 points | `scenarios/weak-rng/dual-ec-backdoor.md` | Recover state via known `e` |

## Signature Forgery

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Two ECDSA sigs share `r` | `scenarios/signature-forgery/ecdsa-nonce-reuse.md` | Recover `k`, then `d` |
| RSA-PKCS#1 v1.5 sigs, `e=3`, loose verifier | `scenarios/signature-forgery/rsa-pkcs1-v1.5-bleichenbacher.md` | Cube-root forge |
| JWT verifier picks alg from header | `scenarios/signature-forgery/jwt-alg-confusion.md` | `alg=none`, RS256→HS256 |
| Masked/"projective" ECDSA leaks a binary-GCD `half`/`sub`/`add` transcript of its inversion | `scenarios/signature-forgery/gcd-transcript-operand-recovery.md` | Reconstruct `den=mask·k` from the trace (reverse-replay, `x2=0` anchor). If operands UNREDUCED, `gcd(num,den)` cancels the mask. Else FACTOR `den` (product of two ~256-bit composites, not a hard semiprime) + test divisors vs `r` → `d`. CVE-2019-18222/2020/055 |

## Secret Sharing

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Shamir SSS over `2^k` modulus | `scenarios/secret-sharing/shamir-non-prime-modulus.md` | 2-adic Lagrange interpolation |

## Classical

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Short key XOR'd cyclically over plaintext; no key | `scenarios/classical/repeating-key-xor.md` | IC key-length, per-column frequency analysis |

## Reference Sheets (legacy, full attack catalogs)

| File | Coverage |
|---|---|
| `lattice-attacks.md` | AGCD, discriminant-square factoring, smooth-order DLP, Piret-Quisquater DFA |
| `linear-secret-recovery.md` | GF(2) affine collapse of custom ciphers / hashes |
