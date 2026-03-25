---
name: ctf-crypto
description: Provides cryptography attack techniques for CTF challenges. Use when attacking encryption, hashing, signatures, ZKP, PRNG, or mathematical crypto problems involving RSA, AES, ECC, lattices, LWE, CVP, number theory, Coppersmith, Pollard, Wiener, padding oracle, GCM, key derivation, or stream/block cipher weaknesses.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Cryptography

Quick reference for crypto CTF challenges. Each technique has a one-liner here; see supporting files for full details with code.

## Additional Resources

- [classic-ciphers.md](classic-ciphers.md) - Classic ciphers: Vigenere (+ Kasiski examination), Atbash, substitution wheels, XOR variants (+ multi-byte frequency analysis), deterministic OTP, cascade XOR, book cipher, OTP key reuse / many-time pad, variable-length homophonic substitution, grid permutation cipher keyspace reduction, image-based Caesar shift ciphers
- [modern-ciphers.md](modern-ciphers.md) - Modern cipher attacks: AES (CFB-8, ECB leakage), CBC-MAC/OFB-MAC, padding oracle, S-box collisions, GF(2) elimination, LCG partial output recovery, affine cipher over composite modulus, AES-GCM with derived keys, AES-GCM nonce reuse (forbidden attack), Ascon-like reduced-round differential cryptanalysis, custom linear MAC forgery, CBC padding oracle (full block decryption), Bleichenbacher RSA PKCS#1 v1.5 padding oracle (ROBOT), birthday attack / meet-in-the-middle, CRC32 collision signature forgery, Blum-Goldwasser bit-extension oracle, hash length extension, compression oracle (CRIME-style), hash function time reversal via cycle detection, OFB mode invertible RNG backward decryption, weak key derivation via public key hash XOR, HMAC-CRC linearity attack, DES weak keys in OFB mode, square attack on reduced-round AES
- [stream-ciphers.md](stream-ciphers.md) - Stream cipher attacks: LFSR (Berlekamp-Massey, correlation attack, known-plaintext, Galois vs Fibonacci, Galois tap recovery via autocorrelation), RC4 second-byte bias, XOR consecutive byte correlation
- [rsa-attacks.md](rsa-attacks.md) - RSA attacks: small e (cube root), common modulus, Wiener's, Pollard's p-1, Hastad's broadcast, Fermat/consecutive primes, multi-prime, restricted-digit, Coppersmith structured primes, Manger oracle, polynomial hash, RSA p=q validation bypass, cube root CRT gcd(e,phi)>1, factoring from phi(n) multiple, multiplicative homomorphism signature forgery, weak keygen via base representation, RSA with gcd(e,phi)>1 exponent reduction, partial key recovery from dp/dq/qinv
- [ecc-attacks.md](ecc-attacks.md) - ECC attacks: small subgroup, invalid curve, Smart's attack (anomalous, with Sage code), fault injection, clock group DLP, Pohlig-Hellman, ECDSA nonce reuse, Ed25519 torsion side channel, DSA nonce reuse
- [zkp-and-advanced.md](zkp-and-advanced.md) - ZKP/graph 3-coloring, Z3 solver guide, garbled circuits, Shamir SSS, bigram constraint solving, race conditions, Groth16 broken setup, DV-SNARG forgery, KZG pairing oracle for permutation recovery
- [prng.md](prng.md) - PRNG attacks (MT19937, MT float recovery via GF(2) magic matrix for token prediction, LCG, GF(2) matrix PRNG, V8 XorShift128+ Math.random state recovery via Z3, middle-square, deterministic RNG hill climbing, random-mode oracle, time-based seeds, C srand/rand synchronization via ctypes, password cracking, logistic map chaotic PRNG)
- [historical.md](historical.md) - Historical ciphers (Lorenz SZ40/42, book cipher implementation)
- [advanced-math.md](advanced-math.md) - Advanced mathematical attacks (isogenies, Pohlig-Hellman, baby-step giant-step (BSGS) for general DLP, LLL, Merkle-Hellman knapsack via LLL, Coppersmith, quaternion RSA, GF(2)[x] CRT, S-box collision code, LWE lattice CVP attack, affine cipher over non-prime modulus)
- [exotic-crypto.md](exotic-crypto.md) - Exotic algebraic structures (braid group DH / Alexander polynomial, monotone function inversion, tropical semiring residuation, Paillier cryptosystem, Hamming code helical interleaving, ElGamal universal re-encryption, FPE Feistel brute-force, icosahedral symmetry group cipher, Goldwasser-Micali replication oracle)

---

## Classic Ciphers

- **Caesar:** Frequency analysis or brute force 26 keys
- **Vigenere:** Known plaintext attack with flag format prefix; derive key from `(ct - pt) mod 26`. Kasiski examination for unknown key length (GCD of repeated sequence distances)
- **Atbash:** A<->Z substitution; look for "Abashed" hints in challenge name
- **Substitution wheel:** Brute force all rotations of inner/outer alphabet mapping
- **Multi-byte XOR:** Split ciphertext by key position, frequency-analyze each column independently; score by English letter frequency (space = 0x20)
- **Cascade XOR:** Brute force first byte (256 attempts), rest follows deterministically
- **XOR rotation (power-of-2):** Even/odd bits never mix; only 4 candidate states
- **Weak XOR verification:** Single-byte XOR check has 1/256 pass rate; brute force with enough budget
- **Deterministic OTP:** Known-plaintext XOR to recover keystream; match load-balanced backends
- **OTP key reuse (many-time pad):** `C1 XOR C2 XOR known_P = unknown_P`; crib dragging when no plaintext known
- **Homophonic (variable-length):** Multi-character ciphertext groups map to single plaintext chars. Find n-grams with identical sub-n-gram frequencies, replace with symbols, solve as monoalphabetic. See [classic-ciphers.md](classic-ciphers.md#variable-length-homophonic-substitution-asis-ctf-finals-2013).
- **Grid permutation cipher:** 5x5 grid with independent row/column permutations collapses keyspace to 5! x 5! = 14,400; brute-force in milliseconds. See [classic-ciphers.md](classic-ciphers.md#grid-permutation-cipher-keyspace-reduction-bsidessf-2026).
- **Image-based Caesar shift:** Pixel rows/columns shifted by per-strip offsets; compare original vs shifted image to extract ASCII-encoded flag from shift amounts. See [classic-ciphers.md](classic-ciphers.md#image-based-caesar-shift-ciphers-bsidessf-2026).

See [classic-ciphers.md](classic-ciphers.md) for full code examples.

## Modern Cipher Attacks

- **AES-ECB:** Block shuffling, byte-at-a-time oracle; image ECB preserves visual patterns
- **AES-CBC:** Bit flipping to change plaintext; padding oracle for decryption without key
- **AES-CFB-8:** Static IV with 8-bit feedback allows state reconstruction after 16 known bytes
- **CBC-MAC/OFB-MAC:** XOR keystream for signature forgery: `new_sig = old_sig XOR block_diff`
- **S-box collisions:** Non-permutation S-box (`len(set(sbox)) < 256`) enables 4,097-query key recovery
- **GF(2) elimination:** Linear hash functions (XOR + rotations) solved via Gaussian elimination over GF(2)
- **Padding oracle:** Byte-by-byte decryption by modifying previous block and testing padding validity
- **LFSR stream ciphers:** Berlekamp-Massey recovers feedback polynomial from 2L keystream bits; correlation attack breaks combined generators with biased combining functions
- **Galois LFSR tap recovery:** XOR known file header (PNG/PDF/ZIP) with ciphertext to get keystream; split into N-bit windows, compute `(state >> 1) XOR next_state` for LSB=1 transitions to directly recover tap mask. Autocorrelation sliding finds correct length. See [stream-ciphers.md](stream-ciphers.md#galois-lfsr-tap-recovery-via-autocorrelation-bsidessf-2026).
- **OFB with invertible RNG:** Known plaintext in any block leaks RNG state; if state transition is bijective, run RNG backwards to decrypt all blocks. See [modern-ciphers.md](modern-ciphers.md#ofb-mode-with-invertible-rng-backward-decryption-bsidessf-2026).
- **Weak key derivation (public key hash XOR):** AES key derived from `SHA256(public_key) XOR seed` is fully recoverable without private key; "hybrid" RSA+AES provides no security. See [modern-ciphers.md](modern-ciphers.md#weak-key-derivation-via-public-key-hash-xor-bsidessf-2026).
- **HMAC-CRC linearity:** CRC is linear over GF(2), so HMAC-CRC key is recoverable from a single message-MAC pair via polynomial arithmetic. See [modern-ciphers.md](modern-ciphers.md#hmac-crc-linearity-attack-boston-key-party-2016).
- **DES weak keys in OFB:** 4 DES weak keys make encryption self-inverse; OFB keystream cycles with period 2, reducing to 16-byte repeating XOR. See [modern-ciphers.md](modern-ciphers.md#des-weak-keys-in-ofb-mode-boston-key-party-2016).
- **Square attack (reduced-round AES):** 4-round AES broken by integral cryptanalysis: 256-plaintext lambda set, guess last round key bytes via XOR-sum = 0 distinguisher. See [modern-ciphers.md](modern-ciphers.md#square-attack-on-reduced-round-aes-0ctf-2016).
- **AES-GCM nonce reuse (forbidden attack):** Same nonce = CTR keystream reuse + GHASH authentication key recovery via polynomial factoring over GF(2^128). Tool: `nonce-disrespect`. See [modern-ciphers.md](modern-ciphers.md#aes-gcm-nonce-reuse--forbidden-attack).

See [modern-ciphers.md](modern-ciphers.md) for full code examples.

## RSA Attacks

- **Small e with small message:** Take eth root
- **Common modulus:** Extended GCD attack
- **Wiener's attack:** Small d
- **Fermat factorization:** p and q close together
- **Pollard's p-1:** Smooth p-1
- **Hastad's broadcast:** Same message, multiple e=3 encryptions
- **Consecutive primes:** q = next_prime(p); find first prime below sqrt(N)
- **Multi-prime:** Factor N with sympy; compute phi from all factors
- **Restricted-digit primes:** Digit-by-digit factoring from LSB with modular pruning
- **Coppersmith structured primes:** Partially known prime; `f.small_roots()` in SageMath
- **Manger oracle (simplified):** Phase 1 doubling + phase 2 binary search; ~128 queries for 64-bit key
- **Manger on RSA-OAEP (timing):** Python `or` short-circuit skips expensive PBKDF2 when Y != 0, creating fast/slow timing oracle. Full 3-step attack (~1024 iterations for 1024-bit RSA). Calibrate timing bounds with known-fast/known-slow samples.
- **Polynomial hash (trivial root):** `g(0) = 0` for polynomial hash; craft suffix for `msg = 0 (mod P)`, signature = 0
- **Polynomial CRT in GF(2)[x]:** Collect ~20 remainders `r = flag mod f`, filter coprime, CRT combine
- **Affine over composite modulus:** CRT in each prime factor field; Gauss-Jordan per prime
- **RSA p=q validation bypass:** Set `p=q` so server computes wrong `phi=(p-1)^2` instead of `p*(p-1)`; test decryption fails, leaking ciphertext
- **RSA cube root CRT (gcd(e,phi)>1):** When all primes ≡ 1 mod e, compute eth roots per-prime via `nthroot_mod`, enumerate CRT combinations (3^k feasible for small k)
- **Factoring from phi(n) multiple:** Any multiple of `phi(n)` (e.g., `e*d-1`) enables factoring via Miller-Rabin square root technique; succeeds with prob ≥ 1/2 per attempt
- **Weak keygen via base representation:** Primes `p = kp*B + tp` with small kp create mixed-radix structure in n; brute-force kp*kq (2^24) to factor
- **RSA with gcd(e,phi)>1 (exponent reduction):** Reduce `e' = e/g`, compute `d' = e'^(-1) mod phi`, partial decrypt to `m^g`, then take g-th root over integers
- **RSA partial key recovery (dp/dq/qinv):** CRT exponents from partial PEM leak allow O(e) prime recovery: iterate k, check if `(dp*e-1)/k+1` is prime. See [rsa-attacks.md](rsa-attacks.md#rsa-partial-key-recovery-from-dp-dq-qinv-0ctf-2016).

See [rsa-attacks.md](rsa-attacks.md) and [advanced-math.md](advanced-math.md) for full code examples.

## Elliptic Curve Attacks

- **Small subgroup:** Check curve order for small factors; Pohlig-Hellman + CRT
- **Invalid curve:** Send points on weaker curves if validation missing
- **Singular curves:** Discriminant = 0; DLP maps to additive/multiplicative group
- **Smart's attack:** Anomalous curves (order = p); p-adic lift solves DLP in O(1)
- **Baby-step giant-step (BSGS):** General DLP in O(sqrt(n)) time/space. Combined with Pohlig-Hellman for smooth-order groups (all factors of `p-1` or curve order are small). Sage: `discrete_log(Mod(h,p), Mod(g,p))`. See [advanced-math.md](advanced-math.md#baby-step-giant-step-for-general-dlp).
- **Fault injection:** Compare correct vs faulty output; recover key bit-by-bit
- **Clock group (x^2+y^2=1):** Order = p+1 (not p-1!); Pohlig-Hellman when p+1 is smooth
- **Isogenies:** Graph traversal via modular polynomials; pathfinding via LCA
- **ECDSA nonce reuse:** Same `r` in two signatures leaks nonce `k` and private key `d` via modular arithmetic. Check for repeated `r` values
- **Braid group DH:** Alexander polynomial is multiplicative under braid concatenation — Eve computes shared secret from public keys. See [exotic-crypto.md](exotic-crypto.md#braid-group-dh--alexander-polynomial-multiplicativity-dicectf-2026)
- **Ed25519 torsion side channel:** Cofactor h=8 leaks secret scalar bits when key derivation uses `key = master * uid mod l`; query powers of 2, check y-coordinate consistency
- **Tropical semiring residuation:** Tropical (min-plus) DH is broken — residual `b* = max(Mb[i] - M[i][j])` recovers shared secret directly from public matrices
- **FPE Feistel brute-force:** Format-preserving encryption with 16-bit round key is brute-forceable; remaining affine GF(2) mixing layer solved via Gaussian elimination. See [exotic-crypto.md](exotic-crypto.md#format-preserving-encryption-feistel-brute-force-bsidessf-2026)
- **Icosahedral symmetry cipher:** Dodecahedron face permutations form order-120 group; build lookup table of all permutations via API probing, match visible face patterns. See [exotic-crypto.md](exotic-crypto.md#icosahedral-symmetry-group-cipher-bsidessf-2026)
- **Goldwasser-Micali replication oracle:** GM encrypts one bit per ciphertext; replaying a single ciphertext value N times as an N-bit key forces all-zero or all-one key, distinguishable via hash oracle. 128 queries recover full AES key. See [exotic-crypto.md](exotic-crypto.md#goldwasser-micali-ciphertext-replication-oracle-bsidessf-2026)
- **DSA nonce reuse:** Same r in two DSA signatures leaks private key via same formula as ECDSA nonce reuse. See [ecc-attacks.md](ecc-attacks.md#dsa-nonce-reuse-for-private-key-recovery-volgactf-2016).

See [ecc-attacks.md](ecc-attacks.md), [advanced-math.md](advanced-math.md), and [exotic-crypto.md](exotic-crypto.md) for full code examples.

## Lattice / LWE Attacks

- **LWE via CVP (Babai):** Construct lattice from `[q*I | 0; A^T | I]`, use fpylll CVP.babai to find closest vector, project to ternary {-1,0,1}. Watch for endianness mismatches between server description and actual encoding.
- **LLL for approximate GCD:** Short vector in lattice reveals hidden factors
- **Multi-layer challenges:** Geometry → subspace recovery → LWE → AES-GCM decryption chain

See [advanced-math.md](advanced-math.md) for full LWE solving code and multi-layer patterns.

## ZKP & Constraint Solving

- **ZKP cheating:** For impossible problems (3-coloring K4), find hash collisions or predict PRNG salts
- **Graph 3-coloring:** `nx.coloring.greedy_color(G, strategy='saturation_largest_first')`
- **Z3 solver:** BitVec for bit-level, Int for arbitrary precision; BPF/SECCOMP filter solving
- **Garbled circuits (free XOR):** XOR three truth table entries to recover global delta
- **Bigram substitution:** OR-Tools CP-SAT with automaton constraint for known plaintext structure
- **Trigram decomposition:** Positions mod n form independent monoalphabetic ciphers
- **Shamir SSS (deterministic coefficients):** One share + seeded RNG = univariate equation in secret
- **Race condition (TOCTOU):** Synchronized concurrent requests bypass `counter < N` checks
- **Groth16 broken setup (delta==gamma):** Trivially forge: A=alpha, B=beta, C=-vk_x. Always check verifier constants first
- **Groth16 proof replay:** Unconstrained nullifier + no tracking = infinite replays from setup tx
- **DV-SNARG forgery:** With verifier oracle access, learn secret v values from unconstrained pairs, forge via CRS entry cancellation

See [zkp-and-advanced.md](zkp-and-advanced.md) for full code examples and solver patterns.

## Modern Cipher Attacks (Additional)

- **Affine over composite modulus:** `c = A*x+b (mod M)`, M composite (e.g., 65=5*13). Chosen-plaintext recovery via one-hot vectors, CRT inversion per prime factor. See [modern-ciphers.md](modern-ciphers.md#affine-cipher-over-composite-modulus-nullcon-2026).
- **Custom linear MAC forgery:** XOR-based signature linear in secret blocks. Recover secrets from ~5 known pairs, forge for target. See [modern-ciphers.md](modern-ciphers.md#custom-linear-mac-forgery-nullcon-2026).
- **Manger oracle (RSA threshold):** RSA multiplicative + binary search on `m*s < 2^128`. ~128 queries to recover AES key.

## CBC Padding Oracle Attack

Server reveals valid/invalid padding → decrypt any CBC ciphertext without key. ~4096 queries per 16-byte block. Use PadBuster or `padding-oracle` Python library. See [modern-ciphers.md](modern-ciphers.md#cbc-padding-oracle-attack).

## Bleichenbacher RSA Padding Oracle (ROBOT)

RSA PKCS#1 v1.5 padding validation oracle → adaptive chosen-ciphertext plaintext recovery. ~10K queries for RSA-2048. Affects TLS implementations via timing. See [modern-ciphers.md](modern-ciphers.md#bleichenbacher--pkcs1-v15-rsa-padding-oracle).

## Birthday Attack / Meet-in-the-Middle

n-bit hash collision in ~2^(n/2) attempts. Meet-in-the-middle breaks double encryption in O(2^k) instead of O(2^(2k)). See [modern-ciphers.md](modern-ciphers.md#birthday-attack--meet-in-the-middle).

## CRC32 Collision-Based Signature Forgery (iCTF 2013)

CRC32 is linear — append 4 chosen bytes to force any target CRC32, forging `CRC32(msg || secret)` signatures without the secret. See [modern-ciphers.md](modern-ciphers.md#crc32-collision-based-signature-forgery-ictf-2013).

## Blum-Goldwasser Bit-Extension Oracle (PlaidCTF 2013)

Extend ciphertext by one bit per oracle query to leak plaintext via parity. Manipulate BBS squaring sequence to produce valid extended ciphertexts. See [modern-ciphers.md](modern-ciphers.md#blum-goldwasser-bit-extension-oracle-plaidctf-2013).

## Hash Length Extension Attack

Exploits Merkle-Damgard hashes (`hash(SECRET || user_data)`) — append arbitrary data and compute valid hash without knowing the secret. Use `hashpump` or `hashpumpy`. See [modern-ciphers.md](modern-ciphers.md#hash-length-extension-attack-plaidctf-2014).

## Compression Oracle (CRIME-Style)

Compression before encryption leaks plaintext via ciphertext length changes. Send chosen plaintexts; matching n-grams compress shorter. Same class as CRIME/BREACH. See [modern-ciphers.md](modern-ciphers.md#compression-oracle--crime-style-attack-bctf-2015).

## RC4 Second-Byte Bias

RC4's second output byte is biased toward `0x00` (probability 1/128 vs 1/256). Distinguishes RC4 from random with ~2048 samples. See [stream-ciphers.md](stream-ciphers.md#rc4-second-byte-bias-distinguisher-hackover-ctf-2015).

## RSA Multiplicative Homomorphism Signature Forgery

Unpadded RSA: `S(a) * S(b) mod n = S(a*b) mod n`. If oracle blacklists target message, sign its factors and multiply. See [rsa-attacks.md](rsa-attacks.md#rsa-signature-forgery-via-multiplicative-homomorphism-mma-ctf-2015).

## Common Patterns

- **RSA basics:** `phi = (p-1)*(q-1)`, `d = inverse(e, phi)`, `m = pow(c, d, n)`. See [rsa-attacks.md](rsa-attacks.md) for full examples.
- **XOR:** `from pwn import xor; xor(ct, key)`. See [classic-ciphers.md](classic-ciphers.md) for XOR variants.

## C srand/rand Prediction via ctypes (L3akCTF 2024, MireaCTF)

**Pattern:** Binary uses `srand(time(NULL))` + `rand()` for keys/XOR masks. Python's `random` module uses a different PRNG. Use `ctypes.CDLL('./libc.so.6')` to call C's `srand(int(time()))` and `rand()` directly, reproducing the exact sequence. See [prng.md](prng.md#c-srandrand-synchronization-via-python-ctypes) for XOR decryption examples and timing tips.

## V8 XorShift128+ (Math.random) State Recovery

**Pattern:** V8 JavaScript engine uses xs128p PRNG for `Math.random()`. Given 5-10 consecutive outputs of `Math.floor(CONST * Math.random())`, recover internal state (state0, state1) with Z3 QF_BV solver and predict future values. Values must be reversed (LIFO cache). Tool: `d0nutptr/v8_rand_buster`. See [prng.md](prng.md#v8-xorshift128-state-recovery-mathrandom-prediction).

## MT State Recovery from Float Outputs (PHD CTF Quals 2012)

**Pattern:** Server exposes `random.random()` floats. Standard untemper needs 624 × 32-bit integers, but floats yield only ~8 usable bits each. A precomputed GF(2) magic matrix (`not_random` library) recovers the full MT state from 3360+ float observations. Use to predict password reset tokens, session IDs, or CSRF tokens derived from `random.random()`. See [prng.md](prng.md#mt-state-recovery-from-randomrandom-floats-via-gf2-matrix-phd-ctf-quals-2012).

## Chaotic PRNG (Logistic Map)

- **Logistic map:** `x = r * x * (1 - x)`, `r ≈ 3.99-4.0`; seed recovery by brute-forcing high-precision decimals
- **Keystream:** `struct.pack("<f", x)` per iteration; XOR with ciphertext

See [prng.md](prng.md#logistic-map--chaotic-prng-seed-recovery-bypass-ctf-2025) for full code.

## Useful Tools

- **Python:** `pip install pycryptodome z3-solver sympy gmpy2`
- **SageMath:** `sage -python script.py` (required for ECC, Coppersmith, lattice attacks)
- **RsaCtfTool:** `python RsaCtfTool.py -n <n> -e <e> --uncipher <c>` — automated RSA attack suite (tries Wiener, Hastad, Fermat, Pollard, and many more)
- **quipqiup.com:** Automated substitution cipher solver (frequency + word pattern analysis)
