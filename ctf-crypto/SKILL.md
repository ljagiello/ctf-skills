---
name: ctf-crypto
description: Cryptography attack techniques for CTF challenges. Use when attacking encryption, hashing, signatures, ZKP, PRNG, or mathematical crypto problems involving RSA, AES, ECC, lattices, number theory, Coppersmith, Pollard, Wiener, padding oracle, or stream/block cipher weaknesses.
license: MIT
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Cryptography

Quick reference for crypto CTF challenges. Each technique has a one-liner here; see supporting files for full details with code.

## Additional Resources

- [classic-ciphers.md](classic-ciphers.md) - Classic ciphers: Vigenere, Atbash, substitution wheels, XOR variants, deterministic OTP, cascade XOR, book cipher
- [modern-ciphers.md](modern-ciphers.md) - Modern cipher attacks: AES (CFB-8, ECB leakage), CBC-MAC/OFB-MAC, padding oracle, S-box collisions, GF(2) elimination, LCG partial output recovery
- [rsa-attacks.md](rsa-attacks.md) - RSA attacks: consecutive primes, multi-prime, restricted-digit, Coppersmith structured primes, Manger oracle, polynomial hash
- [ecc-attacks.md](ecc-attacks.md) - ECC attacks: small subgroup, invalid curve, Smart's attack (anomalous, with Sage code), fault injection, clock group DLP, Pohlig-Hellman
- [zkp-and-advanced.md](zkp-and-advanced.md) - ZKP/graph 3-coloring, Z3 solver guide, garbled circuits, Shamir SSS, bigram constraint solving, race conditions
- [prng.md](prng.md) - PRNG attacks (MT19937, LCG, GF(2) matrix PRNG, middle-square, deterministic RNG hill climbing, random-mode oracle, time-based seeds, password cracking)
- [historical.md](historical.md) - Historical ciphers (Lorenz SZ40/42, book cipher implementation)
- [advanced-math.md](advanced-math.md) - Advanced mathematical attacks (isogenies, Pohlig-Hellman, LLL, Coppersmith, quaternion RSA, monotone inversion, GF(2)[x] CRT, S-box collision code)

---

## Classic Ciphers

- **Caesar:** Frequency analysis or brute force 26 keys
- **Vigenere:** Known plaintext attack with flag format prefix; derive key from `(ct - pt) mod 26`
- **Atbash:** A<->Z substitution; look for "Abashed" hints in challenge name
- **Substitution wheel:** Brute force all rotations of inner/outer alphabet mapping
- **Cascade XOR:** Brute force first byte (256 attempts), rest follows deterministically
- **XOR rotation (power-of-2):** Even/odd bits never mix; only 4 candidate states
- **Weak XOR verification:** Single-byte XOR check has 1/256 pass rate; brute force with enough budget
- **Deterministic OTP:** Known-plaintext XOR to recover keystream; match load-balanced backends

See [classic-ciphers.md](classic-ciphers.md) for full code examples.

## Modern Cipher Attacks

- **AES-ECB:** Block shuffling, byte-at-a-time oracle; image ECB preserves visual patterns
- **AES-CBC:** Bit flipping to change plaintext; padding oracle for decryption without key
- **AES-CFB-8:** Static IV with 8-bit feedback allows state reconstruction after 16 known bytes
- **CBC-MAC/OFB-MAC:** XOR keystream for signature forgery: `new_sig = old_sig XOR block_diff`
- **S-box collisions:** Non-permutation S-box (`len(set(sbox)) < 256`) enables 4,097-query key recovery
- **GF(2) elimination:** Linear hash functions (XOR + rotations) solved via Gaussian elimination over GF(2)
- **Padding oracle:** Byte-by-byte decryption by modifying previous block and testing padding validity

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
- **Manger oracle:** Phase 1 doubling + phase 2 binary search; ~128 queries for 64-bit key
- **Polynomial hash (trivial root):** `g(0) = 0` for polynomial hash; craft suffix for `msg = 0 (mod P)`, signature = 0
- **Polynomial CRT in GF(2)[x]:** Collect ~20 remainders `r = flag mod f`, filter coprime, CRT combine
- **Affine over composite modulus:** CRT in each prime factor field; Gauss-Jordan per prime

See [rsa-attacks.md](rsa-attacks.md) and [advanced-math.md](advanced-math.md) for full code examples.

## Elliptic Curve Attacks

- **Small subgroup:** Check curve order for small factors; Pohlig-Hellman + CRT
- **Invalid curve:** Send points on weaker curves if validation missing
- **Singular curves:** Discriminant = 0; DLP maps to additive/multiplicative group
- **Smart's attack:** Anomalous curves (order = p); p-adic lift solves DLP in O(1)
- **Fault injection:** Compare correct vs faulty output; recover key bit-by-bit
- **Clock group (x^2+y^2=1):** Order = p+1 (not p-1!); Pohlig-Hellman when p+1 is smooth
- **Isogenies:** Graph traversal via modular polynomials; pathfinding via LCA

See [ecc-attacks.md](ecc-attacks.md) and [advanced-math.md](advanced-math.md) for full code examples.

## ZKP & Constraint Solving

- **ZKP cheating:** For impossible problems (3-coloring K4), find hash collisions or predict PRNG salts
- **Graph 3-coloring:** `nx.coloring.greedy_color(G, strategy='saturation_largest_first')`
- **Z3 solver:** BitVec for bit-level, Int for arbitrary precision; BPF/SECCOMP filter solving
- **Garbled circuits (free XOR):** XOR three truth table entries to recover global delta
- **Bigram substitution:** OR-Tools CP-SAT with automaton constraint for known plaintext structure
- **Trigram decomposition:** Positions mod n form independent monoalphabetic ciphers
- **Shamir SSS (deterministic coefficients):** One share + seeded RNG = univariate equation in secret
- **Race condition (TOCTOU):** Synchronized concurrent requests bypass `counter < N` checks

See [zkp-and-advanced.md](zkp-and-advanced.md) for full code examples and solver patterns.

## Modern Cipher Attacks (Additional)

- **Affine over composite modulus:** `c = A*x+b (mod M)`, M composite (e.g., 65=5*13). Chosen-plaintext recovery via one-hot vectors, CRT inversion per prime factor. See [modern-ciphers.md](modern-ciphers.md#affine-cipher-over-composite-modulus-nullcon-2026).
- **Custom linear MAC forgery:** XOR-based signature linear in secret blocks. Recover secrets from ~5 known pairs, forge for target. See [modern-ciphers.md](modern-ciphers.md#custom-linear-mac-forgery-nullcon-2026).
- **Manger oracle (RSA threshold):** RSA multiplicative + binary search on `m*s < 2^128`. ~128 queries to recover AES key.

## Common Patterns

- **RSA basics:** `phi = (p-1)*(q-1)`, `d = inverse(e, phi)`, `m = pow(c, d, n)`. See [rsa-attacks.md](rsa-attacks.md) for full examples.
- **XOR:** `from pwn import xor; xor(ct, key)`. See [classic-ciphers.md](classic-ciphers.md) for XOR variants.

## Useful Tools

- **Python:** `pip install pycryptodome z3-solver sympy gmpy2`
- **SageMath:** `sage -python script.py` (required for ECC, Coppersmith, lattice attacks)
