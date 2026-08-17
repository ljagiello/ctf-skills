---
name: cryptography
description: Cryptanalysis techniques — lattice attacks, padding oracles, weak-RNG exploitation, signature forgery, secret-sharing recovery.
---

# Cryptography

## Scope

Practical cryptanalysis for CTF and pentest engagements: identifying when a cryptographic primitive's structure (custom hash, partial leaks, related primes, bad RNG, weak modes) admits a faster-than-brute-force solver, then implementing that solver in pure Python where possible. Covers RSA-style algebraic factoring, lattice/AGCD recovery, GF(2) linear collapse of "complicated-looking" custom ciphers, smooth-order DLP, differential fault attacks, and Shamir-style secret-sharing recovery over non-prime moduli. Always read source first to detect linearity/algebraic structure before reaching for SageMath or symbolic solvers.

## When to use

- A challenge or target ships **custom crypto** (custom hash, custom block cipher, hand-rolled key derivation) and you need to look for affine / GF(2)-linear collapse.
- RSA-style primitives with **structured primes** (`p = a·r + b`, `phi(n)` perfect square, multi-prime hint files, common factors).
- A service exposes a **chosen-ciphertext / chosen-input oracle** and you suspect padding-oracle, smooth-order DLP, or Bleichenbacher-style recovery.
- AES with **fault injection** (correct + faulty ciphertext for the same key — Piret-Quisquater DFA).
- Shamir secret sharing or threshold schemes with non-prime moduli (2-adic recovery via Lagrange interpolation with valuation tracking).

## References

- [reference/lattice-attacks.md](reference/lattice-attacks.md) — AGCD lattice, discriminant-square factoring, smooth-order DLP, Piret-Quisquater DFA.
- [reference/linear-secret-recovery.md](reference/linear-secret-recovery.md) — GF(2) affine collapse of custom hashes/ciphers via column-by-column linear recovery.
