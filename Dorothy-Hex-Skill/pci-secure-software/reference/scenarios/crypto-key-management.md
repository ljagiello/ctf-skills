---
name: crypto-key-management
description: Assessor playbook for finding source-code and documentation evidence for SO7 (random numbers), SO8 (key management), SO9 (strong cryptography catch-all), plus crypto-key metadata 2-1.8.x and output cryptography 6-2.
---

# Random Numbers, Key Management & Cryptography (SO7, SO8, SO9, 2-1.8, 6-2)

This family requires that random values feeding sensitive assets have sufficient entropy and an appropriate generator (SO7), that cryptographic keys are generated, stored, scoped, wrapped, integrity-protected, derived, and revoked correctly (SO8), that any remaining crypto satisfies "strong cryptography" (SO9, the catch-all), and that key metadata (2-1.8.x) and output protection (6-2) are documented and implemented. Most rows are documentation-only or static; a handful are dynamic — for those a static reading is never sufficient (see schema invariant: dynamic + `"dynamic" not in analysis_performed` ⇒ `REQUIRES_MANUAL_REVIEW`).

## Where to find evidence

RNG / CSPRNG call sites (SO7, 8-1, 7-1.3.2):
- Python: `random.` (insecure — flag it), `secrets.`, `os.urandom`, `ssl.RAND_bytes`
- Node: `Math.random` (insecure), `crypto.randomBytes`, `crypto.generateKeyPair`
- Java/Kotlin: `new Random(` / `Math.random` (insecure), `SecureRandom`, `KeyGenerator`, `SecureRandom.getInstanceStrong`
- Go: `math/rand` (insecure), `crypto/rand.Read`
- C/C++/OpenSSL: `rand()`/`srand()` (insecure), `RAND_bytes`, `getrandom`
- Globs: `**/*crypto*`, `**/*random*`, `**/*rng*`, `**/*entropy*`, `**/*seed*`
- In-house DRNG (7-1.3.x): hand-rolled generator loops, custom LFSR/PRNG classes, a fixed/derived seed constant → trigger 7-1.3.1..7-1.3.4 sub-tree.

Key generation / derivation / storage (8-1, 8-2, 8-2.1, 8-6):
- `generateKey`, `KeyGenerator`, `KeyPairGenerator`, `EVP_PKEY_keygen`, `openssl genrsa/genpkey`, `crypto.generateKeySync`
- KDFs: `PBKDF2`, `HKDF`, `bcrypt`, `scrypt`, `argon2`, `KCV`/key-check-value, `hashlib.pbkdf2_hmac`
- Storage: keystore/KMS/HSM integration — `KeyStore`, `keystore.jks`/`.p12`/`.pfx`/`.pem`/`.key` files, `PKCS11`, `boto3 kms`, `azure.keyvault`, `gcp kms`, `vault`, `pkcs8`, env vars / config holding key material.
- Globs: `**/*.jks`, `**/*.p12`, `**/*.pem`, `**/*.key`, `**/*keystore*`, `**/*kms*`, `**/*hsm*`, `**/config/*.{yml,yaml,json,properties,env}`

Algorithm / cipher-suite constants (8-4, 9-1, 6-2):
- Cipher strings: `AES`, `RSA`, `EC`/`ECDSA`/`Ed25519`, `ChaCha20`; mode/padding: `ECB` (weak), `CBC`, `GCM`, `PKCS1` vs `OAEP`; deprecated: `DES`/`3DES`, `RC4`, `MD5`, `SHA1`, `<2048`-bit RSA, `TLSv1`/`TLSv1.1`, `SSLv3`.
- Cipher-suite / TLS config: `ssl_ciphers`, `SSLContext`, `minimum_tls_version`, `Cipher.getInstance("...")`.

Certificate handling & revocation (8-5, 8-7, 6-2.2):
- `X509`, cert pinning, `verify=`, `OCSP`, `CRL`, `setRevocationEnabled`, `PKIXRevocationChecker`, cert/key rotation jobs, a documented revocation/rotation runbook.

Documentation sections to read: the vendor's RNG justification (7-1.2), key-inventory / key-management schema table (2-1.8.1–2-1.8.9: key type, algorithm, schema, length, generation method & origin, destruction method, associations), data-flow diagrams for output protection (6-1, 6-2), and the key-revocation/rotation procedure (8-7).

## Reused sub-skills

- [skills/cryptography/SKILL.md](../../../cryptography/SKILL.md) — weak-RNG detection (insecure `random`/`Math.random`/`math/rand` and predictable seeds → SO7, 8-1), key-handling review (wrapping below equal strength → 8-4; cleartext-key-at-rest → 8-2.1), algorithm/parameter strength and padding/mode issues (ECB, PKCS1 oracle, short RSA, broken hashes → 9-1, 8-6, 6-2).
- [skills/source-code-scanning/SKILL.md](../../../source-code-scanning/SKILL.md) — hardcoded keys/secrets and `.pem`/`.key`/keystore material checked into the repo (8-2.1, 8-2), and weak-cipher SAST patterns (deprecated algorithms/modes → 9-1, 6-2). Its secrets-detection scan is the primary mechanical evidence source for "cleartext keys in non-volatile memory".

## Assessing each requirement

Every cited finding is an `Evidence` object: `source_file` + `source_lineno` + verbatim `quoted_text` (the citation verifier greps it within `±5` lines) + `sha256` + `evidence_type`. See [../core/schema.md](../core/schema.md).

- **7-1.1 / 7-1.2 (RNG strength & appropriateness):** MET = a CSPRNG (or platform/hardware RNG) whose security strength ≥ the strongest key it feeds, with documented justification. NOT_MET = an insecure generator call site feeding key/token/IV/nonce material, or no justification doc. Cite the exact call site for code, the doc section for the justification.
- **7-1.3.x (in-house DRNG):** applies only if the software ships its own generator. MET = DRNG built on a recognized standard (SP 800-90A/ISO 18031), seeded by a trusted NDRNG (7-1.3.2), reseeded frequently (7-1.3.3), seed protected with strong crypto (7-1.3.4). NOT_MET = bespoke PRNG, fixed/low-entropy seed, no reseed. 7-1.3.1 has a **dynamic** test — without running it, the row is `REQUIRES_MANUAL_REVIEW`, not MET.
- **8-1 (key-gen entropy):** MET = key generation draws from a CSPRNG with effective strength ≥ key strength. NOT_MET = key derived from a weak RNG, timestamp, counter, or static secret. Trace the RNG call into the keygen call.
- **8-2 / 8-2.1 (confidentiality; no cleartext keys in NVM):** MET = secret/private keys held only in protected stores (KMS/HSM/encrypted keystore) and zeroized after use; nothing cleartext at rest. NOT_MET = a private key in a repo file, config, env constant, or plaintext on disk — cite the file:line. The source-code-scanning secrets scan is the canonical NOT_MET evidence here.
- **8-3 (single-purpose keys):** MET = each key used for exactly one purpose. NOT_MET = one key for encrypt + sign, or data-key reused as KEK. **Dynamic negative test (8-3.b):** attempt to use a key for a second purpose; success ⇒ NOT_MET. Static-only ⇒ `REQUIRES_MANUAL_REVIEW`.
- **8-4 (equal-strength wrapping):** MET = every key protected by a key of equal/greater strength (no AES-128 KEK over an AES-256 key, no key in cleartext). NOT_MET = under-strength wrapping. **Dynamic negative test (8-4.b):** attempt to wrap/use a key with an inadequate-strength key.
- **8-5 (public-key integrity/authenticity):** MET = public keys/certs authenticated (signature/chain/pin) before use. NOT_MET = trust-on-first-use, `verify=False`, disabled chain validation. **Dynamic negative test (8-5.b):** present an unauthenticated/substituted public key and confirm it is rejected.
- **8-6 / 8-6.1 / 8-6.2 (KDF/KCV one-way, non-leaking):** MET = derivation/check uses a one-way function that does not expose the underlying key. NOT_MET = reversible "derivation", KCV that leaks key bits, raw key in a check value.
- **8-7 (revocation):** MET = a documented and implemented capability to revoke/cease use of compromised keys/certs (CRL/OCSP consumption, rotation job, kill-switch). NOT_MET = no revocation path. Cite both the doc procedure and the code that enforces it.
- **9-1 (strong-crypto catch-all):** any crypto on sensitive assets not covered above must meet the standard's strong-cryptography definition. MET = approved algorithm + adequate key length + secure mode/padding. NOT_MET = DES/3DES/RC4/MD5/SHA1, ECB, RSA<2048, PKCS1v1.5 where OAEP is required, or a downgradeable channel.
- **2-1.8.x (key metadata):** documentation-only. MET = a key inventory documenting type, algorithm, schema, length, generation method & origin, destruction method, and associations (2-1.8.1–2-1.8.9) for every key. NOT_MET = missing fields or undocumented keys found in code but absent from the inventory — cross-check code-discovered keys against the doc.
- **6-2 (output crypto):** MET = sensitive assets output via strong data-level and/or secure-channel cryptography (6-2.1/6-2.2), per-session keys (6-2.2.6), downgrade-resistant (6-2.2.7). NOT_MET = plaintext output, weak channel cipher, reused session keys, missing mutual auth.

## Remediation themes

- Replace insecure generators (`random`, `Math.random`, `math/rand`, `rand()`) with platform CSPRNGs for any value touching a sensitive asset (SO7, 8-1).
- Move private/secret keys out of the repo, config, and env into a KMS/HSM/encrypted keystore; zeroize buffers; never persist cleartext keys (8-2, 8-2.1).
- Scope each key to one purpose; wrap with an equal-or-greater-strength key (8-3, 8-4).
- Authenticate public keys/certs before use; enable chain + revocation checking (OCSP/CRL) and ship a rotation/revocation runbook (8-5, 8-7).
- Retire deprecated algorithms/modes/lengths; prefer AEAD (GCM/ChaCha20-Poly1305), OAEP, RSA≥2048/ECC, TLS≥1.2 with downgrade protection (9-1, 6-2).
- Complete the key-management inventory so every code-discovered key has a documented 2-1.8.x row.

## Anti-Patterns

- Asserting a **dynamic** requirement MET (8-3, 8-4, 8-5, 7-1.3.1) from a static code read or from documentation alone — the negative test (attempt-to-bypass) was not run, so the only honest status is `REQUIRES_MANUAL_REVIEW`.
- Treating an import or dependency (e.g. a `secrets`/`SecureRandom` import, a KMS SDK in `requirements.txt`) as proof the control is used correctly, without tracing the actual call site that produces the key/random value.
- Reading the vendor's key-management doc and marking 8-x MET without cross-checking the code — a documented control that the implementation does not enforce is NOT_MET, and a key found only in code but absent from the 2-1.8.x inventory is a documentation gap.
- Calling a generator "strong" by name (AES, RSA) while ignoring mode/padding/length — ECB, PKCS1v1.5, RSA-1024, or a static IV defeats 9-1 regardless of the algorithm label.
- Re-wording a `quoted_text` so the citation verifier matches — that quarantines the verdict; the quote must be verbatim from `source_file`.

## See also
- [../core/schema.md](../core/schema.md) — Evidence / RequirementVerdict shapes, VerdictStatus enum, dynamic-not-run invariant.
- [../catalog/INDEX.md](../catalog/INDEX.md) — the catalog file, requirement IDs, and counts.
