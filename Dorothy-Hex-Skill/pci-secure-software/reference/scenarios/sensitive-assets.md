---
name: sensitive-assets
description: Assessor playbook for PCI SSS v2.0 Security Objectives 2 (sensitive data/resource/functionality identification & documentation, incl. crypto-key metadata), 3 (secure storage, retention & deletion of data and resources), and 6 (protection of sensitive assets on output — data-level encryption, secure channels, end-user messaging).
---

# Sensitive Asset Identification, Storage, Retention & Output (SO2, SO3, SO6)

This objective family requires the software to have **identified and documented** every sensitive asset (data 2-1, resources 2-2, functionality 2-3, including per-key crypto metadata 2-1.8.x), to **store, retain and securely delete** that data (3-1, 3-2) and those resources (3-3, 3-4) only as permissible, and to **protect every sensitive asset that leaves the software** via data-level encryption (6-2.1), secure channels (6-2.2), or strong transmission crypto (6-2.3). The assessor proves alignment between what the docs claim and what the code actually does — discrepancies are findings, not footnotes.

## Where to find evidence

- **Asset inventory / data classification docs**: design docs, threat models, "data dictionary", `*classification*`, `*data-inventory*`, `*asset*`, README sections titled "Sensitive Data", "Retention", "Key Management". These anchor 2-1.1, 2-1.5/2-1.6, 2-2.1, 2-3.1 and the SO3 retention claims.
- **Data-flow / resource-flow diagrams**: `*.drawio`, `*.mmd`, `*flow*`, `*dfd*`, doc sections feeding 2-1.7 / 2-2.8 (and reused verbatim by 6-1). Confirm every output edge maps to an SO6 control.
- **ORM models & schema/migrations**: `models/`, `entity/`, `*.prisma`, `schema.sql`, `migrations/`, `alembic/`, `db/`. Column names (`pan`, `cvv`, `track`, `password`, `secret`, `token`, `ssn`) reveal what is *actually* stored vs. what 2-1.2/3-1.1 claim is permissible.
- **Write call sites (storage-location discovery)**: grep `open(`, `write(`, `fs.write`, `INSERT`, `save(`, `put_object`, `setItem`, `SharedPreferences`, `NSUserDefaults`, cache/temp-file writes. Map each to a documented storage location (2-1.2, 2-2.3).
- **Serialization & logging (silent leaks)**: `json.dumps`, `pickle`, `Marshal`, `toString()`, `log.`, `logger.`, `print`, `console.log`, exception handlers, telemetry/analytics SDK calls — sensitive data reaching logs/serializers is an unaccounted output (6-1) and often a storage violation (3-1.1).
- **Secure-delete / retention routines**: `*retention*`, `*purge*`, `*shred*`, `*zeroize*`, `memset_s`, `explicit_bzero`, `Arrays.fill`, `crypto_erase`, TTL/cron jobs, `DELETE ... WHERE created_at <`. Backs 2-1.4/2-2.5 (documented method) and 3-1.4/3-2/3-3.4/3-4 (implemented deletion).
- **Storage crypto config**: `*.env`, `application.yml`, KMS/keystore config, `Cipher.getInstance`, `AES`, `createCipheriv`, column-encryption settings — for 3-1.2.1 / 3-3.2.1 strong-crypto-in-storage.
- **TLS / secure-channel setup**: `SSLContext`, `TLSConfig`, `https.createServer`, `ssl.minimum_version`, `cipher_suites`, mTLS/`verify_mode`, cert-pinning, env keys like `TLS_MIN_VERSION` — for 6-2.2.x channel claims and 6-2.3 transmission crypto.
- **Crypto-key metadata (2-1.8.x)**: key-management doc/table listing key type, algorithm, schema, length, generation method & origin, destruction method, and associations. Cross-check against `KeyGenerator`, `generateKey`, `RSA.generate`, keystore aliases, env-injected keys.

## Reused sub-skills

- [skills/source-code-scanning/SKILL.md](../../../source-code-scanning/SKILL.md) — drive the scan; its references do the heavy lifting:
  - [reference/secrets-detection.md](../../../source-code-scanning/reference/secrets-detection.md) — find hardcoded keys/secrets that contradict the 2-1.8 key-management story and expose stored sensitive data.
  - [reference/language-patterns.md](../../../source-code-scanning/reference/language-patterns.md) — per-language storage/serialization/logging sinks for storage-location and unaccounted-output discovery.
  - [reference/manual-review.md](../../../source-code-scanning/reference/manual-review.md) — data-flow tracing from sensitive source → storage/output sink (the core SO2/SO6 evidence move).
- [skills/cryptography/SKILL.md](../../../cryptography/SKILL.md) and [reference/cryptography-principles.md](../../../cryptography/reference/cryptography-principles.md) — judge *strength*: whether storage crypto (3-1.2.1, 3-3.2.1) and channel/transmission crypto (6-2.1, 6-2.2.4, 6-2.3) meet "strong cryptography" (approved algorithms, key lengths, TLS versions, no downgrade 6-2.2.7).

## Assessing each requirement

Every verdict carries `Evidence` per [../core/schema.md](../core/schema.md): `source_file` + `source_lineno` + **verbatim** `quoted_text` (the citation-verifier greps it). A claim with no file:line snippet is not assessable. Cite the *gap location* for NOT_MET (the doc that omits it, or the code path lacking the control). For any `dynamic` / Perform/Test row where dynamic analysis did not run, the only honest status is `REQUIRES_MANUAL_REVIEW`, never MET.

**SO2 — identification & documentation (2-1.x data, 2-2.x resources, 2-3.x functionality)**
- MET: vendor doc enumerates each asset (2-1.1/2-2.1/2-3.1), its storage & locations (2-1.2/2-2.3), retention (2-1.3.x/2-2.4.x), secure-delete method (2-1.4/2-2.5), classification & protection methods (2-1.5/2-1.6/2-2.6/2-2.7), and flows (2-1.7/2-2.8) — **and** static analysis confirms the code handles exactly those assets, no more. External-accessibility doc (2-3.2/2-3.2.1) and sensitive-mode list (2-3.6) present.
- MET (2-1.8.x): a key table records, per key, all nine attributes — type, algorithm, key-management schema, length, generation method & origin, destruction method, and associations to data/resources/functionality — matching the code's actual key objects.
- NOT_MET: code stores/handles a sensitive element (e.g. a `cvv` column, a token in a log) with no corresponding doc entry; or a key in code absent from the 2-1.8 table; or a flow diagram that omits a real output edge.
- Negative-test (static-discovery move): grep the codebase for sensitive sinks and prove a handled asset is **missing** from the inventory — the discrepancy is the finding (SO3/SO6 explicitly require reporting such gaps back to the vendor).

**SO3 — secure storage, retention & deletion (3-1/3-2 data, 3-3/3-4 resources)**
- MET: write call sites store only permissible types (3-1.1/3-3.1); stored sensitive data/resources are protected with strong cryptography at rest (3-1.2.1/3-3.2.1, judged via the cryptography sub-skill); a retention mechanism enforces the documented policy (3-1.3/3-3.3); a secure-delete routine renders data unrecoverable when no longer needed (3-1.4/3-3.4) and volatile/non-persistent copies are zeroized after use (3-2/3-4).
- NOT_MET: prohibited data persisted (e.g. CVV/track after authorization); plaintext or weak-cipher storage; no purge/TTL path; `delete`/SQL `DELETE` that leaves recoverable data with no overwrite/crypto-erase; volatile buffers never cleared.
- Negative-test (dynamic): where the row's method is Perform/Test, attempt to bypass the control — confirm deletion actually renders data unrecoverable (inspect DB/file/cache after purge), or that weak-crypto storage decrypts. If you did not run it, status is `REQUIRES_MANUAL_REVIEW`.

**SO6 — protection of sensitive assets on output**
- 6-1 MET: every output form (cleartext/encrypted/hashed/truncated) is identified, reconciled against the 2-1.7/2-2.8 flows.
- 6-2.1 (data-level encryption) MET: outputs encrypted at the data level use strong, correctly-parameterised crypto (algorithm, mode, key length per cryptography sub-skill).
- 6-2.2 (secure channels) MET: TLS/secure-channel setup uses strong cryptography (6-2.2.4), documents implementation/endpoints/root-of-trust (6-2.2.1–.3), guarantees mutual auth (6-2.2.5), uses per-session unique keys (6-2.2.6), and mitigates downgrade (6-2.2.7 — pinned minimum version, no fallback).
- 6-2.3 MET: any asset capable of transmission is protected with strong transmission crypto.
- NOT_MET: an output path with no encryption/channel control; TLS < 1.2 or weak ciphers permitted; downgrade not blocked; mutual auth absent where required; end-user message exposing sensitive data in cleartext.
- Negative-test (dynamic): attempt a protocol downgrade / observe an output channel for cleartext. Not run ⇒ `REQUIRES_MANUAL_REVIEW`.

## Remediation themes

- **Doc/code drift**: an asset, key, or output edge exists in code but not in the inventory/flow diagram — recommend updating the 2-1.x/2-2.x/2-3.x documentation *and* re-running affected SO3/SO6 requirements.
- **Over-retention / missing secure delete**: add an enforced retention policy and a crypto-erase/overwrite purge routine; zeroize volatile buffers (3-2/3-4).
- **Weak storage or channel crypto**: move to approved algorithms/key lengths; pin TLS ≥ 1.2, disable weak ciphers, block downgrade (6-2.2.7).
- **Silent leaks**: strip sensitive fields from logs, serializers, telemetry, and error messages (6-1/6-2.3).
- **Incomplete 2-1.8 key metadata**: complete the per-key table (all nine attributes) and reconcile with generation/destruction code.

## Anti-Patterns

- Asserting a **dynamic** requirement (Perform/Test — secure-delete actually works, downgrade actually blocked) is MET from a static read of code or docs. If dynamic analysis did not run, the only valid status is `REQUIRES_MANUAL_REVIEW`.
- Treating a documentation claim as proof of implementation — a retention/classification doc satisfies the *documentation* leg only; SO3 storage/deletion still needs the code-side evidence and (where applicable) a dynamic check.
- Treating a crypto library import (`import cryptography`, `Cipher.getInstance`) as proof strong crypto is used *correctly* — verify algorithm, mode, key length, and TLS version against the cryptography sub-skill; an import alone is not a control.
- Marking 6-1 MET from the flow diagram alone without grepping the code for unaccounted output sinks (logs, serializers, telemetry) that the diagram omits.
- Paraphrasing the source into `quoted_text` so the citation appears to match — citation_verify.py greps verbatim within `source_lineno ±5`; a reworded quote quarantines the verdict.

## See also

- [../core/schema.md](../core/schema.md) — Evidence / RequirementVerdict shapes and the status invariants this playbook enforces.
- [../catalog/INDEX.md](../catalog/INDEX.md) — the catalog file and the authoritative Test Requirement texts/IDs for SO2, SO3, SO6.
