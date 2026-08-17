---
name: module-a-account-data
description: Assessor playbook for PCI SSS v2.0 Module A Security Objective A1 (Securing Account Data) — how to find source-code and documentation evidence that SAD is handled per PCI DSS (A1-1.x) and PAN is handled per PCI DSS (A1-2.x), and which repo sub-skills to reuse as evidence aids.
---

# Module A - Account Data Protection (A1)

Module A applies only when `account_data` is true (the software stores, processes, or transmits PAN and/or SAD). Objective A1 requires that **SAD is handled in accordance with PCI DSS** (A1-1.x) and **PAN is handled in accordance with PCI DSS** (A1-2.x): SAD must not be retained after authorization, PAN at rest must be rendered unreadable (encryption / truncation / tokenization / hashing) and masked on display, and the applicable controls are whatever the *latest* PCI DSS version mandates for the discovered SAD/PAN uses.

## Where to find evidence

- **Card-data handling modules** — globs: `**/*pay*`, `**/*card*`, `**/*pan*`, `**/*checkout*`, `**/*authoriz*`, `**/payment/**`, `**/billing/**`. These are the entry points for every A1 search.
- **PAN at rest / in flight** — grep for PAN patterns: `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b` and the generic `\b[3-6][0-9]{12,18}\b`. Find the column/field the value lands in: `pan`, `card_number`, `cc_num`, `account_number`.
- **PAN masking / truncation** — code that emits PAN to UI/logs/receipts: `mask`, `last4`, `lastFour`, `substr(`, `slice(-4`, `***`, `BIN`, `firstSix`. Confirm only the first six / last four are exposed.
- **PAN encryption / tokenization** — crypto over the card field: `encrypt(`, `AES`, `KMS`, `Vault`, `tokenize`, `format-preserving`, `hash`, `HMAC`. Verify strong crypto, not encoding (reject `base64`, `rot13`, custom XOR).
- **SAD (prohibited post-auth)** — track data, CVV, PIN block. Grep `track1`, `track2`, `\b%B`, `;[0-9]{12,19}=`, `cvv`, `cvv2`, `cvc`, `cid`, `cav2`, `pin_block`, `pinblock`, `dukpt`. Then locate the **post-authorization deletion**: zeroization / `del`/`unset`/overwrite right after the auth response.
- **Key management for card data** — where the PAN encryption key lives: `key`, `kek`, `dek`, `keystore`, `HSM`, env vars, `.pem`. A hard-coded key fails A1-2.
- **Documentation** — the vendor data-flow / data-retention / key-management sections, the "how SAD/PAN is managed" statement (the anchor for A1-1.a / A1-2.a), and the mapping of the app's SAD/PAN uses to the latest PCI DSS requirements (A1-1.b / A1-2.b).
- **Latest PCI DSS** — for each discovered SAD/PAN use, look up the current PCI DSS requirement that governs it (e.g. DSS Req 3 for storage/retention) to set the bar A1 measures against.

## Reused sub-skills

- [skills/source-code-scanning/SKILL.md](../../../source-code-scanning/SKILL.md) — drives the PAN/SAD pattern sweep, finds track-data/CVV/PIN-block handling, and locates masking/truncation/deletion logic; see [reference/secrets-detection.md](../../../source-code-scanning/reference/secrets-detection.md) for hard-coded-key and embedded-PAN hunting.
- [skills/cryptography/SKILL.md](../../../cryptography/SKILL.md) — judges whether PAN encryption / truncation / tokenization is cryptographically strong (algorithm, mode, key length) rather than reversible encoding; see [reference/cryptography-principles.md](../../../cryptography/reference/cryptography-principles.md).

## Assessing each requirement

Map every verdict to `source_file` + `source_lineno` + a **verbatim** `quoted_text` (the citation-verifier greps it; never re-word a snippet to make it match). MET/NOT_MET both require ≥1 evidence — a NOT_MET cites the gap location (the code path lacking the control or the doc that omits it).

**A1-1.a / A1-2.a (Examine docs — documentation-only).** MET = vendor doc explicitly states how SAD / PAN is managed, consistent with PCI DSS, cross-referencing Security Objective 2. NOT_MET = no such statement, or it contradicts the code. Evidence type `documentation`.

**A1-1.b / A1-2.b (Examine latest PCI DSS — documentation-only).** MET = the assessment identifies, against the *current* PCI DSS, exactly which requirements apply to the app's discovered SAD/PAN uses. NOT_MET = uses found in code with no mapping to applicable DSS requirements. Cite the doc/mapping artifact.

**A1-1.c / A1-2.c (Perform static and/or dynamic — `static-and-or-dynamic`).** This is the dynamic-capable pair. MET = static (and dynamic where a running instance exists) analysis confirms the code matches the documented handling: **SAD** is never persisted/logged and is zeroized post-auth; **PAN** at rest is rendered unreadable by strong crypto/truncation/tokenization and is masked on output. NOT_MET = SAD found in a store/log/receipt after auth, or PAN stored cleartext / weakly "encrypted" / shown in full. **Negative-test move:** drive a transaction (or unit-exercise the path) and inspect the DB row, log file, and receipt for raw track2/CVV/PIN and for full PAN; attempt to retrieve the stored PAN and show it is unreadable. If no running instance and dynamic did not run, the row is `REQUIRES_MANUAL_REVIEW`, never MET (schema status invariant for dynamic rows).

## Remediation themes

- **SAD retained post-auth** — remove the field from persistence/logs; zeroize the buffer immediately after the authorization response; add a regression test asserting absence.
- **PAN stored cleartext or weakly protected** — render unreadable with strong, keyed crypto, truncation, or tokenization; rotate keys out of source into an HSM/KMS/keystore.
- **Full PAN on display/logs/receipts** — centralize a mask helper exposing at most first-six / last-four; route all PAN output through it.
- **No DSS mapping** — produce a data-flow that ties each SAD/PAN use to the governing latest-PCI-DSS requirement (feeds A1-x.b).

## Anti-Patterns

- Marking A1-1.c / A1-2.c **MET** from a static read of the vendor doc alone — these rows are dynamic-capable; without the running-instance test of the actual DB row / log / receipt the only honest status is `REQUIRES_MANUAL_REVIEW`.
- Treating a crypto-library import (`import AES`, `require('crypto')`) as proof PAN is encrypted — the import may be unused, mis-keyed, or applied to the wrong field; trace the PAN value to the call and back.
- Declaring "no SAD" because the operator said so — Module A applicability and A1 alike demand the negative-evidence grep (track/CVV/PIN patterns returning nothing) recorded with the exact pattern.
- Asserting PAN is "rendered unreadable" when the code only Base64/hex-encodes or obfuscates it — encoding is reversible and is NOT_MET.
- Inventing requirement IDs — A1 has exactly A1-1.a/b/c and A1-2.a/b/c; do not cite an A1-3 or a numbered DSS row as if it were an SSS Test Requirement.

## See also

- [../core/schema.md](../core/schema.md) — the verdict, evidence, and status-invariant contracts.
- [../catalog/INDEX.md](../catalog/INDEX.md) — the catalog the A1 rows live in (`parts/module-a.json`).
