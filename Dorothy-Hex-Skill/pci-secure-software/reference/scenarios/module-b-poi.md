---
name: module-b-poi
description: Assessor playbook for finding source and documentation evidence for PCI SSS v2.0 Module B — POI device software objectives B1 (PTS approval), B2 (approved POI functionality, SRED and non-SRED branches, no cleartext account-data output) and B3 (firmware authentication of software/files).
---

# Module B - POI Device Software (B1, B2, B3)

Module B applies only when `pts_poi_device` is true. It requires that the software runs on a PTS-approved POI device (B1), uses approved POI functionality correctly — strong crypto for account data on non-SRED devices, never bypassing SRED on SRED devices, and never emitting cleartext account data (B2) — and is authenticated by the POI firmware before it loads or executes (B3). Much of Module B is rooted in device firmware/hardware behaviour that a source-plus-docs intake cannot observe; flag those rows `REQUIRES_MANUAL_REVIEW` rather than inferring them.

## Where to find evidence
- **PTS / device approval (B1):** docs naming the device model, vendor, and PTS approval number. Globs: `**/{README,SECURITY,DEPLOYMENT,COMPLIANCE,device,hardware}*.md`, `docs/**`, `*.pdf` deployment guides. Patterns: `PTS`, `approval (number|#)`, `POI`, device model strings. The number itself must be confirmed against the live PCI SSC approved-device list — that lookup is manual.
- **POI SDK / firmware API usage (B2, B3):** how the app calls the terminal SDK. Globs: `**/*sdk*`, `**/*poi*`, `**/include/**`, `**/lib*/**`, build manifests (`Makefile`, `CMakeLists.txt`, `*.gradle`, `package.json`). Patterns: vendor SDK headers/symbols, `SREDEncrypt`, `securePinEntry`, `getEncryptedTrack`, `openProtocol`, `OPI`/`OPI2`, key-injection and KSN/DUKPT calls.
- **SRED-related crypto (B2-2):** calls that encrypt account data inside the secure reader. Patterns: `SRED`, `DUKPT`, `KSN`, `BDK`, `deriveKey`, `encryptPAN`, AES/TDES key-setup feeding the reader path. Look for any code that reads the magstripe/PAN *before or instead of* the SRED entry point — that is a bypass.
- **Account-data output paths (B2 cleartext rule):** trace PAN/track/SAD from capture to every sink — display, audio (tone/beep/TTS), logs, files, and network. Globs: `**/*display*`, `**/*print*`, `**/*audio*`, `**/*log*`, `**/*net*|*http*|*socket*`. Patterns: `PAN`, `track2`, `cardNumber`, `printf`/`render`/`play`/`send` on those variables. Any cleartext PAN reaching a sink is a NOT_MET.
- **Open-protocol & RNG of device functions (B2):** `openProtocol`, `OPI`, plus the RNG used for sensitive assets — `random`, `srand`, `Math.random`, `getRandomBytes`, device CSPRNG/SDK RNG handles. Weak/seeded RNG feeding keys or nonces is a gap.
- **Code-signing / load-authentication (B3):** signing manifests and the firmware's verification of the load. Globs: `**/*.sig`, `**/*manifest*`, `**/sign*`, build/release configs. Patterns: `signature`, `verify`, `RSA`/`ECDSA`, `sha256`, `certificate`, firmware-load/secure-boot config keys. Source can show a signing *step*; the firmware *enforcing* it is a device behaviour → manual.

## Reused sub-skills
- `skills/reverse-engineering/SKILL.md` — inspect firmware/binary artifacts, locate signing blocks, and confirm a load-authentication/secure-boot check actually exists in the image (B3); identify SDK symbols when no source is present.
- `skills/authentication/SKILL.md` — reason about how software/files authenticate *to the device* and how the firmware authenticates the load before execution (B3); spot missing or forgeable signature checks.
- `skills/source-code-scanning/SKILL.md` — trace account-data flow on the device to every output sink and find cleartext PAN/SAD leaks and SRED-bypass paths (B2).
- `skills/cryptography/SKILL.md` — judge whether account-data crypto is strong (B2-1) and whether SRED/DUKPT key handling and RNG are sound.

## Assessing each requirement
Every MET/NOT_MET needs ≥1 `Evidence` with `source_file` + `source_lineno` + a verbatim `quoted_text` (see schema §4). NOT_APPLICABLE here means `pts_poi_device:false` → cite the intake answer.

- **B1 — PTS approval.** MET: documentation states the device model and PTS approval number, and you have confirmed that number against the PCI SSC approved-device list. NOT_MET: docs name an unapproved/unlisted device, or no device identification at all (cite the doc that omits it). If the doc asserts approval but you cannot confirm the listing from intake, mark `REQUIRES_MANUAL_REVIEW` — a static doc claim is not proof of listing.
- **B2-1 — non-SRED, strong crypto for account data** (`sred_approved:false`). MET: account-data crypto uses an approved algorithm/key length with sound key management (cite the call + key setup). NOT_MET: weak/home-rolled cipher, hardcoded/static key, or account data persisted/sent in clear. Negative-test (dynamic): attempt to capture account data downstream of the crypto call and confirm it is unreadable; if dynamic analysis did not run, the row is `REQUIRES_MANUAL_REVIEW`, never MET.
- **B2-2 — SRED, do not bypass SRED functions** (`sred_approved:true`). MET: all account-data capture flows through the SRED entry points; no code path reads PAN/track outside SRED. NOT_MET: a path reads or reconstructs account data outside the secure reader (cite the file:line of the bypass). Negative-test: attempt to obtain account data without invoking SRED; not-run ⇒ `REQUIRES_MANUAL_REVIEW`.
- **B2 — no cleartext account-data output.** MET: every display/audio/log/file/network sink receives only masked or encrypted account data (cite the masking at each sink). NOT_MET: any sink emits cleartext PAN/SAD. Negative-test: drive a transaction and observe each sink; static-only ⇒ `REQUIRES_MANUAL_REVIEW`.
- **B3 — firmware authentication of software/files.** MET (to the extent statically provable): a signing/manifest step exists and source/config shows the load is verified before execution; the *firmware enforcement* is confirmed via the firmware artifact (reverse-engineering) or vendor attestation. NOT_MET: code loads/executes files with no signature check, or verification is skippable. Because enforcement lives in firmware, a source+docs intake that lacks the firmware image should mark B3 `REQUIRES_MANUAL_REVIEW`, citing the missing artifact — do not infer enforcement from a signing script alone.

## Remediation themes
- Move off any unlisted/unapproved device, or supply the verifiable PTS approval number and listing reference (B1).
- Replace weak/static account-data crypto and key handling with approved algorithms + proper key management; route all account data through SRED on SRED devices (B2).
- Eliminate cleartext account data at every sink — mask/truncate for display and logs, encrypt for storage and transport (B2).
- Enforce signed-load / secure-boot authentication in firmware and reject unsigned or modified files before execution (B3).

## Anti-Patterns
- Asserting a dynamic/negative requirement (B2-1, B2-2, B2 cleartext) MET from a static read of code or docs — if dynamic analysis did not run, the only honest status is `REQUIRES_MANUAL_REVIEW`.
- Treating a vendor SDK import or a `SREDEncrypt` symbol as proof the control is *used correctly* — presence of an API is not correct, exception-free usage on every account-data path.
- Calling B1 MET because docs say "PTS approved" without confirming the model and approval number against the live PCI SSC approved-device list.
- Inferring B3 firmware enforcement from a build-time signing script — signing the artifact does not prove the firmware verifies and rejects unsigned loads; that needs the firmware image or attestation.
- Marking Module B rows NOT_APPLICABLE without citing `pts_poi_device:false`, or inventing requirement IDs beyond B1, B2-1, B2-2, B3.

## See also
- [../core/schema.md](../core/schema.md) — Evidence/Verdict shapes and the REQUIRES_MANUAL_REVIEW invariants.
- [../catalog/INDEX.md](../catalog/INDEX.md) — the Module B catalog rows and counts.
