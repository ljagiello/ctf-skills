---
name: module-d-sdk
description: Assessor playbook for finding source, build-artifact, and documentation evidence for PCI SSS v2.0 Module D — SDK objective D1 (SDK Integrity), covering D1-1 (the SDK is designed to mitigate tampering of its execution and compromise of its sensitive assets, including resistance to hooking/reverse-engineering) and D1-2 (the SDK lets an integrating application validate the SDK's integrity and authenticity).
---

# Module D - Software Development Kits (D1)

Module D applies only when the software is delivered as an SDK
(`is_sdk == true`). Objective D1 (SDK Integrity) requires the SDK to be designed
to resist tampering of its execution and compromise of its sensitive assets —
including resistance to hooking and reverse-engineering (D1-1) — and to expose a
mechanism the integrating application can call to validate the SDK's integrity
and authenticity (D1-2). Tamper-resistance of the shipped binary is often only
provable from the built artifact; flag `REQUIRES_MANUAL_REVIEW` wherever source
alone cannot prove the protection holds at runtime. If the software is a
standalone app and not an SDK, every D-row is NOT_APPLICABLE — cite `is_sdk:false`.

## Where to find evidence

- **SDK packaging & signing (D1-1, D1-2):** how the SDK is built, signed, and
  distributed. Globs: build/release configs (`Makefile`, `CMakeLists.txt`,
  `*.gradle`, `build.gradle.kts`, `pom.xml`, `*.podspec`, `*.nuspec`,
  `package.json`, `setup.py`/`pyproject.toml`), CI release pipelines
  (`.github/workflows/*`, `*.yml`), `**/*.sig`, `**/*manifest*`, `MANIFEST.MF`,
  `**/sign*`, `**/codesign*`, `*.p7s`, checksum files (`*.sha256`, `SHASUMS`).
  Patterns: `jarsigner`, `apksigner`, `codesign`, `signtool`, `gpg --sign`,
  `cosign`, `notarytool`, embedded public key / certificate, version + hash
  stamping at build.
- **Integrity self-verification / anti-tamper / anti-debug (D1-1):** code the SDK
  runs on itself at load/runtime. Patterns: self-checksum/CRC/hash of own
  code/resources, `ptrace(PTRACE_TRACEME)`, `isDebuggerConnected`,
  `sysctl(... P_TRACED)`, `IsDebuggerPresent`/`CheckRemoteDebuggerPresent`,
  timing/`rdtsc` debug checks, `AppCheck`/Play Integrity / DeviceCheck /
  attestation calls, jailbreak/root detection, code-signing / `dladdr` /
  `_dyld_image` self-inspection, embedded reference digests compared at startup.
- **Anti-hook / runtime-protection (D1-1):** detection of injected frameworks and
  patched functions. Patterns: scans for `frida`, `xposed`, `substrate`,
  `cydia`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, PLT/GOT or inline-hook
  detection, syscall-prologue checks, integrity checks over loaded modules.
- **Obfuscation (D1-1):** build steps and config that harden the artifact.
  Globs/keys: `proguard-rules.pro`, `R8`/`-dontobfuscate` (a red flag),
  `*dexguard*`, LLVM-obfuscator/`-mllvm` flags, `strip`/`-s` link flags,
  `obfuscator`/`uglify`/`terser` (`mangle`) config, string-encryption helpers.
  Absence of any obfuscation on an SDK guarding sensitive assets is a gap.
- **Integrity/authenticity validation API (D1-2):** the public surface the
  integrator calls. Patterns: exported methods/headers named `verifyIntegrity`,
  `validateSignature`, `checkAuthenticity`, `getSdkChecksum`, `attest*`,
  `isTampered`, a public key/cert the integrator pins, a documented
  manifest+signature the integrator verifies. The API must be reachable from
  *outside* the SDK (exported/public), not an internal-only helper.
- **Integrator documentation (D1-1, D1-2):** README / integration guide / SECURITY
  docs. Globs: `**/{README,SECURITY,INTEGRATION,INSTALL}*.md`, `docs/**`,
  generated API reference. Sections: "verifying the SDK", "integrity check",
  "signature verification", "supply-chain / authenticity", threat model naming
  hooking/RE resistance.

## Reused sub-skills

- [skills/reverse-engineering/SKILL.md](../../../reverse-engineering/SKILL.md) —
  D1-1: confirm anti-tamper / anti-debug / anti-hook and integrity self-checks
  actually exist (and survive) in the built artifact, gauge obfuscation strength,
  and attempt the negative bypass (patch/hook a check and see if it still fires).
- [skills/source-code-scanning/SKILL.md](../../../source-code-scanning/SKILL.md) —
  D1-1/D1-2: locate the self-verification and anti-tamper source, and the public
  integrity/authenticity-validation API exposed to integrators (exported symbols,
  signing wiring, embedded keys/digests).

## Assessing each requirement

For every row, evidence = `source_file:source_lineno` + a **verbatim**
`quoted_text` snippet (schema §4). Tamper/hook/RE resistance is a runtime
property: a row whose protection you could only read statically, but not confirm
holds against an active bypass on the artifact, is `REQUIRES_MANUAL_REVIEW`,
never MET (schema §3 invariants). Build-artifact evidence uses
`evidence_type:build_artifact`.

- **D1-1 (mitigate tampering / asset compromise; resist hooking & RE).** MET (to
  the extent provable): the SDK self-verifies its code/resources, detects
  debug/hook/injection, ships obfuscated, and a reverse-engineering pass on the
  *artifact* confirms the checks are present and not trivially stripped (cite the
  build-artifact finding). NOT_MET: no integrity self-check, no anti-debug/anti-hook,
  unobfuscated SDK guarding sensitive assets, or `-dontobfuscate`/`strip`-disabled
  build (cite the absent control or the disabling flag). Negative move: on the
  built artifact, patch out or hook one protection (e.g. attach a debugger, inject
  Frida, NOP a checksum compare) and confirm the SDK still resists / refuses to
  run. If that bypass attempt did not run, the row is `REQUIRES_MANUAL_REVIEW` —
  source showing a check is not proof the shipped binary enforces it.
- **D1-2 (integrating app can validate SDK integrity/authenticity).** MET: a
  public, documented API or signed-manifest mechanism lets the integrator verify
  the SDK's integrity and authenticity, the verification is cryptographically
  sound (signature/checksum over the real artifact with a pinned key, not a
  self-reported boolean), and the integrator docs show how to call it. NOT_MET: no
  such API, an internal-only helper the integrator cannot reach, or a check the
  SDK can trivially fake (returns a constant / verifies nothing). Negative move:
  exercise the validation API against a tampered SDK copy and confirm it reports
  failure; if not executed, `REQUIRES_MANUAL_REVIEW`.

## Remediation themes

- Sign and notarize the SDK artifact; stamp a version + reference digest at build
  and ship a verifiable manifest the integrator can pin.
- Add runtime self-integrity checks (hash own code/resources against an embedded
  digest) plus anti-debug, anti-hook (Frida/Xposed/`*_INSERT_LIBRARIES`), and
  root/jailbreak detection that fail safe.
- Obfuscate the release build (enable ProGuard/R8/DexGuard, LLVM obfuscation,
  string encryption, symbol stripping); remove any `-dontobfuscate`.
- Expose a public, documented `verifyIntegrity`/`checkAuthenticity` API backed by
  cryptographic signature verification with a pinned key, and document for
  integrators exactly how to validate the SDK before trusting it.

## Anti-Patterns

- Asserting D1-1 or D1-2 MET from a **static** read of source or integrator docs —
  tamper/hook/RE resistance and validation behaviour are runtime properties; if
  the bypass/validation attempt did not run on the artifact, the honest status is
  `REQUIRES_MANUAL_REVIEW`.
- Treating a **library import** or an SDK symbol (a Frida-detection package, a
  signing lib, an `verifyIntegrity` declaration) as proof the control is wired in
  and effective — the call must be reachable on the protected path and survive in
  the shipped binary, with a cited site.
- Claiming D1-2 MET because docs describe an integrity API, without confirming the
  API is exported/public and that it actually fails on a tampered SDK.
- Accepting a self-reported integrity boolean or an unobfuscated check the
  attacker can NOP as "tamper resistance"; signing the artifact at build does not
  prove the runtime enforces or validates it.
- Marking D-rows NOT_APPLICABLE without citing `is_sdk:false`, or inventing
  requirement IDs beyond D1-1 and D1-2.

## See also

- [../core/schema.md](../core/schema.md) — Evidence/Verdict shapes and the REQUIRES_MANUAL_REVIEW invariants.
- [../catalog/INDEX.md](../catalog/INDEX.md) — the Module D catalog rows and counts.
