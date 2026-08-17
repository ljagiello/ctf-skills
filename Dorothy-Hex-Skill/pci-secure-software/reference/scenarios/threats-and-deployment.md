---
name: threats-and-deployment
description: Assessor playbook for PCI SSS v2.0 Security Objective 10 (designing/updating against known threats and vulnerabilities across programming languages, third-party elements, and protocols, plus unsupported dependencies) and Security Objective 11 (secure release/delivery, prompt security updates, secure implementation guidance, integrity verification, version-info mechanism, and forced change of default credentials).
---

# Threats, Vulnerabilities, Secure Deployment & Management (SO10, SO11)

This family asks whether the software is designed and maintained with awareness of known security issues in its languages, third-party elements, protocols, and dependencies (SO10), and whether its release, update, integrity-verification, guidance, version-reporting, and default-credential handling keep it secure through deployment and operation (SO11). Most rows are `Examine`/documentation-only, but the two `negative`-polarity rows (11-4.b, 11-6.b) are **dynamic** and cannot be MET from documents alone.

## Where to find evidence

- **Dependency manifests / versions (10-1.1.2, 10-2):** `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `pom.xml`, `build.gradle`, `go.mod`/`go.sum`, `Gemfile.lock`, `composer.lock`, `Cargo.lock`, `*.csproj`/`packages.config`, vendored `vendor/` trees, SBOMs (`*.spdx.json`, CycloneDX). Cross-reference the SO1 software-composition inventory.
- **Languages (10-1.1.1):** file extensions and toolchain config establish the language set; look for design docs or coding-standard files that name language-specific hazards (memory safety, deserialization, format strings).
- **Protocols (10-1.1.3):** grep for `http://`, `ftp://`, `telnet`, `smtp`, `snmp`, TLS version pins (`TLSv1`, `SSLv3`, `ssl_version`, `minimum_version`), cipher lists, and custom wire formats.
- **EOL / unsupported components (10-2):** compare manifest versions against vendor EOL data (endoflife.date, distro EOL, runtime EOL such as Python 3.7-/Node 14-); look for a documented exception/risk-acceptance register.
- **Vuln-management & patch process (10-1.b, 11-2):** `SECURITY.md`, vulnerability-management / SDLC / patch-SLA policy docs, advisory/changelog/CHANGELOG feeds, ticketing references.
- **Release & delivery (11-1):** CI/CD pipeline config (`.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`), signing keys, release scripts, artifact-repository config.
- **Integrity verification (11-4):** installer/updater code calling signature/hash verification — `verify`, `signature`, `gpg`/`cosign`/`minisign`, `sha256`/`checksum`, `X509`, code-signing; the update endpoint and how the downloaded artifact is checked before apply.
- **Installer/config defaults & default-credential change (11-6):** installer scripts, seed/migration data, `config/*.yml|.ini|.env.example`, `first_run`/`must_change_password`/`password_expired`/`force_reset` flags, admin-bootstrap code.
- **Version mechanism (11-5):** `VERSION` file, `--version`/`-v` CLI handler, `/version` or `/about` route, `version` field in API responses or build metadata.
- **Secure implementation guide (11-3.x):** customer-facing install/integrate/configure/operate/update/remove docs and the documented version-reporting procedure.

## Reused sub-skills

- `skills/source-code-scanning/SKILL.md` — dependency CVE scanning (`reference/dependency-cve-scanning.md`), outdated/unsupported component detection, language-specific hazards (`reference/language-patterns.md`), and insecure-protocol usage; the primary engine for 10-1.1.1/.2/.3 and 10-2.
- `skills/cve-risk-score/SKILL.md` — authoritative CVSS/severity/CWE for any CVE surfaced in a dependency, to weigh whether a known issue is "accounted for" (10-1.1.2, 10-2).
- `skills/cve-poc-generator/SKILL.md` — vulnerability research and a safe PoC when a component CVE must be shown reachable/mitigated for 10-1.1 evidence.
- `skills/reconnaissance/SKILL.md` — version-surface and default-credential checks (the dynamic side of 11-5 and 11-6.b); endpoint/version banner discovery.

## Assessing each requirement

Cite every claim as `source_file:lineno` with a **verbatim** `quoted_text` (schema §4). A negative finding (`NOT_MET`) still needs evidence — the doc that omits the control or the code path that lacks it.

- **10-1 / 10-1.1 (design + update for known issues):** MET = vendor doc shows threats/vulns were factored into design **and** a process re-evaluates them on every update. NOT_MET = no such doc, or it is purely aspirational with no language/element/protocol specifics.
- **10-1.1.1 (programming languages):** MET = doc names the languages and the class of issues each invites, corroborated by static analysis (`10-1.1.1.b`). NOT_MET = generic "we write secure code" with no language-specific awareness.
- **10-1.1.2 (third-party elements):** MET = inventory from SO1 + evidence each element was screened for known issues; SCA shows no unaddressed high/critical CVEs, or each is risk-accepted. NOT_MET = unscreened deps or unaddressed known-vulnerable versions.
- **10-1.1.3 (protocols):** MET = utilized protocols enumerated and screened (no plaintext/legacy TLS without justification). NOT_MET = insecure protocol in code with no documented rationale.
- **10-2 (unsupported dependencies):** MET = no EOL/unsupported deps, **or** each is documented with a demonstrable risk-mitigation/transition plan (`10-2.b`) that static analysis confirms is effective (`10-2.c`). NOT_MET = silent EOL component with no register.
- **11-1 (secure release/delivery):** MET = documented release process that preserves integrity (signed artifacts, controlled pipeline). NOT_MET = ad-hoc, unsigned distribution.
- **11-2 (prompt security updates):** MET = process with a stated SLA/mechanism to push security fixes to all affected customers. NOT_MET = no defined timeline or distribution path.
- **11-3 / 11-3.1–11-3.7 (secure implementation guidance):** MET = current guidance covers each procedure (install, integrate, configure, operate, update, remove, and version-reporting) clearly; `11-3.b` requires the assessor to **perform** each procedure following the guide and confirm accuracy. NOT_MET = missing procedure or steps that don't reproduce a secure result.
- **11-4 (integrity verification at install + update):** `11-4.a` documentation MET = a signature/hash mechanism is described and present in installer/updater code. `11-4.b` is **dynamic + negative** — you must actually **attempt to bypass/circumvent** verification (tamper the artifact, strip/forge the signature, downgrade) and confirm it is rejected. If dynamic testing did not run, the verdict is `REQUIRES_MANUAL_REVIEW`, never MET.
- **11-5 (version-info mechanism):** MET = a working mechanism returns the version (CLI/route/file), reconciled with 11-3.7. NOT_MET = no programmatic way to obtain the version.
- **11-6 (forced default-credential change):** `11-6.a` static MET = code forces change of all default auth values before business use (a `must_change_password`/first-run gate that blocks use). `11-6.b` is **dynamic + negative** — attempt to use the shipped defaults to reach sensitive assets; MET only if every default is rejected/forced-changed. No dynamic run ⇒ `REQUIRES_MANUAL_REVIEW`.

**Negative-test discipline:** for 11-4.b and 11-6.b the control is proven by a *failed* attack, captured as a `dynamic_observation` evidence item. A static reading of the updater or the bootstrap code supports `11-4.a`/`11-6.a` only — it can never satisfy the dynamic sibling.

## Remediation themes

- Unscreened or EOL dependencies → add SCA to CI, pin to supported versions, and maintain an exception register with risk acceptance and transition dates (10-1.1.2, 10-2).
- Insecure/legacy protocols with no rationale → remove or document the compensating control (10-1.1.3).
- Unsigned releases or no integrity check on update → sign artifacts and verify signature/hash before applying (11-1, 11-4).
- No patch SLA / no push channel → define and document a security-update process reaching all customers (11-2).
- Shipped defaults usable in production → force credential change on first use and reject defaults at the auth gate (11-6).
- Implementation guide missing a lifecycle step → author the install/integrate/configure/operate/update/remove/version procedures and re-test by following them (11-3.x).

## Anti-Patterns

- Marking 11-4.b or 11-6.b **MET** from a static reading of the updater/bootstrap code or the implementation guide — these are dynamic, negative-polarity rows that require an actual bypass attempt; without a dynamic run the only honest status is `REQUIRES_MANUAL_REVIEW`.
- Treating a library **import or a signing-library dependency** as proof the control is used correctly — verify the verification result is checked and enforced, not merely that the function is called or the package is present.
- Asserting 10-1.1.2/10-2 MET because a manifest lists a version, without checking it against EOL data and CVE feeds (use `cve-risk-score`/`source-code-scanning`).
- Inventing 11-3 sub-IDs beyond the catalog's 11-3.1–11-3.7 range, or paraphrasing requirement text instead of quoting it verbatim from the source file.
- Claiming a documented process is effective for 10-2.c without the static analysis that confirms the mitigation actually constrains the unsupported dependency.

## See also

- [../core/schema.md](../core/schema.md) — verdict, evidence, and citation contracts these assessments emit.
- [../catalog/INDEX.md](../catalog/INDEX.md) — the pinned catalog and Test Requirement counts for SO10/SO11.
