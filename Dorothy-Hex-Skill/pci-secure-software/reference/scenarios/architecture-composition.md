---
name: architecture-composition
description: Assessor playbook for PCI SSS v2.0 Security Objective 1 — architecture documentation (1-1, 1-1.1), software bill-of-materials/composition (1-2), minimal composition incl. third-party elements (1-3, 1-3.1), supply-chain provenance (1-4) and versioning/wildcard schema (1-5, 1-5.1).
---

# Architecture, Composition & Versioning (SO1)

SO1 requires the vendor to document the software's architecture and its security-relevant aspects, declare an accurate bill of materials for every dependency, keep the composition minimal (including third-party elements), record provenance for supply-chain tracking, and publish a versioning (and wildcarding) schema. This family is overwhelmingly **documentation-only** evidence; 1-3.b is the one **static** row where you corroborate the claimed minimal composition against the actual code/build.

## Where to find evidence

- **Architecture docs (1-1, 1-1.1):** `**/{ARCHITECTURE,DESIGN,SECURITY}*.{md,adoc,pdf,docx}`, `docs/**`, `README*`, `/design/**`, threat models, data-flow/trust-boundary diagrams. For 1-1.1 specifically look for sections naming sensitive-asset stores, crypto boundaries, auth/session flow, and where account data transits.
- **Bill of materials (1-2):** manifests + lockfiles — `package.json` + `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml`, `requirements*.txt`/`Pipfile.lock`/`poetry.lock`, `pom.xml`/`build.gradle`, `go.mod`/`go.sum`, `Gemfile.lock`, `composer.lock`, `Cargo.lock`. SBOM artifacts: `*.cdx.json`/`bom.json` (CycloneDX), `*.spdx`/`*.spdx.json`. Hardware deps: BOM spreadsheets, datasheets, HSM/PTS-POI references.
- **Minimal composition (1-3, 1-3.1):** compare the declared BOM against what is actually pulled in. Build/CI config that strips dev/test deps for prod: `Dockerfile` (multi-stage, `--production`/`--omit=dev`), `.dockerignore`, `npm ci --omit=dev`, `mvn -P`, `go build` tags, tree-shaking config. Flag unused/transitive-only packages and bundled binaries not in the BOM.
- **Provenance (1-4):** package origin/integrity records — lockfile `resolved`/`integrity` hashes, `go.sum` checksums, vendored-dependency notes, signed-commit/SLSA/in-toto attestation files, `*.intoto.jsonl`, registry/source URLs, supplier names, license files.
- **Versioning schema (1-5, 1-5.1):** `VERSION`, `version` keys in manifests, tags (`git tag`), `CHANGELOG*`/release notes, a documented SemVer/scheme doc. For 1-5.1 search release/version docs for **wildcard** notation (`1.2.*`, `~`, `^`, `x`) and a written rule that wildcards apply only to non-security-impacting changes.

## Reused sub-skills

- [skills/source-code-scanning/reference/dependency-cve-scanning.md](../../../source-code-scanning/reference/dependency-cve-scanning.md) — parses manifests/lockfiles and SBOMs to build the dependency inventory and enumerate third-party elements; the BOM-vs-actual diff for 1-2 / 1-3 / 1-3.1.
- [skills/source-code-scanning/SKILL.md](../../../source-code-scanning/SKILL.md) — overall source/dependency review entry point (vendored binaries, transitive deps, license/origin signals for 1-4).
- [skills/cve-risk-score/SKILL.md](../../../cve-risk-score/SKILL.md) — known-vuln context for any listed component (informs whether minimal-composition / provenance gaps carry real risk; not itself a SO1 verdict).
- [skills/cve-poc-generator/SKILL.md](../../../cve-poc-generator/SKILL.md) — deeper exploit/advisory context for a flagged component when a remediation theme needs risk weight.

## Assessing each requirement

Map every verdict to **file:line + verbatim quoted_text** per the `Evidence` shape in schema.md. MET and NOT_MET both require ≥1 evidence (a NOT_MET cites the doc that omits it or the manifest that lacks the record).

- **1-1 / 1-1.1 (architecture documented):** MET = an architecture doc exists and, for 1-1.1, explicitly describes the security-relevant aspects protecting sensitive assets (cite the section). NOT_MET = no architecture doc, or one with no security/sensitive-asset content. Documentation-only — no bypass move.
- **1-2 (BOM):** MET = a BOM enumerating software **and** hardware dependencies that reconciles with the manifests/lockfiles (use source-code-scanning to confirm coverage). NOT_MET = no BOM, or BOM omits dependencies the lockfile/SBOM proves are present (cite the missing entry).
- **1-3 / 1-3.1 (minimal composition, incl. third-party):** 1-3.a/1-3.c are documentation; **1-3.b is static** — corroborate the "only what is required" claim by inspecting the build (prod prune, multi-stage Docker, removed dev deps) and listing components present but unjustified. MET = build evidence shows composition restricted and third-party elements justified. NOT_MET = unused/unjustified packages or bundled binaries not in the BOM (cite the line). Negative-test move (only because 1-3.b runs static): try to demonstrate a non-required element actually ships in the production artifact — if you can show a dev/test/unused dependency in the built image or bundle, that refutes a documented "minimal" claim.
- **1-4 (provenance):** MET = documented origin/supplier/integrity for components enabling supply-chain tracking (lockfile integrity hashes, `go.sum`, attestations). NOT_MET = no provenance, or claims unbacked by any integrity/source record.
- **1-5 / 1-5.1 (versioning / wildcards):** MET = a documented versioning schema in accordance with the Program; if wildcards are used, 1-5.1 requires an explicit wildcarding schema limited to non-security-impacting changes. NOT_MET = no schema, or wildcards in use (seen in manifests) with no governing doc. NOT_APPLICABLE for 1-5.1 only if no wildcards are used — cite the manifest scan that found none (applicability_evidence).

All SO1 rows here are `polarity: positive`. There are no `dynamic` rows in this family, so do **not** force a dynamic verdict; documentation-only and static rows are assessed as above, and any row you could not corroborate is `REQUIRES_MANUAL_REVIEW`, never an assumed MET.

## Remediation themes

- BOM absent or hand-maintained and drifting — recommend generating an SBOM (CycloneDX/SPDX) from the lockfile in CI so 1-2 stays reconciled.
- Architecture doc lacks a security-relevant section — recommend a dedicated sensitive-asset / trust-boundary section to satisfy 1-1.1.
- Dev/test/unused dependencies shipped to production — recommend multi-stage builds and prod-only installs to satisfy 1-3.
- No integrity/provenance records — recommend pinning with hashes and retaining build attestations for 1-4.
- Wildcards in manifests without a governing doc — recommend documenting the wildcarding schema and constraining it to non-security-impacting changes for 1-5.1.

## Anti-Patterns

- Asserting **1-3 MET** from the documentation alone — 1-3.b is static; a "minimal composition" claim in a doc is not proof until the built artifact/build config is inspected. State MET without the static corroboration and it is over-claiming.
- Treating a library appearing in a manifest as proof the related control is correctly used — an import/dependency listing is composition evidence, not control-correctness evidence (that belongs to other Security Objectives).
- Counting a generated SBOM as automatically MET for 1-2 without reconciling it against hardware dependencies and the actual lockfile — an incomplete BOM is NOT_MET, not MET.
- Marking 1-5.1 NOT_APPLICABLE without scanning manifests for wildcard notation — absence must be evidenced (applicability_evidence), not assumed.
- Paraphrasing a doc/manifest line to make it read as compliant — `quoted_text` must be verbatim; rewording to fit is a citation quarantine, not a pass.

## See also
- [../core/schema.md](../core/schema.md) — Evidence / RequirementVerdict shapes and the MET/NOT_MET/REQUIRES_MANUAL_REVIEW invariants.
- [../catalog/INDEX.md](../catalog/INDEX.md) — the SO1 catalog rows (1-1 … 1-5.1) and their analysis types.
