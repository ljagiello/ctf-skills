---
name: pci-secure-software-reference-index
description: Reference router for the pci-secure-software skill — links every contract, catalog, anti-hallucination, agent, scenario, and reporting file. Read this to find the right reference for the task at hand.
---

# pci-secure-software — reference index

The transferable knowledge layer for PCI SSS v2.0 readiness gap-assessment. The deterministic engine is in `tools/pci-sss/`; the orchestration is `.claude/workflows/pci-compliance.js`; these files carry the "why", the contracts, and the assessment know-how.

## Core contracts
- [core/schema.md](core/schema.md) — the data contracts: CatalogTestRequirement, AppContext, RequirementVerdict, Evidence, ControlRef, the enums, and the rollup ladder.
- [core/applicability.md](core/applicability.md) — the 7-key AppContext, the evidence each answer requires, and how `applicability.py` filters the catalog.

## Catalog (source of truth)
- [catalog/INDEX.md](catalog/INDEX.md) — per-objective counts, the schema-field legend, how to load the catalog, the fidelity spot-check procedure. The catalog itself is `catalog/pci-sss-v2.0.json`.

## Anti-hallucination
- [anti-hallucination/control-stack.md](anti-hallucination/control-stack.md) — the 10-layer control stack and who owns each.
- [anti-hallucination/coverage-gate.md](anti-hallucination/coverage-gate.md) — the 100% coverage rule and how unassessable rows surface.
- [anti-hallucination/citation-verifier.md](anti-hallucination/citation-verifier.md) — the deterministic grep gate (wraps `citation_verify.py`).

## Agent briefs (workflow roles)
- [agents/evidence-gatherer.md](agents/evidence-gatherer.md) — Examine/static evidence collection.
- [agents/dynamic-tester.md](agents/dynamic-tester.md) — Perform/Test negative testing against a running instance.
- [agents/verdict-assessor.md](agents/verdict-assessor.md) — assigns the RequirementVerdict per Test Requirement.
- [agents/refutation-validator.md](agents/refutation-validator.md) — the blind adversary against every MET/NOT_MET.
- [agents/citation-verifier.md](agents/citation-verifier.md) — dispatch brief for the deterministic gate.

## Assessment playbooks (per objective family)
- [scenarios/architecture-composition.md](scenarios/architecture-composition.md) — SO1.
- [scenarios/sensitive-assets.md](scenarios/sensitive-assets.md) — SO2, SO3, SO6.
- [scenarios/protection-and-modes.md](scenarios/protection-and-modes.md) — SO4, SO5.
- [scenarios/crypto-key-management.md](scenarios/crypto-key-management.md) — SO7, SO8, SO9.
- [scenarios/threats-and-deployment.md](scenarios/threats-and-deployment.md) — SO10, SO11.
- [scenarios/module-a-account-data.md](scenarios/module-a-account-data.md) — Module A.
- [scenarios/module-b-poi.md](scenarios/module-b-poi.md) — Module B.
- [scenarios/module-c-web.md](scenarios/module-c-web.md) — Module C.
- [scenarios/module-d-sdk.md](scenarios/module-d-sdk.md) — Module D.

## Reporting
- [reporting/gap-report.md](reporting/gap-report.md) — the deliverable spec (sections, JSON export, tracker.csv, disclaimer).
- [reporting/output-discipline.md](reporting/output-discipline.md) — the engagement OUTPUT_DIR tree (pointer).

## Versions
- [VERSIONS.md](VERSIONS.md) — every version pin.
