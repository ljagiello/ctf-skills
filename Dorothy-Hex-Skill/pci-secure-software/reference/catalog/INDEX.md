---
name: pci-sss-catalog-index
description: How to read and load the pinned PCI SSS v2.0 Test Requirement catalog (pci-sss-v2.0.json) — the per-objective structure, the schema-field legend, the deterministic loader, and the fidelity controls (validate_catalog.py + the verbatim spot-check) that keep it faithful to the source PDF.
---

# PCI SSS v2.0 catalog

`pci-sss-v2.0.json` is the **deterministic source of truth** for the assessment. The requirement set is loaded from here and filtered by `tools/pci-sss/applicability.py` — it is never generated from model memory. One JSON object: `{ "meta": {...}, "test_requirements": [ ... ] }`, one array entry per **lettered Test Requirement** (the atomic testable unit). Parent Security Requirements are reconstructed by grouping on `requirement_id`.

The authoritative counts live in `meta` (`test_requirement_count`, `objectives`). Read them with:
`python3 -c "import json;m=json.load(open('skills/pci-secure-software/reference/catalog/pci-sss-v2.0.json'))['meta'];print(m['test_requirement_count'], m['objectives'])"`.

## Structure (Security Objectives)

| Module | Objectives | Title family |
|---|---|---|
| core | 1–11 | 1 Architecture/Composition/Versioning · 2 Sensitive Asset Identification · 3 Storage & Retention · 4 Sensitive Modes of Operation* · 5 Protection Mechanisms · 6 Asset Output · 7 Random Numbers* · 8 Key Management · 9 Cryptography · 10 Threats & Vulnerabilities · 11 Secure Deployment & Management |
| A | A1 | Securing Account Data (applies when `account_data`) |
| B | B1, B2, B3 | PTS Approval · Approved POI Functionality (SRED branch) · Authentication (applies when `pts_poi_device`) |
| C | C1, C2, C3, C4 | HTTP Headers · Input Protection · Session Management · User Authentication (applies when `public_network_interface`) |
| D | D1 | SDK Integrity (applies when `is_sdk`) |

\* SO 4 is conditional on `sensitive_mode`; SO 7 on `random_for_sensitive_assets`. See [../core/applicability.md](../core/applicability.md).

## Schema-field legend

Each entry's fields are defined in [../core/schema.md](../core/schema.md) §1. Quick legend: `id` (atomic lettered, e.g. `5-3.3.1.c`) · `module`/`objective`/`objective_title` · `requirement_id`+`requirement_text` (the parent) · `test_requirement_text` (the citation anchor) · `test_method` (Examine/Interview/Observe/Perform/Test/Verify) · `analysis_type` (documentation-only/static/dynamic/static-and-or-dynamic/research) · `polarity` · `applicability` (the AST) · `cross_refs` · `guidance` · `printed_page`/`pdf_page`.

## How to load (the applicable set)

```
python3 tools/pci-sss/applicability.py --context '{...7 booleans...}' --out-dir <engagement_dir> [--running-instance]
```
→ writes `<engagement_dir>/applicability/{applicable.jsonl, not-applicable.jsonl, work-list.json}`. The workflow Assess phase iterates `applicable.jsonl`.

## Fidelity controls (how the catalog stays faithful to the PDF)

1. **Structural validator** — `python3 tools/pci-sss/validate_catalog.py` fails closed on: id regex + uniqueness, enum closure, `test_method` first-word agreement, cross-ref resolution, applicability grammar/key closure, per-objective counts, page-range provenance, negative-polarity consistency, contiguous `.a/.b/.c` lettering per requirement, and the pinned PDF sha256. Run it after every catalog edit.
2. **One-time verbatim spot-check** — sample ≥1 Test Requirement per objective (≥21 rows total), `Read` its `pdf_page` from `PCI-Secure-Software-Standard-v2.0.pdf`, and assert `test_requirement_text` appears verbatim on that page. A mismatch is fixed in the catalog, never in the assertion. This bootstraps provenance; thereafter `citation_verify.py` enforces ongoing evidence fidelity.

## Rebuilding

The catalog is assembled by `tools/pci-sss/build_catalog.py` from per-objective `parts/*.json` (one per Security Objective and Module B/C/D) produced by the transcription workflow `tools/pci-sss/build_catalog_workflow.js`, then validated. `parts/` is intermediate (gitignored); the merged `pci-sss-v2.0.json` is committed.

## See also
- [../core/schema.md](../core/schema.md) — the entry contract.
- [../core/applicability.md](../core/applicability.md) — the applicability vocabulary.
- [../INDEX.md](../INDEX.md) — the reference router.
