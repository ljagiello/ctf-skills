---
name: pci-secure-software-versions
description: Single source of truth for every version pin in the pci-secure-software skill — the standard, the catalog, the source PDF hash, and the tool versions. Version drift is a citation-verifier quarantine reason.
---

# Version pins

The framework version is load-bearing. A verdict that cites a control under the wrong version is a quarantine event, never a silent pass.

| Component | Pin | Notes |
|---|---|---|
| Standard | **PCI Secure Software Standard v2.0** | January 2026 major revision. `ControlRef.version` = `"2.0"`, `ControlRef.framework` = `"PCI_SSS_v2.0"`. |
| Source document | `PCI-Secure-Software-Standard-v2.0.pdf` | sha256 `7c71af6db6ae5bd2d4aa8117471cef0fbb4ff1b9dde91ed0eee06bfb7b879c40` (pinned in the catalog `meta.source_sha256`). |
| Catalog | `catalog_schema_version` `1.0.0` | `reference/catalog/pci-sss-v2.0.json`. Page offset: PDF page = printed page + 4 (document body). |
| Tooling | `tools/pci-sss/` v1 | `validate_catalog.py`, `applicability.py`, `citation_verify.py`, `aggregate.py`, `coverage_gate.py`, `build_catalog.py`. |
| Workflow | `pci-compliance` | `.claude/workflows/pci-compliance.js`. |

## Related PCI publications (not pinned here, examined at assessment time)
- PCI Secure Software Standard — Sensitive Asset Identification (companion, mandatory for scoping).
- PCI Secure Software Program Guide; PCI Secure Software Technical FAQs.
- PCI Data Security Standard (latest) — referenced by Module A (account data).
- ROV / AOV Templates — where official marking occurs (out of scope for this automated tool).

## Pitfalls
- PCI SSS v2.0 numbering (`SO-req.letter`, e.g. `5-3.3.1.c`) is distinct from PCI DSS numbering (`Req 6.2.x`). Do not cross-cite.
- The standard defines no marking scheme — any "In Place / Not in Place" language belongs to the ROV/AOV, not to a PCI SSS verdict. Our statuses are gap-analysis labels.
- Module A defers to the *latest* PCI DSS for SAD/PAN handling — cite the PCI DSS version current at assessment time, not a frozen one.

## See also
- [INDEX.md](INDEX.md) — the reference router.
- [catalog/INDEX.md](catalog/INDEX.md) — the catalog this version pins.
