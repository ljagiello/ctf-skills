---
name: pci-sss-output-discipline
description: The engagement OUTPUT_DIR tree for a PCI SSS v2.0 gap-assessment — where applicability decisions, per-requirement evidence, verdicts, and the report live. Points to the canonical output-discipline rule and adapts the tree for compliance (findings keyed by Test Requirement id).
---

# Output discipline (compliance engagement)

The canonical rule on writing artifacts under an engagement directory rather than anywhere else lives in [`coordination/reference/output-discipline.md`](../../../coordination/reference/output-discipline.md) — follow it. This file adapts the tree for a PCI SSS gap-assessment, where the unit of work is a **Test Requirement** (not a finding-NNN).

```
projects/compliance/outputs/<YYMMDD>_<app>/      # engagement OUTPUT_DIR (under outputs/, gitignored)
├── recon/                       tech-stack.json, source/docs inventory
├── applicability/               <scope_unit>.md (evidence), decisions.json, applicable.jsonl,
│                                not-applicable.jsonl, work-list.json
├── findings/
│   └── <test_requirement_id>/   one dir per Test Requirement, e.g. 5-3.3.1.c/
│       ├── assessment.md        the assessor's reasoning + proposed status
│       └── evidence/            cited snippets / dynamic transcripts (append-only)
├── artifacts/
│   ├── validated/<id>.json          surviving verdicts (any status)
│   ├── false-positives/<id>.json    MET/NOT_MET downgraded to REQUIRES_MANUAL_REVIEW (sole record)
│   ├── quarantined.json             citation-verification failures
│   ├── coverage.json                {applicable, emitted, coverage_ratio, missing_ids}
│   ├── status-rollup.json           per-objective + overall counts, %MET
│   └── compliance-report.json       machine-readable export
├── reports/
│   ├── Compliance-Assessment-Report.pdf
│   ├── compliance-report-source.md
│   ├── build_report.py
│   └── tracker.csv
├── logs/
├── experiments.md               append-only assessment ledger
├── engagement-scope.json
└── engagement-meta.json
```

Verdicts dual-write to `artifacts/validated/` and `artifacts/false-positives/` exactly as the pentest validator does — a downgraded MET/NOT_MET lives only in `false-positives/` and never appears as MET in the report.

## See also
- [gap-report.md](gap-report.md) — the deliverable spec.
- [../anti-hallucination/coverage-gate.md](../anti-hallucination/coverage-gate.md) — why every applicable id must have a verdict here.
