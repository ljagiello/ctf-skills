---
name: pci-sss-gap-report
description: The PCI SSS v2.0 gap-assessment deliverable spec — report sections, the machine-readable compliance-report.json export, the tracker.csv columns, and the mandatory "not an official PCI validation" disclaimer. The ReportLab rendering follows formats/transilience-report-style/compliance-report.md.
---

# Gap report — deliverable spec

The assessment produces three coupled artifacts in `reports/` + `artifacts/`: a Transilience-style PDF, a machine-readable JSON, and a per-requirement CSV tracker. All three carry the disclaimer and the Coverage & Limitations disclosure. The PDF is rendered via the design system in [`formats/transilience-report-style/compliance-report.md`](../../../../formats/transilience-report-style/compliance-report.md).

## Mandatory disclaimer (every artifact)

> This is an automated **readiness gap-analysis** against PCI Secure Software Standard v2.0. It is **NOT an official PCI validation**. The PCI SSS defines no In-Place/Not-in-Place marking scheme; official marking occurs solely in the ROV/AOV templates assessed by a qualified PCI Secure Software Assessor.

## Report sections (PDF + compliance-report-source.md)

1. **Executive Summary** — disclaimer banner; overall counts (MET / NOT_MET / PARTIALLY_MET / NOT_APPLICABLE / REQUIRES_MANUAL_REVIEW); %MET by Security Objective; applicability summary.
2. **Scope & Applicability** — app, source/docs/BOM, running-instance availability, declared assets; a per-unit APPLICABLE/NOT_APPLICABLE table with the (negative-)evidence quote for each decision.
3. **Assessment Results by Objective** — one sub-section per applicable objective, with a per-requirement table: `Req ID | Requirement | Status | Evidence (file:line) | Why | Remediation`.
4. **Coverage & Limitations** — explicit list + counts of every `REQUIRES_MANUAL_REVIEW` (with reason), every dynamic-analysis-not-run item, and every quarantined item (with the failed citation). Known unknowns disclosed, never hidden. States the coverage ratio (must be 1.0 for a COMPLETE report).
5. **Prioritized Remediation Roadmap** — NOT_MET + PARTIALLY_MET ranked (Immediate / Short-term / Medium-term) by objective criticality.
6. **Methodology & Chain-of-Custody** — catalog version + sha; the assessor→refuter→verdict pipeline; the deterministic citation verifier; per-requirement proof dirs; the "no fabricated MET" guarantee.

## `artifacts/compliance-report.json` (machine-readable)

```
{
  "assessment": { app_name, standard:"PCI Secure Software Standard v2.0", catalog_version,
                  catalog_sha256, date, compliance_status:"COMPLETE|INCOMPLETE_coverage",
                  coverage_ratio, disclaimer },
  "applicability": { modules:[...], objectives_applicable:[...],
                     decisions:[{scope_unit, decision, why, evidence:[{file,line,quote,kind}]}] },
  "rollup": { overall:{applicable,MET,NOT_MET,PARTIALLY_MET,NOT_APPLICABLE,REQUIRES_MANUAL_REVIEW,pct_met},
              by_objective:{...} },
  "requirements": [ { req_id, objective, requirement_id, requirement_text, test_requirement_text,
                      test_method, analysis_type, module, status,
                      evidence:[{file,line,quote,polarity}], why, remediation,
                      citation_verified, downgraded_from, votes, refuted_count, proof_dir } ],
  "limitations": { requires_manual_review:[{req_id,reason}], dynamic_not_run:[{req_id}],
                   quarantined:[{req_id,failed_citation}] }
}
```

## `reports/tracker.csv` columns (exact)

```
req_id,objective,requirement_text,status,evidence_file,evidence_line,quoted_evidence,why,remediation,citation_verified
```
One row per applicable Test Requirement. For multi-evidence requirements the primary supporting citation goes in the columns; the full evidence set lives in `compliance-report.json`.

## Gates (a COMPLETE report requires all)
- `coverage.json.coverage_ratio == 1.0` and `missing_ids == []`.
- `citation_verify.py` has run; no MET/NOT_MET row has `citation_verified:false`.
- The PDF carries the disclaimer and a populated Coverage & Limitations section.

## Anti-Patterns
- A MET row in any artifact whose evidence is empty or whose `citation_verified` is false.
- Omitting REQUIRES_MANUAL_REVIEW rows from the report to inflate %MET.
- Rendering a COMPLETE report when coverage < 1.0.

## See also
- [output-discipline.md](output-discipline.md) · [../anti-hallucination/coverage-gate.md](../anti-hallucination/coverage-gate.md) · [../core/schema.md](../core/schema.md)
