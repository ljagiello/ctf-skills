---
name: anti-hallucination-coverage-gate
description: The 100% coverage rule for PCI SSS v2.0 gap-assessment — every applicable Test Requirement must carry exactly one explicit verdict, an unassessable one is REQUIRES_MANUAL_REVIEW (never dropped), and coverage_gate.py fails closed below 1.0. Read this when asked whether the assessment covered everything.
---

# Coverage gate

Because enumeration is deterministic (the applicable set is computed from the catalog, not guessed), a complete assessment must produce **exactly one verdict for every applicable Test Requirement**. A missing verdict means a requirement was silently skipped — the most dangerous failure in a compliance report, because silence reads as "covered."

## The rule

`coverage_ratio = covered / applicable` where `applicable` = the ids in `applicability/work-list.json` and `covered` = the ids with a verdict in `artifacts/validated/` or `artifacts/false-positives/`.

- `coverage_ratio` must equal **1.0** and `missing_ids` must be empty for a report to be `COMPLETE`.
- `REQUIRES_MANUAL_REVIEW` **counts as covered** — but every such row is listed, with its reason, in the report's Coverage & Limitations section.
- The gate is stricter than the pentest engagement-validator default (0.80) precisely because the requirement set here is not discovered heuristically — it is known exactly.

## Run it

```
python3 tools/pci-sss/coverage_gate.py --output-dir <engagement_dir>
```
Writes `artifacts/coverage.json` `{applicable, emitted, covered, coverage_ratio, missing_ids, extra_ids, complete}` and exits non-zero unless complete. The Report phase reads `coverage.json` and refuses to emit a `COMPLETE` report when `missing_ids` is non-empty.

## What "unassessable" maps to

| Situation | Status |
|---|---|
| Dynamic analysis required, no running instance | `REQUIRES_MANUAL_REVIEW` |
| Evidence ambiguous / not independently corroborated | `REQUIRES_MANUAL_REVIEW` |
| Citation could not be verified by `citation_verify.py` | downgraded to `REQUIRES_MANUAL_REVIEW` (quarantined) |
| Requirement needs a firmware/binary artifact not in scope (typical Module B/D) | `REQUIRES_MANUAL_REVIEW` |
| Module/objective excluded by the AppContext | `NOT_APPLICABLE` (with negative evidence) — not in the applicable set, so not counted against coverage |

## Anti-Patterns
- Reporting a high `%MET` while quietly omitting requirements that were hard to evaluate — they must appear as `REQUIRES_MANUAL_REVIEW`, not vanish.
- Capping the work-list (e.g. `max_requirements`) without logging exactly which requirements were deferred.
- Treating `coverage_ratio < 1.0` as a soft warning — it blocks a `COMPLETE` report.

## See also
- [control-stack.md](control-stack.md) · [citation-verifier.md](citation-verifier.md) · [../reporting/gap-report.md](../reporting/gap-report.md)
