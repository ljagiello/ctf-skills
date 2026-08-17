---
name: anti-hallucination-control-stack
description: The 10-layer anti-hallucination control stack for PCI SSS v2.0 gap-assessment — what each layer guarantees, where it is enforced (tool / agent / schema), and why no verdict can claim MET without a verifiable citation. Read this to understand why the pipeline is trustworthy and what to never bypass.
---

# Anti-hallucination control stack

Compliance assessment is a documentation + source-code review with no live target to "prove" most findings. The risk is an assessor asserting MET without evidence. These ten layers make that structurally hard: a verdict cannot claim MET without a real `file:line` that a deterministic tool re-checks, and no applicable requirement can be silently skipped.

| # | Layer | Enforced in | Guarantee |
|---|---|---|---|
| 1 | Deterministic enumeration | `tools/pci-sss/applicability.py` + the pinned catalog | The requirement set comes from the catalog, never model memory — no invented or forgotten requirements. |
| 2 | 100% coverage gate | `tools/pci-sss/coverage_gate.py` | Every applicable Test Requirement gets exactly one verdict; an unassessable one is `REQUIRES_MANUAL_REVIEW`, never dropped. Fails closed (blocks Report). See [coverage-gate.md](coverage-gate.md). |
| 3 | Evidence-bound verdicts | `core/schema.md` invariants + the verdict agent | `MET`/`NOT_MET` require ≥1 `Evidence{file,line,quoted_text}`. |
| 4 | Deterministic citation-verifier | `tools/pci-sss/citation_verify.py` | Greps every quoted snippet at its `file:line ±5`, checks the file sha; a miss quarantines + downgrades. Non-LLM, fails closed. See [citation-verifier.md](citation-verifier.md). |
| 5 | Blind adversarial refutation | the refuter agents (workflow Assess) | N independent refuters see only the evidence package and try to overturn each MET/NOT_MET; majority-refute kills it. See [../agents/refutation-validator.md](../agents/refutation-validator.md). |
| 6 | Dynamic-analysis honesty | `core/schema.md` invariant + the verdict agent | A dynamic requirement with no running instance is `REQUIRES_MANUAL_REVIEW` — never a faked MET. |
| 7 | Negative-evidence applicability | `applicability.py` + the Applicability phase | Excluding a Module/objective requires the search that returned nothing. See [../core/applicability.md](../core/applicability.md). |
| 8 | Catalog fidelity self-test | `tools/pci-sss/validate_catalog.py` + verbatim spot-check | Structural validation + sha-pinned PDF + sampled verbatim check keep the catalog faithful. See [../catalog/INDEX.md](../catalog/INDEX.md). |
| 9 | Append-only evidence | OUTPUT_DIR `findings/<id>/evidence/` | Per-requirement evidence is append-only and reproducible (reuses the coordination output discipline). |
| 10 | Independent blind re-verification | engagement validator (reuse `coordination/reference/validator-role.md`) | Coverage recomputed blind; fails below 1.0. |

## The non-negotiables (never bypass)

- A `MET` or `NOT_MET` without a citation that `citation_verify.py` confirms is downgraded to `REQUIRES_MANUAL_REVIEW`. There is no path to MET that skips the grep.
- A quote is never re-worded to make it match; a framework version is never adjusted to pass; a `test_requirement_id` is never edited to resolve; a quarantined verdict is never un-quarantined.
- A requirement that cannot be honestly evaluated is surfaced as `REQUIRES_MANUAL_REVIEW`, with its reason, in the report's Coverage & Limitations section. It is never silently omitted or upgraded.

## See also
- [coverage-gate.md](coverage-gate.md) · [citation-verifier.md](citation-verifier.md) · [../core/schema.md](../core/schema.md)
