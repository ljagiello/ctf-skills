---
name: anti-hallucination-citation-verifier
description: The deterministic citation verifier for PCI SSS v2.0 verdicts — a non-LLM grep gate (tools/pci-sss/citation_verify.py) that opens every cited file:line, confirms the quoted snippet is actually there, checks the file sha, resolves the control id against the pinned catalog, and quarantines + downgrades any verdict that fails. Read this when a MET/NOT_MET verdict must be verified.
---

# Citation verifier (deterministic gate)

The single mechanism that makes "MET" trustworthy. It is **deterministic, non-LLM, no-retry, fail-closed**, adapted from firewall-review's citation-verifier. A verdict that cites evidence which does not actually exist at the stated location cannot survive it.

## What it checks, per verdict

1. **Control resolution** — `control_ref.framework == "PCI_SSS_v2.0"`, `control_ref.version == "2.0"`, and `test_requirement_id` exists in the pinned catalog. A mismatch quarantines.
2. **Status/evidence invariants** (schema.md §3) — `MET`/`NOT_MET` carry ≥1 evidence; `NOT_APPLICABLE` carries ≥1 applicability_evidence.
3. **Quote grep** — for each `Evidence`: the `source_file` exists, its sha256 matches `evidence.sha256`, and the whitespace-normalized `quoted_text` appears within `source_lineno ±5` lines (or anywhere in the file when `source_lineno` is null). A miss on any of these quarantines the verdict.

A quarantined verdict has its `status` rewritten to `REQUIRES_MANUAL_REVIEW`, `citation_verified=false`, `downgraded_from` set to the original status, and is appended to `artifacts/quarantined.json`. `REQUIRES_MANUAL_REVIEW` verdicts with no evidence pass the quote step (nothing to grep) but still get control-resolution + invariant checks.

## Run it

```
python3 tools/pci-sss/citation_verify.py --output-dir <engagement_dir> [--source-root <app_root>]
```
Rewrites each `artifacts/validated/*.json` in place with the verifier state, writes `artifacts/quarantined.json`, and exits non-zero if anything was quarantined.

## Hard rules (for any agent dispatching or repairing around this gate)

- NEVER re-word a `quoted_text` to make it match the source — fix the verdict or downgrade it.
- NEVER adjust `control_ref.version` or `framework` to pass resolution.
- NEVER edit a `test_requirement_id` to make it resolve against the catalog.
- NEVER move a verdict out of `quarantined.json` by hand. Re-assess it and let the verifier pass it.

These exist because an LLM will, given the chance, "helpfully" massage a citation into passing. The verifier is the backstop that guarantees every shipped MET is traceable to an exact line in an exact file.

## See also
- [control-stack.md](control-stack.md) · [../agents/citation-verifier.md](../agents/citation-verifier.md) · [../core/schema.md](../core/schema.md)
