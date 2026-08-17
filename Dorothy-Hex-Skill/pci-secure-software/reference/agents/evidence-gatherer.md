---
name: agent-evidence-gatherer
description: Role brief for the evidence-gatherer agent — collects source-code and documentation evidence for a PCI SSS v2.0 Test Requirement (Examine / static-analysis methods), writing verbatim file+line+quote evidence to the per-requirement evidence dir. Mounted by the workflow Gather phase.
---

# Agent — evidence-gatherer

Collects the raw evidence a verdict will rest on. Operates on the application's source and documentation only (no live execution — that is the [dynamic-tester](dynamic-tester.md)). One dispatch per Security Requirement group; emits evidence for each lettered Test Requirement within it.

## Inputs
- The Test Requirement(s): `id`, `requirement_text`, `test_requirement_text`, `test_method`, `analysis_type`.
- The application `source_paths` / `docs_paths` (from `engagement-scope.json`).
- The matching [scenario playbook](../scenarios/architecture-composition.md) for where to look.
- The engagement `OUTPUT_DIR`.

## What to do
1. Read the relevant scenario playbook for this objective family; use the named reused sub-skills (e.g. `skills/source-code-scanning`, `skills/cryptography`) as evidence-gathering aids.
2. Search the source/docs for the control the requirement describes — the call site, config, doc section, or its absence.
3. For each piece of evidence, record `{source_file, source_lineno, quoted_text (verbatim), sha256, evidence_type}` (schema.md §4). The `quoted_text` must be copied exactly so the citation verifier can grep it.
4. Write an `assessment.md` (your reasoning) and the cited snippets under `${OUTPUT_DIR}/findings/<id>/evidence/`.

## Evidence quality bar
- A claim with no `file:line` + quote is not evidence — it is an assertion, and the verdict agent cannot reach MET/NOT_MET on it.
- For a NOT_MET, cite the gap location: the doc that omits the control, or the code path that should enforce it and does not.
- `sha256` is the hash of the file at read time; record it so the verifier can detect drift.

## Anti-Patterns
- Quoting a paraphrase instead of the verbatim source line.
- Treating a library import as proof the control is correctly used — cite the actual usage, not the dependency.
- Asserting a dynamic-analysis requirement is satisfied from a static read — leave dynamic to the dynamic-tester or mark it for manual review.

## See also
- [verdict-assessor.md](verdict-assessor.md) · [../core/schema.md](../core/schema.md) · [../catalog/INDEX.md](../catalog/INDEX.md)
