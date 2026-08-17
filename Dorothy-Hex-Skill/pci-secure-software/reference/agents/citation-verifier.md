---
name: agent-citation-verifier
description: Dispatch brief for the citation-verifier step — runs the deterministic, non-LLM grep gate (tools/pci-sss/citation_verify.py) over every PCI SSS v2.0 verdict's cited evidence and quarantines any that cannot be confirmed. The verifier is code, not judgement; this brief governs how an agent invokes it and handles the result.
---

# Agent — citation-verifier (dispatch)

This role runs a **tool**, it does not exercise judgement. The verification is `tools/pci-sss/citation_verify.py` — deterministic, fail-closed. The agent's job is to invoke it correctly and faithfully record the outcome, never to "help" a verdict pass.

## What to run

```
python3 tools/pci-sss/citation_verify.py --output-dir <engagement_dir> [--source-root <app_root>]
```
For each verdict in `artifacts/validated/`, the tool resolves `control_ref` against the pinned catalog, enforces the status/evidence invariants, and greps every `quoted_text` at its cited `file:line ±5` (whitespace-normalized) with an `sha256` file check. A failure rewrites the verdict to `REQUIRES_MANUAL_REVIEW` (`citation_verified=false`, `downgraded_from` set) and appends it to `artifacts/quarantined.json`. The tool exits non-zero if anything was quarantined.

## How to handle the result

- Report the pass/quarantine counts and the path to `artifacts/quarantined.json`.
- A non-zero exit is expected and acceptable — it means the gate did its job; the quarantined verdicts are now `REQUIRES_MANUAL_REVIEW` and will appear in the report's Coverage & Limitations section.
- The mechanics and hard rules live in [../anti-hallucination/citation-verifier.md](../anti-hallucination/citation-verifier.md).

## Anti-Patterns
- Editing a verdict's `quoted_text`, `control_ref.version`, or `test_requirement_id` so the tool passes it — re-assess the requirement instead.
- Moving a verdict out of `quarantined.json` by hand.
- Treating a non-zero exit as a tool error to be suppressed — it is the gate signalling quarantines.

## See also
- [../anti-hallucination/citation-verifier.md](../anti-hallucination/citation-verifier.md) · [verdict-assessor.md](verdict-assessor.md) · [../core/schema.md](../core/schema.md)
