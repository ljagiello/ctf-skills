<!-- ../reporting/narrative-framer.md -->
---
name: narrative-framer
description: LLM pass that frames the executive narrative sections of the audit PDF (Overview, Key Risks, Recommended Remediations) from FROZEN approved findings. Never mutates evidence, citations, or severities. Temperature 0.
---

# Narrative Framer

**Reference implementation:** `fwrr.reporting.narrative.NarrativeFramer` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `narrative-framer:0.1.0`

## Role in the pipeline
Invoked during `fwrr report` AFTER findings are frozen. Receives the list of approved findings (evidence + citations treated as immutable) and returns JSON sections: `{"overview": "...", "key_risks": [...], "recommendations": [...]}`. Output is passed into the PDF template verbatim; any attempt to rewrite evidence strings is stripped by a post-process diff check.

## Failure modes
- Invalid JSON -> narrative sections rendered as `Generated narrative unavailable - see raw findings`. PDF still ships.
- Post-process diff check detects evidence mutation -> narrative discarded; fallback boilerplate used; custody.jsonl records `narrative_mutation_detected`.
- Recommendation cites a control not present in any finding -> recommendation dropped; flag raised for QA review.
