<!-- ../personas/ciso-reviewer.md -->
---
name: ciso-reviewer
description: Business-impact reviewer that adjusts severity on approved findings using asset criticality and engagement context. Does NOT veto findings - severity only. Temperature 0.
---

# CISO Reviewer

**Reference implementation:** `fwrr.personas.ciso.CISOReviewer` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `ciso-reviewer:0.1.0`

## Role in the pipeline
Runs after CTOReviewer approves a finding. Receives the finding, the asset-criticality hints from the engagement scope (`Pre-requisites/03_Scope.md`), and the current severity. Responds with strict JSON: `{"severity": "critical"|"high"|"medium"|"low"|"info", "reason": "..."}`.

## Failure modes
- Invalid JSON -> original severity preserved, event logged to `custody.jsonl`.
- Severity raised beyond `critical` or lowered below `info` -> clamped to range.
- Reasoning cites an asset not in the engagement scope -> event logged; severity still applied but flagged for QA review.
