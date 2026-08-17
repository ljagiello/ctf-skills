<!-- ../personas/cto-reviewer.md -->
---
name: cto-reviewer
description: Independent LLM reviewer that re-verifies each finding's technical claim against the parsed ruleset AST. Holds findings on "uncertain", rejects on "no", approves on "yes". Temperature 0.
---

# CTO Reviewer

**Reference implementation:** `fwrr.personas.cto.CTOReviewer` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `cto-reviewer:0.1.0`

## Role in the pipeline
After the deterministic citation-verifier passes, CTOReviewer is invoked per finding. It receives the CLAIM (title + detector), EVIDENCE (quoted rule), and AST summary. It MUST respond with strict JSON: `{"verdict": "yes"|"no"|"uncertain", "reason": "..."}`.

## Failure modes
- Invalid JSON -> `held` (routed to human reviewer).
- `uncertain` -> `held`. Operators can then inspect the AST in `held.jsonl` and decide manually.
- `no` -> `quarantine` (finding never reaches the auditor review UI).
