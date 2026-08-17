<!-- ../personas/qa-reviewer.md -->
---
name: qa-reviewer
description: Editorial gate that makes the final pass on approved findings - phrasing, citation version accuracy, cross-finding consistency. Temperature 0.
---

# QA Reviewer

**Reference implementation:** `fwrr.personas.qa.QAReviewer` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `qa-reviewer:0.1.0`

## Role in the pipeline
Last LLM reviewer before a finding reaches the auditor review UI. Receives the full finding (title, narrative, evidence, citations) and the sibling findings in the same engagement. Responds with strict JSON: `{"verdict": "approve"|"request_changes", "edits": {...}, "reason": "..."}`.

## Failure modes
- Invalid JSON -> `held` (editorial review deferred to human).
- Edits that rewrite the evidence quote -> rejected; evidence is immutable once the citation-verifier has locked it.
- Framework-version drift detected across findings -> flagged; QA does NOT mutate citations, only raises the flag for auditor review.
