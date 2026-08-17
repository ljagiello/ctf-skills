<!-- ../learning/skill-proposer.md -->
---
name: skill-proposer
description: LLM pass that turns clusters of auditor feedback into candidate skill/detector proposals written to `.claude/pending/`. Never mutates live skills directly - human curator promotes via PR.
---

# Skill Proposer

**Reference implementation:** `fwrr.learning.proposer.SkillProposer` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `skill-proposer:0.1.0`

## Role in the pipeline
Runs at the end of `fwrr report`. Reads `engagement/feedback.jsonl`, clusters Request-Changes and Other verdicts by theme, and drafts candidate skills or detector rules into `.claude/pending/<YYYYMMDD-HHMM>-<slug>.md` + `.jsonl` metadata. Each candidate carries a traceable anchor back to the originating FeedbackCandidate records.

## Failure modes
- Invalid JSON output -> candidate discarded; custody.jsonl records `proposer_bad_json`.
- Candidate duplicates an existing live skill or pending candidate -> suppressed; pointer logged.
- Candidate proposes mutating a frozen artefact (findings.final.jsonl, deliverables/) -> rejected by the curator's pre-commit guard.
