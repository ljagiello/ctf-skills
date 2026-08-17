<!-- ../learning/pending-curator.md -->
---
name: pending-curator
description: Human-driven curator over `.claude/pending/` candidates. Exposes `fwrr pending <list|review|promote|reject|hold> [<id>]` for deterministic triage. No LLM.
---

# Pending Curator

**Reference implementation:** `fwrr.learning.curator.PendingCurator` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `pending-curator:0.1.0`

## Role in the pipeline
Operator-facing CLI that runs between engagements. `fwrr pending list` shows unreviewed candidates; `review <id>` opens the candidate + its feedback lineage; `promote <id>` creates a git PR moving the candidate into `reference/` catalogue or `src/fwrr/detectors/`; `reject <id>` archives it; `hold <id>` defers.

## Failure modes
- Promote with failing tests -> git PR opened but marked DRAFT; curator must green the CI before merge.
- Reject without reason -> blocked; curator must supply a reason (archived alongside the candidate).
- Promote of a candidate that shadows a live skill -> blocked; candidate must be rewritten to coexist or explicitly supersede.
