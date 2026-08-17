<!-- ../learning/feedback-capture.md -->
---
name: feedback-capture
description: Captures auditor feedback on each finding during REVIEW (Approve / Request Changes / Other) into a structured FeedbackCandidate record. Deterministic, no LLM.
---

# Feedback Capture

**Reference implementation:** `fwrr.learning.feedback.FeedbackCapture` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `feedback-capture:0.1.0`

## Role in the pipeline
Runs inside `fwrr review` (localhost UI or `--cli-only` pager). Each auditor decision on a finding is serialised into a `FeedbackCandidate` record (engagement-id, finding-id, verdict, free-text reason, tool + skill-set versions, timestamp) and appended to `engagement/feedback.jsonl`. Records flow to the skill-proposer at the end of the engagement.

## Failure modes
- Auditor closes the UI mid-review -> partial feedback persisted; next `fwrr review` resumes from last captured record.
- Disk write failure -> finding review blocked; error surfaced to auditor (fail-closed to preserve custody integrity).
- Free-text reason exceeds 4 KB -> truncated with `__truncated__` marker; full text archived to `feedback.full.jsonl`.
