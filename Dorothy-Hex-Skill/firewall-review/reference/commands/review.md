---
name: review
description: Triage findings in chat. Operator sees each finding with evidence, chooses approve / request-changes / other per finding (or batches).
---

# /review — Triage findings in chat

No arguments. Operates on `findings.final.jsonl` in the most recent engagement.

## What to do

### Step 1 — Load and summarize

Read `findings.final.jsonl`. Count by severity. Print a summary:

```
📋 Review — <engagement-slug>

  Critical:  X
  High:      Y
  Medium:    Z
  Low:       W
  Info:      V
  ManualReview: U

  Total: <N> findings to triage.

I'll walk through them by severity, Critical first. You can respond with:
  • "approve F1, F2, F3"             (approve specific findings)
  • "approve all"                    (approve everything remaining)
  • "request changes F4 severity=Medium because non-prod"
  • "other F5 — need traffic logs"
  • "skip" or "next"                 (skip this one, revisit later)
  • "show F6"                        (re-show a previously-shown finding in full detail)
  • "done"                           (close review; remaining become 'other' with reason='not triaged')

Ready when you are.
```

### Step 2 — Walk findings interactively

For each finding, present in this format:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
F001 · Critical · any-any-broadness · rule "allow-any-any"

Unrestricted allow rule (3×any): source=any, destination=any, port=any

Evidence:
  Pre-requisites/palo-alto/acme-panos.xml:42
  <entry name="allow-any-any"><source><member>any</member>...

Impact:
  Broad allow semantics bypass least-privilege...

Frameworks: NIST CSF 2.0 PR.AA-05 · PCI DSS v4.0.1 1.3.1 · CIS Controls v8.1 4.4

Recommended: Constrain source, destination, and port to documented business flows.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Your call?
```

### Step 3 — Parse operator decisions

The operator may respond in any of these shapes:

- `approve F1` or `approve F1 F2 F3` or `approve F1-F5` — mark listed findings as approved in `feedback.jsonl`
- `approve all` — approve every remaining untriaged finding
- `request changes F3 severity=High because asset is non-prod` — mark as request_changes with proposed severity + reason
- `request changes F4 because <reason>` — request_changes without severity change
- `other F5 — <free text>` — mark as "other" with the free-text reason
- `skip F7` — do not record a decision; keep in queue
- `next` — show the next untriaged finding
- `done` — close the review; any remaining findings become `other` with reason="not triaged"

Write each decision immediately to `<engagement-dir>/feedback.jsonl` as a JSON line:

```json
{"finding_id":"F001","decision":"approve","reason":"","proposed_severity_change":null,"auditor":"<ask once per session>","timestamp":"<ISO-8601-UTC>"}
```

Ask the operator their auditor email/handle ONCE per session and reuse it.

### Step 4 — Close the review

When the operator says `done` OR every finding has a decision, print:

```
✅ Review complete.
  Approved:         N
  Request changes:  M
  Other:            K
  Total decisions:  N+M+K / <total>

Next: /report to render PDF + Excel.
```

## Hard rules

- Never fabricate evidence. If a finding's `evidence.quoted_rule_text` is empty or missing, surface it anyway but flag `⚠️ evidence incomplete — citation-verifier may have quarantined this; do NOT ship without manual verification`.
- Operator's free-text reason is verbatim recorded. Do not paraphrase or summarize their reasoning into `feedback.jsonl`.
- If the operator says "request changes F3 severity=<new>", validate that `<new>` is one of {Critical, High, Medium, Low, Info}. If not, ask.
- Findings in `held/` and `quarantine/` do NOT appear in `/review`. They require a separate manual escalation path, documented in the report's Limitations section.
