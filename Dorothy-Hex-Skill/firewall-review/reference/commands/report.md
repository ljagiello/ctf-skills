---
name: report
description: Render audit-grade PDF + Excel remediation tracker from the current engagement's approved findings. Gated on ≥1 approve in feedback.jsonl.
---

# /report — Render deliverables

No arguments. Operates on the most recent engagement.

## What to do

### Step 1 — Preflight

- Check `findings.final.jsonl` exists. If not, error: "run /launch first".
- Check `feedback.jsonl` exists and has at least one `"decision":"approve"` entry.
  - If missing AND the operator has explicitly requested the report without running `/review` (e.g. asked for "the report now" / "skip review, render"), synthesize a batch-approve `feedback.jsonl` — one entry per finding with `decision: "approve"`, `decided_by: <engagement.lead_assessor>`, `mode: "batch-approve-at-report"`, and `reason` noting that interactive review was skipped by operator choice. This preserves the audit trail (the mode field makes the path explicit) and satisfies the `/report` gate. Print a one-line notice in chat so the operator sees it: "Synthesized batch-approve feedback.jsonl; audit trail records `mode: batch-approve-at-report`."
  - If missing AND the operator did NOT ask to skip `/review`, error: "run /review and approve at least one finding first".
- Verify `scoping-questionnaire.yaml` has non-empty `engagement.client`, `engagement.lead_assessor`, and `regulatory_overlay`. If any are empty, ASK the operator to fill them before rendering — these fields appear on the PDF cover page and in the appendix.

### Step 2 — Render deliverables

Run:

```bash
python3.11 scripts/render-pdf.py <engagement-dir>
python3.11 scripts/render-xlsx.py <engagement-dir>
```

These write:
- `deliverables/report.pdf` (10-section canonical audit layout, ~30-80 pages depending on finding count)
- `deliverables/remediation-tracker.xlsx` (21-column POA&M-style tracker, 5 tabs)
- `deliverables/manifest.json` (chain-of-custody: tool/skill versions + input SHA256s + engagement metadata)

### Step 3 — Trigger learning loop

Run: `python3.11 scripts/propose-skills.py <engagement-dir>`

If ≥3 feedback entries share the same detector + proposed severity adjustment, the script writes a PendingCandidate YAML to `.claude/pending/<slug>.yaml` for curator review. Report the candidate count in chat.

### Step 4 — Confirm + open

Print:

```
✅ Deliverables rendered.

  PDF:       deliverables/report.pdf          (X KB, Y pages)
  Excel:     deliverables/remediation-tracker.xlsx
  Manifest:  deliverables/manifest.json

  Learning candidates proposed: N
    (review with /pending list, promote with /pending promote <id>)

Open:
  open <engagement-dir>/deliverables/report.pdf
  open <engagement-dir>/deliverables/remediation-tracker.xlsx
```

Attempt to open the PDF and Excel automatically via `bash -c "open <path>"` on macOS (or `xdg-open` on Linux). If the open command fails silently, give the operator the paths to open manually.

## Hard rules

- Do NOT render if the preflight fails. Missing approvals or missing engagement metadata = no deliverable ships.
- Every finding in the PDF must have: severity, title, detector, affected rule IDs, evidence (source file + byte offset + quoted rule text), impact, likelihood, recommendation, and ≥1 framework citation with version.
- The PDF's §10 Limitations must explicitly list findings in `held/` and `quarantine/` with counts — known unknowns are disclosed, never hidden.
- The manifest must include `input_sha256` for every original config file in `Pre-requisites/`, so the client can independently verify the inputs match what they provided.
