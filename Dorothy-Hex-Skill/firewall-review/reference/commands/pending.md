---
name: pending
description: Curator commands for learning-loop candidates. Usage — /pending list | /pending review <id> | /pending promote <id> | /pending reject <id> | /pending hold <id>
---

# /pending — Curator commands

Arguments: `<action> [<candidate_id>]` where action is one of `list`, `review`, `promote`, `reject`, `hold`.

## What to do

### `/pending list`

- Read `.claude/pending/*.yaml`.
- Print a table:

```
Learning candidates (pending curator review):

  ID                                                   Status    Target detector        Proposed change
  pending-2026-04-19-nonprod-severity-downgrade        proposed  any-any-broadness     Downgrade severity for non-prod assets
  pending-2026-04-20-ssh-management-whitelist          proposed  public-source-allow   Allow public-source if documented bastion
  ...
```

### `/pending review <candidate_id>`

- Read `.claude/pending/<candidate_id>.yaml`.
- Pretty-print the full candidate: proposal_type, target_skill, change_summary, evidence (finding_ids + auditor_reasons), test_cases, validation_status.
- At the end, print: `Decide with: /pending promote <id> | /pending reject <id> | /pending hold <id>`

### `/pending promote <candidate_id>`

- Set `validation_status: approved` in the candidate YAML.
- Create a new git branch: `learning/<candidate_id>`.
- Tell the operator: "Branch `learning/<candidate_id>` created. Open `../detectors/<target_skill>.md` and apply the proposed change, add regression golden tests, commit, and open a PR."
- Do NOT actually edit the skill file yourself — promotion is a human curator action; you only prepare the branch and point the way.

### `/pending reject <candidate_id>`

- Set `validation_status: rejected` in the candidate YAML.
- Ask the operator for a reason and record it in `curator_notes`.

### `/pending hold <candidate_id>`

- Set `validation_status: held` in the candidate YAML.
- Ask the operator for a reason (e.g., "need more engagement data") and record it in `curator_notes`.

## Hard rules

- Never auto-promote. Curator always reviews. This is the "do not learn blindly" guarantee.
- Preserve the audit trail — `curator_notes` should always be filled on reject/hold.
- Promotion creates a branch but does NOT modify the skill. The human reviews the proposed change, writes regression tests, and lands the PR manually. This ensures every skill update has evidence + tests before it ships to 1001+ auditors.
