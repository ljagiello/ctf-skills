---
name: Independent validation loop (adversarial second-pass review)
description: Two-independent-passes methodology for findings that will be handed to a client. The second pass re-derives findings from raw config WITHOUT seeing the first pass; disagreements escalate. Required before any client deliverable.
type: process-pattern
---

# Independent validation loop

**Rule:** no finding ships to a client without two independent passes agreeing. Disagreements are HELD for human escalation, never silently resolved.

## Why

Deterministic detectors are deterministic — but their rule boundaries (severity, framework mapping, RequiresManualReview thresholds) are human judgment calls frozen in code. A single pass through the pipeline can perpetuate a bad judgment call across 1001 auditors.

An independent second pass — fresh context, fresh rule-comprehension — catches:
- false positives the primary pipeline over-flagged (e.g. `-i lo` loopback rules as "public-source-allow")
- false negatives the primary pipeline missed (e.g. unusual protocol combinations)
- severity drift (primary flags Critical, secondary sees Medium)
- citation drift (primary cites framework v3.2.1, secondary notes v4.0.1 is current)

Also: when the client receives the report, the presence of an independent validation pass is itself evidence of audit discipline — a standalone differentiator in the market.

## Pipeline position

The loop sits BETWEEN the senior-pentester semantic pass and the CTO/CISO/QA chain:

```
  detect.py (deterministic)
     ↓
  findings.draft.jsonl
     ↓
  senior-pentester subagent (semantic)
     ↓
  findings.draft.jsonl (augmented)
     ↓
  citation-verifier.py (deterministic)
     ↓
  findings.verified.jsonl
     ↓
  ╔═══════════════════════════════════╗
  ║ INDEPENDENT VALIDATION PASS       ║
  ║                                   ║
  ║ second-pass subagent:             ║
  ║   - input: rules.jsonl ONLY       ║
  ║   - NO findings.verified.jsonl    ║
  ║   - produces findings.alt.jsonl   ║
  ╚═══════════════════════════════════╝
     ↓
  diff-findings.py:
     agree  → findings.validated.jsonl
     miss   → held.jsonl (primary missed)
     extra  → held.jsonl (secondary over-flagged, primary to review)
     sev-δ  → held.jsonl (severity disagreement)
     ↓
  CTO / CISO / QA chain (on validated set only)
```

## Second-pass agent brief

The second-pass subagent MUST:
- Receive `rules.jsonl` and the raw source configs
- NOT receive `findings.verified.jsonl`, `findings.draft.jsonl`, or any detector output
- Re-derive findings using the same detector taxonomy (names in memory) but without code-path context
- Emit findings in the same schema
- Record its own chain-of-custody with `parser_version` and a distinct `detector_version: "independent-review:<sha>"` so the diff tool knows this is the second pass

## Diff rules

`diff-findings.py` compares by `(affected_rule_id, detector_name, severity)`:

| Case | Primary | Secondary | Action |
|------|---------|-----------|--------|
| Full match | Finding F | Finding F' matching (rule_id, detector, severity) | → `validated` |
| Severity disagreement | Critical | High | → `held` with reason "severity_delta:C→H" |
| Primary-only | Finding F | — | → `held` reason "primary_only_needs_confirmation" |
| Secondary-only | — | Finding F' | → `held` reason "secondary_caught_primary_missed" |
| Same rule, different detector | any-any-broadness | public-source-allow | → both kept, flagged as `held` reason "detector_mismatch" |

Held findings are NOT in `findings.final.jsonl` — they require human review. The report's §9 Limitations must note the held count with a breakdown by disagreement class.

## Cost

Adds one subagent per engagement. Given rate-limit pacing (≤8/msg, ≤12/2h), schedule the second pass as a separate message from the senior-pentester dispatch.

## Mandatory flag

A feature flag `pipeline.require_independent_validation: true` must be ON for any engagement tagged `deliver_to_client: true`. Can be relaxed only for internal dry-runs.

## Why not just CTO-reviewer

CTO-reviewer sees the primary findings and decides yes/no/uncertain — it is a REVIEW step, not an INDEPENDENT PASS. Different cognition pattern. Both are required. Think of it as:
- Independent pass: can I reach the same conclusions from scratch?
- CTO review: given these claimed findings, do they survive scrutiny?

The first catches missed-coverage and over-coverage; the second catches bad-reasoning-within-coverage.
