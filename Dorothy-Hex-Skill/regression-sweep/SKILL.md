---
name: regression-sweep
description: Re-validates every previously-confirmed finding against its current target — detects drift (patched, mitigated, re-introduced). Cron-driven weekly sweep across the org's validated finding tree.
---

# Regression Sweep

Walk the entire `validated/*.json` tree, re-fire each finding's `poc.py`, compare output against the recorded `poc_output.txt`, and write a weekly drift report. Mounted onto the cloud-agent task #4.

## Trigger

Cron weekly (default Mondays 02:00 UTC). May also be invoked ad-hoc after a major patch deployment.

## Workflow

1. **Index validated findings.** Glob `validated/*.json` and resolve each entry's `FINDING_DIR` (under `findings/finding-NNN/`).
2. **Per finding:**
   - Re-run `python3 poc.py` with a 60-second timeout.
   - Capture stdout/stderr into `findings/finding-NNN/evidence/validation/regression-{week}-rerun.txt`.
   - Diff against `findings/finding-NNN/evidence/validation/poc-rerun-output.txt` (the validator's original re-run output) using a normalized line-set comparison (strip timestamps, request IDs, ephemeral tokens).
   - Re-check the finding's CVE via `tools/nvd-lookup.py` — has severity changed?
3. **Classify each finding** into one of:
   - `still_valid` — re-run matches baseline within tolerance, CVSS unchanged.
   - `drift_severity` — re-run matches, but CVSS shifted ≥1.0 (NVD re-scored).
   - `newly_invalid` — re-run output diverges, exploit no longer fires. Likely patched.
   - `newly_revalidated` — finding had been marked `REJECTED` later, but now fires again. Regression.
   - `inconclusive` — re-run errored (network, target unreachable). Retry next sweep.
4. **Write report** to `artifacts/regression-{YYYYWww}.json` + human-readable `regression-{YYYYWww}.md`. Transitions (`newly_revalidated`, `drift_severity`, `newly_invalid`) appear in the report under explicit headers for analyst review.

## Output

```
{OUTPUT_DIR}/
  artifacts/
    regression-{YYYYWww}.json         # machine-readable result
    regression-{YYYYWww}.md           # human summary
  findings/finding-NNN/evidence/validation/
    regression-{YYYYWww}-rerun.txt    # captured re-run output
```

`regression-{week}.json` schema:

```json
{
  "week": "2026W19",
  "swept_at": "2026-05-13T02:00:00Z",
  "counts": {"still_valid": 47, "drift_severity": 2, "newly_invalid": 5, "newly_revalidated": 1, "inconclusive": 3},
  "findings": [
    {"finding_id": "finding-012", "asset": "asset42", "cve": "CVE-2024-12345",
     "verdict": "newly_invalid", "reason": "PoC output diverged: response now 404",
     "baseline_cvss": 9.8, "current_cvss": 9.8}
  ]
}
```

## Rules

1. **Demonstrate, never disrupt.** Re-firing a PoC is observation, not mutation. Every `poc.py` already satisfied the demonstrate-only constraints at validation time (task-03 Safety section); the sweep simply re-executes the same script — which by contract reads a proof signal and exits. If a PoC at re-run attempts a mutating action it should not have contained originally, the sweep aborts that finding with `inconclusive` and emits a stderr WARN — the PoC needs re-validation, not regression scoring.
2. **Bounded per-PoC time.** 60-second timeout per `poc.py`. Timeouts → `inconclusive`, not `newly_invalid`. Avoids false-positive "patched" claims caused by network blips.
3. **Normalized diff.** Strip timestamps (`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}`), request-IDs (`[a-f0-9]{32,}`), and ephemeral session tokens before comparing. Real exploit output is structurally stable.
4. **No new findings.** A regression sweep can flip status of existing findings but cannot create new ones. Newly observed vulns belong to the Validation Run task, not this skill.
5. **Idempotent.** Re-running the same week's sweep overwrites the same `regression-{YYYYWww}.json`. The per-finding `regression-{week}-rerun.txt` is timestamped to preserve history.
6. **Cap concurrent re-runs.** Max 5 parallel PoC re-runs per sweep to avoid hammering production assets.

## References

- `reference/diff-normalization.md` — full normalization rules and per-finding output-stability heuristics.
