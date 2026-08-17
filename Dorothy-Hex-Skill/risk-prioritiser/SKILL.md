---
name: risk-prioritiser
description: Risk-based prioritisation of confirmed attack paths. Combines exploit feasibility, technical CVSS severity, and asset business impact into a single ranked list driving remediation roadmaps.
---

# Risk Prioritiser

Consume the attack-path graph + the client-supplied business-tier map and emit a single ranked list of paths the org should remediate first. Mounted onto cloud-agent task #7.

## Trigger

Cron daily after `attack-path-stitcher` (task #6) completes. Also event-fires when a new `validated/*.json` is written with `nvd.score >= 9.0`.

## Workflow

1. **Load inputs.**
   - `artifacts/attack-paths.json` — graph from task #6. Split into `confirmed_paths` (RFP-grade) and `inferred_paths` (topology/supply-chain).
   - `business-tier-map.csv` — client-supplied asset → tier. Search order: `{OUTPUT_DIR}/business-tier-map.csv` → `projects/rfp-3.3/schemas/business-tier-map.csv`.
2. **Score each `confirmed_paths` entry.**
   - `feasibility` = product of every edge's `feasibility` along the path. For confirmed paths this is always 1.0.
   - `technical_severity` = `max_cvss_along_path / 10`.
   - `business_impact` = tier weight of the *destination* (crown_jewel = 1.0 by definition).
   - `entry_exposure` = 1.0 if entry node is `external: true`, else 0.5.
   - **Final score** = `feasibility × technical_severity × business_impact × entry_exposure`.
3. **Score each single-asset validated finding** that does not sit on a confirmed path. Same formula; `feasibility = 1.0`, `business_impact` = asset's own tier weight, hop count = 1.
4. **Score each `inferred_paths` entry**, but cap their bucket placement at `theoretical` regardless of numeric score. Inferred paths NEVER reach `immediate` / `short_term` / `medium_term` — RFP §3.3 requires "confirmed", and inferred paths are evidence-deficient by construction.
5. **Sort descending.** Stable tie-break order: max CVSS desc → hop count asc → finding age desc (newer first).
6. **Bucket into roadmap tiers.**
   - `immediate` (0-7 days): confirmed AND score ≥ 0.6
   - `short_term` (7-30 days): confirmed AND 0.3 ≤ score < 0.6
   - `medium_term` (30-90 days): confirmed AND 0.1 ≤ score < 0.3
   - `monitor`: confirmed AND score < 0.1
   - `theoretical` (track-only): any path with `path_class != "confirmed"`. Surfaced in board reports but excluded from the remediation SLA roadmap.
7. **Write outputs** to `artifacts/attack-paths-ranked.json` + `attack-paths-ranked.md`. Each row carries `path_class` so downstream consumers can filter.

## Tier weights

| Tier | Weight |
|---|---|
| `crown_jewel` | 1.00 |
| `revenue` | 0.70 |
| `support` | 0.40 |
| `dev` | 0.20 |
| `unknown` | 0.30 |

The `unknown` weight is deliberately above `support` to bias toward investigating un-mapped assets — they often turn out to be high-tier once discovered.

## Output

```
{OUTPUT_DIR}/
  artifacts/
    attack-paths-ranked.json
    attack-paths-ranked.md
```

`attack-paths-ranked.json` schema:

```json
{
  "generated_at": "2026-05-13T03:30:00Z",
  "tier_weights_used": {"crown_jewel": 1.0, "revenue": 0.7, "support": 0.4, "dev": 0.2, "unknown": 0.3},
  "ranked": [
    {
      "rank": 1,
      "kind": "path",
      "path_class": "confirmed",
      "path_id": "asset05->asset42->asset99",
      "hops": ["asset05", "asset42", "asset99"],
      "feasibility": 1.0,
      "max_cvss": 9.8,
      "business_impact": 1.0,
      "entry_exposure": 1.0,
      "score": 0.98,
      "bucket": "immediate",
      "remediation_focus": "asset05"
    },
    {
      "rank": 2,
      "kind": "finding",
      "path_class": "confirmed",
      "finding_id": "finding-018",
      "asset": "asset42",
      "feasibility": 1.0,
      "max_cvss": 9.1,
      "business_impact": 0.7,
      "entry_exposure": 1.0,
      "score": 0.637,
      "bucket": "immediate"
    }
  ],
  "buckets": {"immediate": 4, "short_term": 11, "medium_term": 22, "monitor": 8, "theoretical": 14}
}
```

## Remediation focus

For each ranked path, pick a single `remediation_focus` asset — the one whose patch breaks the chain at the lowest cost:

- **If any edge has feasibility < 1.0** → focus on that edge's *source* asset. The weakest pivot is the attacker's cheapest hop; hardening it eliminates the easiest entry.
- **If every edge is feasibility 1.0** (fully confirmed chain) → focus on the path's **entry asset** (`hops[0]`). Patching the externally-reachable foothold breaks every downstream hop and is the cheapest patch surface operationally.

This rule yields a single deterministic asset id per path. The previous "edge contribution formula" was deprecated — on uniformly-confirmed chains every edge has identical contribution, which gives no useful signal.

## Rules

1. **Always derive from `attack-paths.json`.** Do not re-derive feasibility / CVSS — those are already validated by upstream tasks.
2. **`business-tier-map.csv` is authoritative.** If an asset is missing from the map, use `unknown` tier weight + flag `unmapped_assets[]` at the top of the JSON output.
3. **Stable rank for stable input.** Re-running on identical input must produce byte-identical output.
4. **No new findings.** Prioritisation never creates findings; it only re-orders.
5. **Bucket thresholds are config.** The 0.6/0.3/0.1 cuts can be overridden via `--thresholds` argument when running on a client with different remediation cadences. Default values match the Transilience report's "Immediate / Short-term / Medium-term" labels.

## Implementation

The scoring is implemented deterministically by `tools/risk-prioritise.py` (not delegated to an LLM agent), to satisfy Rule 3 (stable rank for stable input). The tool reads `artifacts/attack-paths.json` and writes the two output files. Override the tier weights or bucket thresholds with `--tier-weights` / `--thresholds` JSON arguments — recorded in the output for audit.

## References

- `reference/scoring-formula.md` — worked example + edge-case behaviour.
- `projects/rfp-3.3/schemas/business-tier-map.csv` — input schema and example rows.
- `tools/risk-prioritise.py` — deterministic implementation.
