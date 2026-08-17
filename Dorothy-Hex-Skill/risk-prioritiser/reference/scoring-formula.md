# Scoring Formula — Worked Examples

The risk-prioritiser score is intentionally simple so it's auditable end-to-end.

## Formula

```
score = feasibility × (max_cvss / 10) × business_impact × entry_exposure
```

All four terms ∈ [0, 1], so `score ∈ [0, 1]`.

## Worked Example A — High-confidence crown-jewel chain

3-hop chain `web01 → app03 → db_finance`:

| Hop | Detector | Edge feasibility |
|---|---|---|
| web01 → app03 | credential-reuse | 1.0 |
| app03 → db_finance | ssrf-reach | 1.0 |

- `feasibility` = 1.0 × 1.0 = **1.0**
- `max_cvss` along path = 9.8 (from finding-012 on web01)
- `technical_severity` = 9.8 / 10 = **0.98**
- `business_impact` = 1.0 (db_finance is `crown_jewel`)
- `entry_exposure` = 1.0 (web01 is external)
- **score = 1.0 × 0.98 × 1.0 × 1.0 = 0.98** → `immediate`

`remediation_focus`: every edge has feasibility 1.0 (fully confirmed chain), so per the SKILL.md rule the focus is the **entry asset** = `web01`. Patching the externally-reachable foothold breaks every downstream hop and is the cheapest patch surface operationally.

## Worked Example B — Plausible-but-unproven chain

2-hop chain `partner_portal → asset77`:

| Hop | Detector | Edge feasibility |
|---|---|---|
| partner_portal → asset77 | trust-zone | 0.5 |

- `feasibility` = **0.5**
- `max_cvss` = 7.5 (medium-high finding on partner_portal)
- `technical_severity` = **0.75**
- `business_impact` = 0.7 (asset77 is `revenue`)
- `entry_exposure` = 1.0 (partner_portal external)
- **score = 0.5 × 0.75 × 0.7 × 1.0 = 0.2625** → `medium_term`

The trust-zone hop is plausible (zone implies reach) but no PoC confirms a real pivot. The score acknowledges the risk without overweighting it.

## Worked Example C — Single high-severity finding on a non-jewel asset

`finding-021`: RCE on a `support` tier asset, no chain available.

- `feasibility` = 1.0 (validated finding)
- `max_cvss` = 9.0
- `technical_severity` = 0.9
- `business_impact` = 0.4 (support tier)
- `entry_exposure` = 1.0
- **score = 1.0 × 0.9 × 0.4 × 1.0 = 0.36** → `short_term`

CVSS 9.0 alone might suggest "immediate" — the business-impact term correctly lowers it because the asset isn't critical to the business. The chain-aware Example A (CVSS 9.8 ending at a crown-jewel) outranks this isolated RCE, as it should.

## Edge cases

- **Path of length 1** (just an asset with a confirmed finding) — treated as `kind: finding`, scored as Example C.
- **All edges feasibility 0.25** (theoretical chain) — score may compute as 0.25, but `path_class != "confirmed"` so the row is placed in `theoretical` regardless. Theoretical chains never enter the remediation SLA roadmap (`immediate` / `short_term` / `medium_term`); they appear in board reports for visibility only. This is required for RFP §3.3 compliance ("confirmed attack paths").
- **CVSS 0 / no NVD score** — set `technical_severity = 0.5` (assume medium) and flag `cvss_missing: true` in the output row.
- **Missing tier in business-tier-map.csv** — use `unknown` weight (0.3) and emit the asset id under `unmapped_assets` at the top of the output.
- **Zero feasibility edge** — drop the edge from path consideration entirely (it shouldn't exist; if it does, treat as no-edge).

## Why these weights

The defaults were chosen so that:
1. A theoretical crown-jewel chain (Example B without proven hops) ranks below a confirmed high-CVSS finding on a revenue asset.
2. A confirmed crown-jewel chain (Example A) is always in `immediate`.
3. A confirmed RCE on a `dev` tier asset (e.g., a staging environment) ranks in `medium_term` — present but not blocking.

The weights are configurable per client via `--tier-weights '{"revenue": 0.85, ...}'` if their business model differs (e.g., a SaaS where "support" infrastructure actually carries revenue traffic).
