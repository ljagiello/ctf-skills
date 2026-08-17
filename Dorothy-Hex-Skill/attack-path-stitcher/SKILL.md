---
name: attack-path-stitcher
description: Stitches confirmed single-asset findings into multi-hop attack paths across the organization. Builds a graph where nodes are assets and edges are confirmed exploit hops citing the findings that enable them.
---

# Attack Path Stitcher

The Validation Run task (#3) produces confirmed findings *per asset*. Real attacker risk lives in **chains**: a finding on asset A leaks credentials that enable a finding on asset B that pivots into asset C. This skill builds that graph.

Mounted onto cloud-agent task #6.

## Trigger

Cron daily (default 03:00 UTC). May also re-run after a Validation Run task batch completes.

## Workflow

1. **Load inputs.**
   - `validated/*.json` — every confirmed finding across all engagements.
   - `artifacts/org-surface.json` — the org-wide surface graph (assets, services, network zones, trust relationships).
   - `findings/finding-NNN/evidence/raw-source.txt` — for credential / token extraction during stitching.
2. **Build asset nodes.** One node per asset in `org-surface.json`, attributed with: `tier`, `services`, `network_zone`, `trust_relationships`.
3. **Build edges** — one edge per detected pivot. See `reference/edge-detectors.md` for the seven detectors:
   - Credential reuse (creds leaked on A reused as auth on B)
   - Shared secret / API key (same secret appears in two assets' evidence)
   - Trust-zone transitive access (A in zone X has implicit reach to B in zone X)
   - AD path hops (kerberoast / DC sync / RBCD chains)
   - Cloud IAM role chains (assume-role from compromised asset)
   - SSRF → internal asset reach (A's SSRF reaches B's internal endpoint)
   - Supply-chain (A is a dependency of B per `source-code-scanning` SBOM)
4. **Compute reachability closure.** For each tier-`crown_jewel` node, BFS backwards through edges to find every external-facing node that can reach it. Mark these as "entry points".
5. **Write graph** to `artifacts/attack-paths.json` plus a human DOT file `artifacts/attack-paths.dot` (renderable with Graphviz).

Implementation runs through `tools/chain-merger.py` which handles the graph construction. The skill provides the *rules* the tool consults; the tool does the iteration.

## Output

```
{OUTPUT_DIR}/
  artifacts/
    attack-paths.json     # nodes, edges, entry_points, crown_jewel_paths
    attack-paths.dot      # Graphviz source
    attack-paths.md       # ranked list of distinct paths (human read)
```

`attack-paths.json` schema:

```json
{
  "generated_at": "2026-05-13T03:00:00Z",
  "nodes": [
    {"id": "asset42", "tier": "revenue", "services": ["http/443"], "zone": "dmz",
     "external": true, "findings": ["finding-012", "finding-018"], "max_cvss": 9.8}
  ],
  "edges": [
    {"src": "asset42", "dst": "asset77", "detector": "credential-reuse",
     "via_findings": ["finding-012", "finding-019"],
     "evidence": "credential (userpass) present in evidence of asset42 and asset77",
     "feasibility": 1.0}
  ],
  "entry_points": ["asset42", "asset05"],
  "confirmed_paths": [
    {"jewel": "asset99", "paths": [
      {"hops": ["asset42", "asset77", "asset99"],
       "edges": [{"src":"asset42","dst":"asset77","detector":"credential-reuse","feasibility":1.0,"via_findings":["finding-012"]},
                 {"src":"asset77","dst":"asset99","detector":"ssrf-reach","feasibility":1.0,"via_findings":["finding-024"]}],
       "feasibility": 1.0, "max_cvss": 9.8, "path_class": "confirmed"}
    ]}
  ],
  "inferred_paths": [
    {"jewel": "asset99", "paths": [
      {"hops": ["asset05", "asset99"], "edges": [...],
       "feasibility": 0.5, "max_cvss": 7.5, "path_class": "inferred"}
    ]}
  ],
  "truncation": {
    "edge_cap_hit": false, "depth_truncated_count": 0,
    "topn_dropped_count": 0, "max_depth": 8, "edge_cap": 50000
  }
}
```

**Crucial for RFP §3.3 compliance**: `confirmed_paths` contains ONLY paths where every edge has feasibility 1.0 AND every edge cites at least one validated finding. These are the "confirmed attack paths" the RFP requires. `inferred_paths` carries topology / supply-chain hops with no PoC evidence — surfaced for analyst review but excluded from remediation SLA buckets by `risk-prioritiser`.

## Rules

1. **Edges require evidence.** An edge is only written if at least one finding's evidence corroborates the pivot. No speculative edges.
2. **Bi-directional ≠ assumed.** If A reaches B, do not infer B reaches A. Each direction needs its own evidence.
3. **Deduplicate by `(src, dst, detector)`.** Multiple findings that enable the same hop merge into one edge with `via_findings` listing all of them.
4. **Feasibility ∈ {1.0, 0.5, 0.25}.** Reliable PoC re-run = 1.0; conditional (race, timing, specific user) = 0.5; theoretical (logically follows but never demonstrated) = 0.25.
5. **Limit path enumeration.** For each crown-jewel, return top-10 paths per class (confirmed + inferred separately) sorted by `feasibility × max_cvss / hop_count`. Full graph is in `attack-paths.json` for downstream prioritisation.
6. **Read-only.** Stitcher never re-fires PoCs and never touches `findings/`. It only reads.
7. **Bound graph size.** Stop edge construction at 50,000 edges; cap path-search depth at `--max-depth` (default 8 hops). Emit `truncation.edge_cap_hit`, `truncation.depth_truncated_count`, and `truncation.topn_dropped_count` in the JSON so downstream consumers can detect silent path loss.
8. **Confirmed vs inferred is non-negotiable.** A path appears in `confirmed_paths` only if every edge has feasibility 1.0 AND every edge has a non-empty `via_findings`. Trust-zone-only, shared-secret-only, and supply-chain-only chains land in `inferred_paths`. This split is the contract that lets the RFP-§3.3 claim "confirmed attack paths" stand.
9. **Schema enforcement on input.** `tools/chain-merger.py` drops `validated/{id}.json` rows missing `finding_id` or `asset`, or whose `verdict != "VALID"`, with stderr WARNs. Upstream validator must comply with the schema in `projects/rfp-3.2/task-03-validation-run.md`.

## References

- `reference/edge-detectors.md` — the 7 detector rules with concrete signal patterns.
- `projects/rfp-3.3/task-06-attack-path-stitcher.md` — cloud-agent runtime contract.
