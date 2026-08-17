# Edge Detectors

Seven detectors. Each consumes the validated-findings tree + `org-surface.json` and emits zero-or-more edges.

## 1. Credential Reuse

**Signal**: A finding's `evidence/raw-source.txt` contains a `user:password` pair, API token, or NTLM hash. Subsequent findings on other assets reference the same secret in `description.md` or `poc.py`.

**Extraction patterns** (apply to raw-source.txt):

```
\b([A-Za-z_][A-Za-z0-9_.-]{2,32}):([^\s'"]{6,64})\b      # user:password
\b[A-Za-z0-9_-]{20,200}\.[A-Za-z0-9_-]{20,200}\.[A-Za-z0-9_-]{20,200}\b   # JWT
\b[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}\b                       # LM:NT hash
sk-[A-Za-z0-9]{20,}                                       # OpenAI-style key
AKIA[0-9A-Z]{16}                                          # AWS access key
ghp_[A-Za-z0-9]{36}                                       # GitHub PAT
```

**Edge feasibility**:
- 1.0 — second finding's PoC explicitly authenticates with the extracted credential and succeeds.
- 0.5 — credential appears in second asset's *config* (e.g., `source-code-scanning` flagged it) but no live exploit confirms still-valid.
- 0.25 — credential format matches a known scheme but second finding only *references* it without using it.

## 2. Shared Secret / API Key

**Signal**: same long-entropy token (≥ 20 chars, ≥ 3.5 bits/char Shannon) appears in two distinct assets' evidence trees.

Distinct from #1 because the token isn't a credential — could be a signing key, encryption key, webhook secret. Edge represents trust transitivity rather than auth pivot.

## 3. Trust-Zone Transitive Access

**Signal**: `org-surface.json` declares assets share a network zone OR an explicit trust edge (e.g., AD trust, VPN, peering).

```json
"network_zones": {"dmz": ["asset05", "asset42"], "internal": ["asset77"]},
"trust_edges": [{"src_zone": "dmz", "dst_zone": "internal", "via": "service-mesh"}]
```

Emit an edge for every reachable pair, feasibility = 0.5 (transitively assumed unless a finding confirms a live pivot, in which case bump to 1.0).

## 4. AD Path Hops

**Signal**: a finding's evidence includes any of:

- `secretsdump.py` output (NTLM hash dump)
- `ticketer.py` / `getST.py` invocation (Kerberos tickets)
- RBCD modification (msDS-AllowedToActOnBehalfOfOtherIdentity)
- ESC1-ESC15 ADCS chain artifacts
- Kerberoast / AS-REPRoast cracked hashes

For each AD path hop, the destination is the next AD principal in the chain. Look it up in `org-surface.json` under `ad_principals`.

Feasibility = 1.0 if the chain step's PoC produced a working ticket / hash / NTLM auth; 0.5 if only theoretical.

## 5. Cloud IAM Role Chains

**Signal**: a finding's PoC includes `sts:AssumeRole`, `iam:PassRole`, or analogous Azure / GCP role-assumption calls AND the target role exists in `org-surface.json` under `iam_roles`.

Edge `src=compromised_asset`, `dst=asset_owned_by_assumed_role`. Feasibility = 1.0 if `sts:AssumeRole` actually returned credentials in the PoC output.

## 6. SSRF → Internal Asset Reach

**Signal**: a finding's vuln class is `SSRF` AND the PoC successfully reached an internal IP/hostname that maps to another asset in `org-surface.json`.

Match pattern: extract `http(s)?://<host>` from PoC output, look up `<host>` in surface `assets[].internal_endpoints`. Feasibility = 1.0 (the PoC already proved reach) for the first hop; 0.5 for any inferred secondary hops.

## 7. Supply-Chain

**Signal**: `source-code-scanning` SBOM lists asset B as depending on a package version maintained in / served by asset A.

Edge represents the risk that compromising A's build pipeline / artifact registry affects B. Feasibility = 0.25 by default (no demonstrated exploit), 0.5 if the artifact-registry asset itself has a confirmed RCE-class finding.

## Detector ordering

Run in the order above. Detector #1 (credential reuse) tends to produce the highest-confidence edges and should be considered the strongest signal for crown-jewel-path ranking.

## What does NOT create an edge

- Two assets sharing a vendor / product (e.g., both running nginx) — not a pivot, that's a class-wide vuln.
- Two assets having the same kind of vuln class — not a pivot, that's vuln-class clustering (belongs to a separate analytic).
- A finding hypothesizing future lateral movement without evidence — speculative, drop.
- Public CVE list — CVEs are vuln-class data, not pivots.
