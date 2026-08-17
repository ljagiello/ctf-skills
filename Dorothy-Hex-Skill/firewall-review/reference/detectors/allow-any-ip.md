<!-- ../detectors/allow-any-ip.md -->
---
name: allow-any-ip
description: Flag allow rules where source OR destination is literally `any` / `0.0.0.0/0` / `::/0`, even when the opposite side is tightly scoped.
---

# Allow Any IP

**Reference implementation:** `fwrr.detectors.allow_any_ip.AllowAnyIp` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `allow-any-ip:0.2.0`
**Default severity:** Medium

## What it checks
Scans `action=allow` rules where `source` or `destination` contains `any`, `0.0.0.0/0`, or `::/0`. Complements any-any-broadness (which counts multiple wildcards on one rule) and public-source-allow (which owns the explicit-public-source case). When the source is explicitly `0.0.0.0/0` or `::/0` AND the destination is scoped, the finding is suppressed — public-source-allow already reports that rule. Infrastructure-rule filter skips loopback and state-established returns.

## Why this matters
A fully-scoped destination paired with a wildcard source means every host on the reachable network can talk to that service. A fully-scoped source paired with a wildcard destination means one internal host can reach anything — both shapes defeat segmentation on the unscoped dimension. This is the rule type most commonly introduced by "temporary" troubleshooting changes that never got narrowed. The fix is to replace the `any` side with the explicit CIDR or object-group that reflects the documented business flow — auditors will want to see the ticket that justified the original shape.

## Frameworks cited
- PCI DSS v4.0.1 — `1.3.1` (restrict inbound/outbound traffic to that which is necessary)
- NIST CSF 2.0 — `PR.AA-05` (access permissions enforced with least privilege)
- CIS Controls v8.1 — `4.4` (secure configuration of network infrastructure)

## v0.2 / v0.3 plans
- v0.2: de-duplication against public-source-allow (shipped — suppresses overlap when source is explicit public and destination is scoped).
- v0.3: directional weighting — outbound-destination-any from internal segments is the typical data-exfiltration vector; raise severity to High on outbound rules with wildcard destination.
- v0.3: object-group expansion awareness — a named object-group containing `0.0.0.0/0` as a member should be treated the same as a literal `any` on the same side.
