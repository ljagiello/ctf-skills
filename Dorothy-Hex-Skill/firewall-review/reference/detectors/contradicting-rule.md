<!-- ../detectors/contradicting-rule.md -->
---
name: contradicting-rule
description: Flag pairs of rules with identical match tuples but opposite actions. Gated behind default-deny-presence.
---

# Contradicting Rule

**Reference implementation:** `fwrr.detectors.contradicting_rule.ContradictingRule` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `contradicting-rule:0.1.0`
**Default severity:** High

## What it checks
Finds pairs of rules whose match tuples (source, destination, ports, protocol, direction) are identical but whose `action` differs (one `allow`, one `deny`). Gated behind the default-deny-presence detector — runs only when an explicit terminator is present, so shadow-vs-contradiction classification is deterministic.

## Why this matters
Contradicting rules mean the evaluated action depends on rule ordering alone, not expressed intent. Subtle reorderings during change-control silently flip effective policy. Unlike shadowing (where one rule is unreachable), both rules appear active — making the defect particularly hard to spot in a UI or diff review.

## Frameworks cited
- NIST CSF 2.0 — `PR.PS-01` (configuration management practices are established)
- ISO/IEC 27001:2022 — `A.8.9` (configuration management)

## v0.2 / v0.3 plans
- v0.2: propose the canonical resolved rule (based on hit-count evidence) and generate a diff-ready remediation patch.
- v0.3: surface contradictions introduced since the last audited baseline by comparing rule-hashes across engagement snapshots.
