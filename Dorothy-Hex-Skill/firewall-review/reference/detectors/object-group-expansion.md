<!-- ../detectors/object-group-expansion.md -->
---
name: object-group-expansion
description: Rerun inner detectors against the effective policy after expanding object-groups / address-groups / service-groups. Surfaces findings hidden behind named object references.
---

# Object-Group Expansion

**Reference implementation:** `fwrr.detectors.object_group_expansion.ObjectGroupExpansion` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `object-group-expansion:0.1.0`
**Default severity:** inherited from the inner detector that produced the finding

## What it checks
Expands every `ObjectDefinition` reference in the ruleset (`grp_partners` → `[any]`, `svc_web` → `[tcp/80, tcp/443]`, etc.) to produce an "effective policy" view. Then reruns the configured inner detectors (any-any-broadness, public-source-allow, risky-service, ...) against the expanded rules. Findings emerging only in the expanded view are re-tagged with `detector=object-group-expansion` and prefixed `[effective-policy]` so reviewers can see the reason a defect was invisible to naive single-rule analysis.

## Why this matters
Modern firewalls heavily use named object-groups. A rule that reads `source=grp_partners destination=internal_db` looks tightly scoped until you learn `grp_partners` resolves to `any`. This detector is the layer that prevents an auditor from being fooled by a well-named group that hides an any-any permit. It catches the most embarrassing findings in any review — the ones where remediation is "rename the object-group so the next reviewer reads what the firewall actually sees."

## Frameworks cited
- NIST CSF 2.0 — `PR.PS-01` (configuration management practices — named-object semantics must be audit-legible)
- NIST CSF 2.0 — `PR.AA-05` (least-privilege enforcement across expanded policy)
- CIS Controls v8.1 — `4.4` (secure configuration of network infrastructure)
- ISO/IEC 27001:2022 — `A.8.9` (configuration management)

## v0.2 / v0.3 plans
- v0.2: transitively expand nested object-groups (group-of-groups) with cycle detection and depth-bounded recursion.
- v0.3: emit a diff between the authored ruleset view and the effective-policy view, so auditors can show clients the exact delta their naming conventions are hiding.
