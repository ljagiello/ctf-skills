<!-- ../detectors/duplicate-rule.md -->
---
name: duplicate-rule
description: Flag groups of rules that share identical action, source, destination, ports, protocol, and direction.
---

# Duplicate Rule

**Reference implementation:** `fwrr.detectors.duplicate_rule.DuplicateRule` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `duplicate-rule:0.1.0`
**Default severity:** Low

## What it checks
Canonicalises each rule's match tuple (action, source, destination, ports, protocol, direction) and groups rules that share the same canonical key. Emits one finding per group of 2+ exact duplicates.

## Why this matters
Duplicates are operational noise that inflate rulebase size, slow change review, and hide the authoritative rule. They routinely accumulate through tooling imports, copy-paste change requests, and merged configurations. While the security impact is typically low, they degrade the reviewability of the ruleset — and auditors cannot certify what they cannot read efficiently.

## Frameworks cited
- CIS Controls v8.1 — `12.2` (establish and maintain a secure network architecture)
- ISO/IEC 27001:2022 — `A.8.9` (configuration management)

## v0.2 / v0.3 plans
- v0.2: detect near-duplicates (tuples differing only in log-level / name / comment) and cluster them for bulk remediation.
- v0.3: cross-firewall duplicate detection in the composite-policy view.
