<!-- ../detectors/shadow-rule.md -->
---
name: shadow-rule
description: Flag rules that are unreachable because an earlier rule with opposite action matches a superset of their traffic.
---

# Shadow Rule

**Reference implementation:** `fwrr.detectors.shadow_rule.ShadowRule` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `shadow-rule:0.1.0`
**Default severity:** High

## What it checks
Walks the ordered ruleset. For each rule `later`, tests whether an earlier rule `earlier` with opposite action matches a superset of `later`'s traffic tuple (source, destination, port, protocol, direction). When true, `later` is unreachable — the firewall will never evaluate it.

## Why this matters
Shadowed rules silently override operator intent. The ruleset reads as if it expresses a specific policy, but the effective behaviour is whatever the earlier rule dictates. This class of defect is invisible to visual inspection of large rulebases and commonly arises from incremental changes without holistic review. The most dangerous form: a specific deny shadowed by an earlier broad allow.

## Frameworks cited
- NIST CSF 2.0 — `PR.PS-01` (configuration management practices are established)
- CIS Controls v8.1 — `12.2` (establish and maintain a secure network architecture)
- ISO/IEC 27001:2022 — `A.8.9` (configuration management)

## v0.2 / v0.3 plans
- v0.2: partial-overlap detection — flag rules whose traffic is partially (not fully) shadowed, with the exact overlap quantified.
- v0.3: suggest minimal rule reordering / merge to eliminate shadowing while preserving semantic intent.
