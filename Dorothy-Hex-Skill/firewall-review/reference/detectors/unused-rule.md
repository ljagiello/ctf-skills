<!-- ../detectors/unused-rule.md -->
---
name: unused-rule
description: Flag rules with zero hits over the supplied observation window. If no traffic-log hit counts are provided, emits RequiresManualReview findings.
---

# Unused Rule

**Reference implementation:** `fwrr.detectors.unused_rule.UnusedRule` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `unused-rule:0.1.0`
**Default severity:** Info (confirmed unused) / RequiresManualReview (no log data)

## What it checks
For each rule, looks up a hit-count from `DetectorContext.hit_counts`. If `hits == 0` over the observation window, emits an Info finding recommending removal or replacement with an explicit deny. If `hit_counts` is absent, emits a RequiresManualReview finding per rule asking the engagement owner to supply traffic logs.

## Why this matters
Unused rules accumulate attack surface, confuse subsequent reviews, and mask the current operational truth of the ruleset. The RequiresManualReview path is first-class here: the tool refuses to auto-fill unknown usage. Auditors receive an evidence-backed determination or an explicit "cannot be determined" note — never a guess.

## Frameworks cited
- CIS Controls v8.1 — `13.4` (traffic filtering between segments)
- NIST CSF 2.0 — `DE.CM-01` (networks and network services are monitored)

## v0.2 / v0.3 plans
- v0.2: accept per-vendor native hit-count formats (ASA `show access-list` counters, FortiGate session counters, PAN-OS rule-hit-count XML) via a parser sidecar.
- v0.3: rolling 90-day observation window with age-weighted severity — rules unused for >90 days auto-upgrade to Low.
