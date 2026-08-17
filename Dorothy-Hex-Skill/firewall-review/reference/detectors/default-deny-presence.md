<!-- ../detectors/default-deny-presence.md -->
---
name: default-deny-presence
description: Flag rulesets that lack an explicit catch-all deny rule at end-of-ruleset. Runs first; gates contradicting-rule detector.
---

# Default-Deny Presence

**Reference implementation:** `fwrr.detectors.default_deny_presence.DefaultDenyPresence` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `default-deny-presence:0.1.0`
**Default severity:** Critical

## What it checks
The final rule in the evaluated ruleset must be an explicit `action=deny` rule matching `source=any`, `destination=any`, `port=any`. Implicit vendor default-deny behaviour is not audit-grade and is not trusted by this detector.

## Why this matters
Rulesets that rely on implicit deny are brittle: operators routinely append new allow rules without inspecting the tail, which can flip semantic intent silently. An explicit catch-all deny at end-of-ruleset gives reviewers a visible, grep-able terminator and prevents accidental permit-by-omission.

## Frameworks cited
- NIST CSF 2.0 — `PR.IR-01` (networks protected from unauthorized access)
- PCI DSS v4.0.1 — `1.2.1` (network security control standards)
- CIS Controls v8.1 — `13.4` (traffic filtering between segments)
- ISO/IEC 27001:2022 — `A.8.20` (networks security)

## v0.2 / v0.3 plans
- v0.2: per-vendor benchmark tie-in (CIS Cisco ASA §3.x; CIS FortiGate 7 equivalent; CIS PAN-OS equivalent).
- v0.3: composite analysis across multiple firewalls (does the composite effective policy terminate in deny?).
