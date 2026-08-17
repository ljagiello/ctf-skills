<!-- ../detectors/rules-end-with-drop-all-and-log.md -->
---
name: rules-end-with-drop-all-and-log
description: Flag rule lists whose terminal rule is not an explicit deny/drop/reject, or does not log. Grouped by (vendor, chain) — one finding per chain.
---

# Rules End With Drop-All And Log

**Reference implementation:** `fwrr.detectors.rules_end_with_drop_all.RulesEndWithDropAll` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `rules-end-with-drop-all-and-log:0.2.0`
**Default severity:** Medium (has deny, missing log) / High (missing deny)

## What it checks
Groups rules by `(vendor, chain)` where chain comes from the scope's `chain:` marker (fallback to full scope). Within each chain, sorts by `priority` then `source_lineno` and checks the last rule. Emits a finding when the terminal rule is not `deny`/`drop`/`reject`, or when it is but does not log. Distinct from default-deny-presence: both conditions must hold on the terminal rule — deny AND log.

## Why this matters
A terminal drop-all-and-log rule does two things. It makes the deny explicit on platforms whose default might be allow (or ambiguous under policy drift). It produces an audit trail for denied traffic — without logging, incident responders have no forensic visibility into what the firewall was asked to pass and refused. On platforms without an explicit deny-all, a silent policy change upstream can implicitly widen access without any log signal. The recommendation is a single catch-all rule: `action=deny, source=any, destination=any, protocol=any, logging=enabled, description="catch-all deny — DO NOT REMOVE"`.

## Frameworks cited
- PCI DSS v4.0.1 — `10.2.1.4` (log all access to audit trails), `1.2.1` (deny-all default for inbound/outbound)
- CIS Controls v8.1 — `8.2` (collect audit logs)
- NIST CSF 2.0 — `DE.AE-03` (event data collected and correlated)

## v0.2 / v0.3 plans
- v0.2: chain-only grouping (shipped) — previous per-scope grouping flagged sub-scopes whose natural terminal was an ACCEPT (e.g. the lone `-i lo` ACCEPT in iptables INPUT). A chain has exactly one terminal rule.
- v0.3: default-policy awareness — on iptables, treat `:INPUT DROP [0:0]` in `scope_metadata` as a satisfactory terminal-deny (no explicit `-A INPUT -j DROP` needed).
- v0.3: vendor-specific log-verb detection — Cisco `log-input`, PAN-OS `log-end` / `log-start`, FortiGate `set logtraffic all`.
