---
name: cisco-asa-parser
description: Parse Cisco ASA `show running-config` output into NormalizedRule objects, expanding `object-group` references to effective policy. Use when the engagement's Pre-requisites folder contains ASA config dumps (`.cfg` / `.txt`) with `access-list`, `object-group`, and `access-group` stanzas.
---

# Cisco ASA Parser

**Reference implementation:** `fwrr.parsers.cisco_asa.CiscoAsaParser` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `cisco-asa:0.1.0`

## When this skill fires
The `fwrr launch` orchestrator dispatches this parser when a file in `Pre-requisites/cisco-asa/` contains `access-list` lines bound by `access-group <name> in interface <iface>`. Typical export command: `show running-config` (captured to `.cfg`).

## Inputs it accepts
- `show running-config` full dump (preferred)
- `show running-config access-list` + `show running-config object-group` + `show running-config access-group` (combined)
- Standalone ASA 9.x, ASAv, and multi-context exports (one context per file)

## Gotchas (v0.1 limitations)
- **Object-group expansion:** nested `object-group network` / `object-group service` references are captured by name on the raw rule; full cartesian expansion into effective policy is handled by the `object-group-expansion` detector (C.8), not by the parser. This matters because one `permit tcp any object-group WEB-FARM object-group WEB-PORTS` can hide dozens of effective rules.
- Multi-context (security context) ASA: each admin context must be exported separately; the parser treats each file as one scope.
- `access-list` remarks and inactive rules are captured on `raw` but skipped from effective analysis.
- Time-ranges, user-identity, and FQDN object-groups are preserved as `raw` but not resolved in v0.1.

## Normalized schema it emits
See `fwrr.schema.NormalizedRule`. Rule IDs have the form `asa-<scope>:<acl-name>:<line>` where `<scope>` is the interface name bound by `access-group` (e.g. `outside`, `inside`).

## Failure modes
- `UnsupportedFormatError` when no `access-list` lines present or no `access-group` binding can be located.
- Raw ASA text preserved on `raw` attribute of every rule — citation-verifier uses this for the audit-grade evidence trail.

## v0.2 / v0.3 plans
- v0.2: resolve time-ranges and user-identity object-groups.
- v0.3: multi-context composite analysis across admin contexts.
