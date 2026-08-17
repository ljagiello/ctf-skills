---
name: cisco-ios-parser
description: Parse Cisco IOS / IOS-XE `show running-config` output into NormalizedRule objects, covering named and numbered ACLs bound via `ip access-group`. Use when the engagement's Pre-requisites folder contains IOS config dumps with `access-list` / `ip access-list` and `ip access-group` bindings.
---

# Cisco IOS Parser

**Reference implementation:** `fwrr.parsers.cisco_ios.CiscoIosParser` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `cisco-ios:0.1.0`

## When this skill fires
The `fwrr launch` orchestrator dispatches this parser when a file in `Pre-requisites/cisco-ios/` contains `ip access-list {standard|extended} <name>` or legacy numbered `access-list <n>` lines AND at least one `ip access-group <name> {in|out}` binding under an interface.

## Inputs it accepts
- `show running-config` full dump (preferred)
- `show running-config | section access-list` + `show running-config | section interface` combined
- IOS 15.x, IOS-XE 16.x/17.x router and L3-switch exports

## Gotchas (v0.1 limitations)
- **Named vs numbered ACLs** — both must be supported; numbered standard ACLs (1-99, 1300-1999) have only source; numbered extended ACLs (100-199, 2000-2699) have source/dest/protocol. The parser preserves the numeric class on `raw` for audit provenance.
- **Direction matters:** `ip access-group <name> in` vs `out` on a given interface produces two distinct effective-policy scopes; the parser treats them as separate rule scopes.
- Reflexive ACLs (`evaluate <name>`), `object-group` references (IOS 12.4T+), and time-ranges are captured as `raw` but not expanded in v0.1.
- VRF-aware ACLs are flagged on `raw.vrf` but composite VRF analysis is deferred.

## Normalized schema it emits
See `fwrr.schema.NormalizedRule`. Rule IDs have the form `ios-<iface>:<acl-name>:<seq>` where `<iface>` is the interface binding and `<seq>` is the ACL sequence number (or synthesized if absent).

## Failure modes
- `UnsupportedFormatError` when no ACL definitions or no `ip access-group` bindings are present.
- Raw IOS text preserved on `raw` attribute of every rule — citation-verifier uses this for the audit-grade evidence trail.

## v0.2 / v0.3 plans
- v0.2: object-group (IOS 12.4T+) expansion parity with Cisco ASA.
- v0.3: reflexive / established / zone-based firewall (ZBF) rule-map expansion.
