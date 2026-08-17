---
name: palo-alto-parser
description: Parse Palo Alto PAN-OS firewall exports (XML or set-format) into NormalizedRule objects. Use when the engagement's Pre-requisites folder contains `<config>` XML or `set`-prefixed CLI dumps from PAN-OS.
---

# Palo Alto PAN-OS Parser

**Reference implementation:** `fwrr.parsers.panos.PanosParser` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `panos:0.1.0`

## When this skill fires
The `fwrr launch` orchestrator dispatches this parser when a file in `Pre-requisites/palo-alto/` has `.xml` extension and contains a `<rulebase>/<security>/<rules>` element, OR a `.txt`/`.cfg` with `set` lines.

## Inputs it accepts
- `show config running` XML (preferred, canonical)
- `show | match ^set` set-format dump
- Exports from Panorama and standalone firewalls

## Gotchas (v0.1 limitations)
- Panorama device-group inheritance (pre-rules → DG pre → local → DG post → shared post) is **not yet resolved** — v0.3 adds this.
- Application-ID (`application any` vs specific) is preserved in the `application` field but is NOT currently used by the detector suite.
- Security profile groups are captured as `raw` text but not expanded.

## Normalized schema it emits
See `fwrr.schema.NormalizedRule`. Rule IDs have the form `panos-<scope>:<rule-name>` where `<scope>` is `vsys:<name>` or `dg:<name>` (Panorama).

## Failure modes
- `UnsupportedFormatError` on malformed XML or missing `<rulebase>/<security>/<rules>`.
- Raw text preserved on `raw` attribute for every rule — citation-verifier uses this for the audit-grade evidence trail.
