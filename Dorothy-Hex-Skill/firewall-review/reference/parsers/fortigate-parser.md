---
name: fortigate-parser
description: Parse Fortinet FortiGate `show full-configuration` / `execute backup config` output into NormalizedRule objects, preserving per-VDOM scope. Use when the engagement's Pre-requisites folder contains FortiOS config dumps with `config firewall policy` blocks, optionally under `config vdom` partitions.
---

# FortiGate (FortiOS) Parser

**Reference implementation:** `fwrr.parsers.fortigate.FortigateParser` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `fortigate:0.1.0`

## When this skill fires
The `fwrr launch` orchestrator dispatches this parser when a file in `Pre-requisites/fortigate/` contains `config firewall policy` blocks. Typical export commands: `show full-configuration` (CLI) or `execute backup config` (full device backup).

## Inputs it accepts
- `show full-configuration` (preferred, flattened CLI)
- `execute backup config` (device backup, contains all VDOMs)
- FortiOS 6.4 / 7.0 / 7.2 / 7.4 exports

## Gotchas (v0.1 limitations)
- **VDOMs** — multi-VDOM devices wrap each VDOM in a `config vdom` / `edit <name>` / `config firewall policy` tree. The parser captures each VDOM as a distinct scope; rules from `root` VDOM are NOT merged with customer VDOMs. A single firewall can legitimately have wildly different policies per VDOM and the auditor needs to see them separately.
- **Implicit deny:** FortiGate has an implicit deny at end-of-policy per VDOM; the `default-deny-presence` detector does NOT trust it (must be explicit to be audit-grade).
- `config firewall address` / `addrgrp` / `service` / `service-group` objects are captured by name on raw; the `object-group-expansion` detector (C.8) handles effective-policy rerun.
- UTM profiles (AV, IPS, webfilter, app-control) are preserved on `raw` but not currently scored.
- HA clusters: primary's exported config is used; standby's config is assumed identical (not verified in v0.1).

## Normalized schema it emits
See `fwrr.schema.NormalizedRule`. Rule IDs have the form `fgt-vdom:<vdom>:<policy-id>` — scope always begins `vdom:` (even single-VDOM devices use `vdom:root`).

## Failure modes
- `UnsupportedFormatError` when no `config firewall policy` block is present.
- Raw FortiOS CLI text preserved on `raw` attribute of every rule — citation-verifier uses this for the audit-grade evidence trail.

## Partial-export detection (IMPORTANT for audit-defensibility)

Clients frequently supply incomplete FortiGate exports. The parser must not silently skip these — they MUST be surfaced to the operator with the likely reason + re-export command. Two patterns seen in the wild:

**Pattern A — Multi-VDOM device exported from `config global` context only.**

First line of file: `<hostname> # config global` followed by `show full-configuration`. File ends cleanly with `end` and `(global) #` prompt. Contains plenty of `config system *` / `config wireless-controller *` stanzas but ZERO `config firewall policy` blocks — because policies live under `config vdom / edit <vdom>`, which wasn't captured. Check `config-version=` header: if it shows `vdom-mode=multi-vdom` (or the file contains `set vdom-mode multi-vdom`), confirm the pattern.

Re-export command: `config global` + `show full-configuration` + `end` + `config vdom` + `edit <vdom-name>` + `show full-configuration` (repeat per VDOM in scope).

**Pattern B — Truncated export (SSH session drop mid-capture).**

File tail contains `Connection lost. Press Enter to start a new session.` or similar abort marker, typically mid-stanza (e.g. partial `config firewall address` block). Zero policy blocks because the stream was cut before `config firewall policy` was emitted. Single-VDOM VM configs are the usual victims.

Re-export command: same `show full-configuration` as before, but with unlimited scrollback on the SSH client (PuTTY: Lines of scrollback = 200000; iTerm2: unlimited) and no idle-disconnect timeout. Consider `execute backup config tftp ...` which streams to a file rather than terminal.

**What the orchestrator should do:** when `can_parse()` succeeds (config-version sentinel present) but `parse()` yields 0 `NormalizedRule`s, raise a `PartialExportWarning` rather than returning silently. The `/launch` command spec instructs Claude to move such configs to `engagement-dir/_deferred/<name>` with a README explaining why, and disclose them explicitly in the final report's §10 Limitations section.

## v0.2 / v0.3 plans
- v0.2: UTM profile scoring (`ips-sensor`, `av-profile`, `webfilter-profile`).
- v0.3: inter-VDOM link analysis + FortiManager ADOM inheritance resolution.
