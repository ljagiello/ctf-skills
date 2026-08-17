---
name: Audit report patterns (Nipper-class)
description: Technical patterns extracted from industry-standard firewall audit reports (Nipper Studio family + canonical audit-firm deliverables). Use when rendering client-facing PDFs to match audit-firm expectations. Zero client identifiers stored.
type: learning-pattern
source: real-engagement-distillation
---

# Nipper-class audit report — layout & content patterns

The following patterns are distilled from industry-standard commercial firewall audit reports (Nipper Studio family) and must be reproduced by our `/report` pipeline when the engagement is to be handed to a client. These are transferable techniques — no client names, device hostnames, or rule content are captured.

## Report section ordering (canonical)

1. **Cover page** — brand mark, tool name, engagement title, date
2. **Summary** — prose + bullet explanation of what the report contains (5 parts: Best Practice Security / Configuration / NIST NVD Vulnerability / PCI DSS / Filtering Complexity)
3. **Audit Scope** — table: `Device | Name | OS`
4. **Best Practice Security** — narrative + stats + TWO visuals:
   - Severity Classification (pie)
   - Issue Classification (line chart by CATEGORY: Admin, Auth, Clear-Text, Filter, Routing)
5. **Summary of findings per device** — `Device | Name | Findings | Highest Rating`
6. **Impact × Ease matrix** — 4×5 grid of counts:
   - Rows (Ease): Trivial / Easy / Moderate / Challenging
   - Columns (Severity): Informational / Low / Medium / High / Critical
   - Color-coded cells (green / yellow-green / orange / red gradient)
7. **NIST NVD vulnerability audit** — CVE matching against device software version (per-device table: device | critical | high | medium | low | info | total + DB-update date)
8. **PCI DSS 4.0 Assessment Summary** — Pass/Fail/Investigate/N/A pie + table + Impact×Ease matrix per outcome; tables of testing procedures (`Title | Testing Procedure | Status | Devices | Risk`)
9. **Filtering Complexity Summary** — separate issues class: `Title | Issue | Status | Devices | Risk`
10. **Contents / TOC** (appears mid-report in Nipper — at the end of the summary block, before the detailed body)
11. **Detailed body** — per-finding write-ups grouped by category with hyperlink cross-refs

## Best-Practice Security detector catalog (≈28 detectors)

This is the Nipper-class catalog. Our current pipeline ships 9 — below is the full set to implement:

### Authentication / access
- User Authentication With No Password
- Users With A Weak Authentication Password
- User Account Names Contained "admin"
- No Console Connection Timeout
- Long Session Timeout
- Weak Password Age Policy Setting
- Weak Minimum Password Length Policy Setting
- Weak Password Expiry Warning Policy Setting

### Banners & legal
- No Pre-Logon Banner Message
- No Post Logon Banner Message

### Rule broadness (expand our any-any-broadness into discrete flags)
- Filter Rules Allow From Any Source Address
- Filter Rules Allow To Any Destination Address
- Filter Rules Allow To Any Port
- Filter Rules Allow From A Subnet
- Filter Rules Allow To A Subnet
- Filter Rules Allow From A Network Address Range
- Filter Rules Allow Any Protocol
- Filter Rules Allow Any IP
- Filter Rules Allow ICMP
- Filter Rules Allow To Port Range

### Services
- Rules Allow Access To Administrative Services
- Rules Allow Access To Clear-Text Services
- Rules Allow Access To Potentially Sensitive Services
- Rules Allow Access To Potentially Unnecessary Services

### Structural / discipline
- Filter Rule List Does Not End With Drop All And Log
- Potentially Unused Network Interfaces
- Filter Rules Overlap Other Rules (RULES-OVERLAP)
- Filter Rules Contradict Other Rules (FILTER-RULES-CONTRADICT)
- Disabled Filter Rules Were Configured (DISABLED-FILTER-RULES)
- Filter Rules Configured With No Comments (RULES-NO-COMMENTS)

## Filtering Complexity audit (separate pass — 9 issues)

Independent of Best-Practice: the ruleset's maintainability hygiene.
- UNDEFINED-OBJECTS — object group reference with no definition
- UNUSED-OBJECTS — defined address/service objects never referenced
- EMPTY-OBJECT-GROUPS — defined groups with zero members
- OBJECT-GROUPS-THRESHOLD — object groups exceeding max-members threshold (vendor-specific)
- UNUSED-OBJECT-GROUPS — defined groups never referenced
- FILTER-RULES-CONTRADICT
- DISABLED-FILTER-RULES
- RULES-NO-COMMENTS
- RULES-OVERLAP

## PCI DSS 4.0 Testing-Procedure cross-reference

Each finding should map to **specific testing procedures**, not just control families. Example IDs observed:
- `2.2.4.b` `2.2.7.a` `2.2.7.c` `2.3.1.b` `2.2.5.b` `2.2.6.a` `2.2.6.b` `2.2.1.c` (Req 2 — secure configs)
- `8.2.8` `8.3.2.a` `8.3.4.a` `8.3.4.b` `8.3.6` `8.3.9` `8.3.7` `8.2.1.b` (Req 8 — authentication)
- `10.2.1` `10.2.1.3` `10.2.1.4` `10.2.1.5` `10.2.1.2` `10.2.2` `10.3.3` `10.6.1` `10.6.2` `10.6.3.a` (Req 10 — logging)
- `1.2.1.b` `1.2.5.b` `1.2.6.b` `1.3.1.b` `1.3.2.b` `1.3.3` `1.4.1.b` `1.4.2` `1.4.3` `1.4.4.b` `1.4.5.a` (Req 1 — network security controls)

**Status per procedure**: `Pass` / `Fail` / `Investigate` / `N/A` — this is a richer model than just approve/reject.

## NIST NVD vulnerability audit

A pass independent of the ruleset audit — matches the device software version (e.g. `FortiOS 7.4.9`) against the NIST NVD CVE database. Emits severity counts per device. DB update date must be printed. Even if zero CVEs, the section appears with an explicit "no vulnerabilities" statement + "absence of evidence ≠ evidence of absence" caveat.

## Device OS identification

Parsers must extract and surface `OS / firmware version` (e.g. FortiOS 7.4.9, PAN-OS 11.2.4, IOS-XE 17.09) — required for the NVD audit pass and for scope Table 1.

## Visual palette

Nipper uses a **PURPLE primary** (approx `#6B5B95`) for section headers, with severity pills:
- Critical: `#E53935` (red)
- High:     `#FB8C00` (orange)
- Medium:   `#FDD835` (amber)
- Low:      `#8BC34A` (lime)
- Informational: `#43A047` (green)
- Pass:     `#2E7D32`
- Fail:     `#C62828`
- Investigate: `#F9A825`
- N/A:      `#757575`

**Matrix cells** use diagonal-gradient (green top-left → red bottom-right) — cells colored by severity implied by row×column intersection, NOT by content count.

## Hyperlink cross-refs

PCI testing procedure IDs in tables are hyperlinks jumping to the detail section (anchor: `#proc-2.2.4.b`). Finding titles in the summary are hyperlinks too. Required for PDFs.

## Status labels on row cells

Nipper uses colored pill-labels for Pass/Fail/Investigate/N/A (not text alone) — large, bold, white-on-color. Our existing severity pills already follow this pattern; extend to status.

## Tables per finding category

Each best-practice category (Authentication / Rule Broadness / Services / Structural) gets its own sub-section with rows of: `Title | Testing Procedure | Status | Devices | Risk`.

## Integration notes for our pipeline

- Our 9 detectors need to be **split** into Nipper-style granular detectors (e.g. `any-any-broadness` → 10 separate detectors, one per broadness class). Granularity improves client-side remediation planning.
- Add **NVD module**: `scripts/audit-nvd.py <device-fingerprint>` → queries offline NVD mirror (local-first per NORTH STAR memory).
- Add **config-audit module**: password policy, banner messages, admin accounts — not just filter rules.
- Add **filtering complexity module**: object-group hygiene + rule-comment discipline.
- Report structure must be **TOC-hyperlinked** for PDF navigation; page numbers and anchors.
- Save every engagement's *patterns* (not data) to `.claude/pending/` so the curator learning loop can surface recurring real-world issues (e.g. "3 of last 5 engagements flagged UNUSED-OBJECT-GROUPS > 50% of defined groups — detector severity should auto-upgrade to Medium when ratio > 50%").
