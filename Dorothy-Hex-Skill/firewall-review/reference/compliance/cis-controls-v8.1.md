<!-- ../compliance/cis-controls-v8.1.md -->
---
name: cis-controls-v8.1
description: CIS Critical Security Controls, version 8.1, published June 2024. Used for every finding's framework_refs. Version drift (e.g., v8.0 May 2021 safeguards) is a citation-verifier quarantine reason.
---

# CIS Critical Security Controls v8.1

**Published:** June 2024 (minor revision of v8.0, which was May 2021)
**Source:** https://www.cisecurity.org/controls
**Pinned version:** 8.1

## Controls cited by our detectors

Union of docs/BENCHMARK.md mappings and `framework_refs=[...]` blocks emitted in [`lib/fwrr/detectors/*.py`](https://github.com/ipunithgowda/firewall-review/blob/main/lib/fwrr/detectors/*.py). The citation-verifier compares finding payloads against this list — any safeguard NOT here is held for QA review.

| Control | Title | Cited by detectors |
|---|---|---|
| 4.1 | Establish and maintain a secure configuration process | any-any-broadness, allow-any-protocol, admin-services, default-deny-presence, rules-no-comments, duplicate-rule, shadow-rule, contradicting-rule, object-group-expansion, port-range-too-broad, unused-rule |
| 4.4 | Implement and manage a firewall on servers | any-any-broadness, allow-any-ip, allow-any-protocol, port-range-too-broad, risky-service |
| 4.7 | Manage default accounts on enterprise assets and software | rules-no-comments |
| 5.3 | Disable dormant accounts | admin-services |
| 8.2 | Collect audit logs | rules-end-with-drop-all-and-log |
| 12.1 | Ensure network infrastructure is up-to-date | public-source-allow, allow-icmp |
| 12.2 | Establish and maintain a secure network architecture | allow-any-ip, public-source-allow, allow-icmp, duplicate-rule, shadow-rule |
| 12.5 | Centralize network authentication, authorization, and auditing (AAA) | any-any-broadness, allow-public-source |
| 12.6 | Use of secure network management and communication protocols | cleartext-service |
| 13.4 | Perform traffic filtering between network segments | default-deny-presence, unused-rule |

## Citation format

`{"framework": "CIS_Controls_v8.1", "control_id": "<ID>", "version": "8.1"}`

Example: `{"framework": "CIS_Controls_v8.1", "control_id": "4.1", "version": "8.1"}`

## Citation-verifier behaviour

- Controls listed above: pass.
- Controls NOT listed above: hold for manual review by the QA reviewer.
- Wrong version (e.g. v7.1 `Control 11.1` "Maintain Standard Security Configurations for Network Devices"): quarantined.

## Pitfalls (CIS v8.1-specific)

- **v8.1 was published June 2024, NOT May 2021.** May 2021 was v8.0. v8.1 added Governance (a new function-level grouping) and aligned terminology with NIST CSF 2.0. Pin `version: "8.1"`, never `"8.0"` or `"8"`.
- **v7.1 → v8.0 was a structural rewrite** — controls renumbered, "sub-controls" renamed to "safeguards", count reduced from 20 to 18. Any detector emitting `CSC 1.1`-style v7 IDs is on a stale mapping.
- **Implementation Groups (IG1/IG2/IG3) are not control IDs.** A finding may note "IG1 baseline" as context but the `control_id` field must be the safeguard number (e.g., `4.1`), never `"IG1"`.
- **Safeguard 4.1 vs 4.4** — easy to confuse: 4.1 is the *configuration process* (do you have one?); 4.4 is *firewall on servers* (is it actually deployed?). Many of our detectors cite both because they cover both gaps; preserve the distinction.
- **Safeguard 5.3 "Disable dormant accounts"** is cited by admin-services for a reason: when admin ports are exposed to broad source IPs, the dormant-account control is what stops a stale credential from being the breach vector. Don't drop it just because it sounds like an identity control.
- **CIS uses "Control N" for the top-level family and "Safeguard N.M" for the specific item.** Our `control_id` always carries the safeguard form (`12.2`), not the family form (`12`).
