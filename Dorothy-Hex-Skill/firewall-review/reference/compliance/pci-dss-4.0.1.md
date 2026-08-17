<!-- ../compliance/pci-dss-4.0.1.md -->
---
name: pci-dss-4.0.1
description: PCI Data Security Standard, version 4.0.1, published June 2024. Used for every finding's framework_refs. Version drift (e.g., v3.2.1 Req 2.4) is a citation-verifier quarantine reason.
---

# PCI DSS v4.0.1

**Published:** June 2024 (errata revision of v4.0; v4.0 originally March 2022)
**Source:** https://www.pcisecuritystandards.org/document_library/
**Pinned version:** 4.0.1

## Controls cited by our detectors

Union of docs/BENCHMARK.md mappings and `framework_refs=[...]` blocks emitted in [`lib/fwrr/detectors/*.py`](https://github.com/ipunithgowda/firewall-review/blob/main/lib/fwrr/detectors/*.py). The citation-verifier compares finding payloads against this list — any requirement NOT here is held for QA review.

| Control | Title | Cited by detectors |
|---|---|---|
| Req 1 | Install and Maintain Network Security Controls | allow-public-source |
| Req 1.2.1 | Configuration standards for NSC rulesets are defined, implemented, and maintained | any-any-broadness, allow-any-ip, allow-any-protocol, allow-icmp, default-deny-presence, port-range-too-broad, rules-end-with-drop-all-and-log |
| Req 1.2.5 | Ports, protocols, and services allowed are identified, approved, and have documented business justification | public-source-allow |
| Req 1.2.7 | Configurations of NSCs are reviewed at least once every six months | rules-no-comments |
| Req 1.3.1 | Inbound traffic to the CDE is restricted to that which is necessary | any-any-broadness, allow-any-ip |
| Req 1.4.1 | NSCs are implemented between trusted and untrusted networks | public-source-allow |
| Req 2.2 | System components are configured and managed securely | admin-services |
| Req 2.2.5 | If insecure services, protocols, or daemons are present, they are justified and additional features documented | risky-service |
| Req 2.2.7 | All non-console administrative access is encrypted using strong cryptography | admin-services |
| Req 4 | Protect cardholder data with strong cryptography during transmission over open, public networks | cleartext-service |
| Req 4.2.1 | Strong cryptography and security protocols protect PAN during transmission | cleartext-service |
| Req 7.2 | Access to system components and data is appropriately defined and assigned | public-source-allow |
| Req 8.1 | Processes and mechanisms for identifying users and authenticating access to system components are defined and understood | admin-services |
| Req 8.3.2 | Strong cryptography is used to render all authentication factors unreadable during transmission and storage | cleartext-service |
| Req 8.4.2 | MFA is implemented for all non-console access into the CDE | admin-services |
| Req 10 | Log and monitor all access to system components and cardholder data | rules-end-with-drop-all-and-log |
| Req 10.2.1.4 | Audit logs capture all invalid logical access attempts | rules-end-with-drop-all-and-log |

## Citation format

`{"framework": "PCI_DSS_v4.0.1", "control_id": "<ID>", "version": "4.0.1"}`

Example: `{"framework": "PCI_DSS_v4.0.1", "control_id": "1.2.1", "version": "4.0.1"}`

## Citation-verifier behaviour

- Controls listed above: pass.
- Controls NOT listed above: hold for manual review by the QA reviewer.
- Wrong version (e.g. v3.2.1 `Req 2.4` was REMOVED in v4.0.x; v3.2.1 `Req 1.1.x` was restructured into v4 `Req 1.2.x`): quarantined.

## Pitfalls (PCI DSS 4.0.1-specific)

- **v3.2.1 Req 1.1.x (firewall configuration standards) was renumbered to v4.0.x Req 1.2.x.** Legacy auditor templates citing `Req 1.1.4` (the famous "deny by default") now belong under `Req 1.2.1`. Do not back-port.
- **v3.2.1 Req 2.4 (inventory of system components) was REMOVED in v4.0.x** and folded into Req 12.5. Any detector emitting `Req 2.4` is on a stale mapping.
- **v4.0 (March 2022) vs v4.0.1 (June 2024).** v4.0.1 is an *errata* — control numbers are stable, but applicability notes and testing procedures shifted. Pin `version: "4.0.1"`, never `"4.0"`.
- **"Future-dated" controls (effective 2025-03-31)** in v4.0.1 — e.g., 8.4.2 MFA-for-all-CDE-access — were "best practice" until that date and "required" after. Findings citing them today must surface that the requirement is now in force.
- **Req 1.2.1 vs Req 1.3.1.** Easy to confuse: 1.2.1 is the *configuration standard* (does a documented ruleset baseline exist?); 1.3.1 is *inbound traffic restriction* (is the inbound CDE perimeter actually tight?). Detector pairing in BENCHMARK keeps these separate — preserve the distinction in narrative.
