<!-- ../compliance/nist-csf-2.md -->
---
name: nist-csf-2
description: NIST Cybersecurity Framework 2.0, version 2.0, published February 2024. Used for every finding's framework_refs. Version drift (e.g., 1.1 PR.AC-* artefacts) is a citation-verifier quarantine reason.
---

# NIST Cybersecurity Framework 2.0

**Published:** February 2024
**Source:** https://www.nist.gov/cyberframework
**Pinned version:** 2.0

## Controls cited by our detectors

Union of docs/BENCHMARK.md mappings and `framework_refs=[...]` blocks emitted in [`lib/fwrr/detectors/*.py`](https://github.com/ipunithgowda/firewall-review/blob/main/lib/fwrr/detectors/*.py). The citation-verifier compares finding payloads against this list — any control NOT here is held for QA review.

| Control | Title | Cited by detectors |
|---|---|---|
| GV.PO-01 | Policy for managing cybersecurity risks is established based on organizational context, cybersecurity strategy, and priorities | rules-no-comments |
| ID.AM-08 | Systems, hardware, software, services, and data are managed throughout their life cycles | unused-rule |
| PR.AA-01 | Identities and credentials for authorized users, services, and hardware are managed | object-group-expansion |
| PR.AA-05 | Access permissions, entitlements, and authorizations are managed and enforced (least privilege) | any-any-broadness, public-source-allow, admin-services, allow-any-ip, allow-any-protocol, port-range-too-broad |
| PR.IR-01 | Networks and environments are protected from unauthorized logical access and usage | any-any-broadness, allow-any-ip, allow-any-protocol, public-source-allow, allow-public-source, admin-services, allow-icmp, default-deny-presence, duplicate-rule, shadow-rule, contradicting-rule, port-range-too-broad |
| PR.DS-02 | The confidentiality, integrity, and availability of data-in-transit are protected | cleartext-service |
| PR.PS-01 | Configuration management practices are established and used | shadow-rule, contradicting-rule, risky-service |
| DE.CM-01 | Networks and network services are monitored to find potentially adverse events | rules-end-with-drop-all-and-log, unused-rule |
| DE.AE-03 | Information is correlated from multiple sources | rules-end-with-drop-all-and-log |

## Citation format

`{"framework": "NIST_CSF_2.0", "control_id": "<ID>", "version": "2.0"}`

Example: `{"framework": "NIST_CSF_2.0", "control_id": "PR.AA-05", "version": "2.0"}`

## Citation-verifier behaviour

- Controls listed above: pass.
- Controls NOT listed above: hold for manual review by the QA reviewer.
- Wrong version (e.g. `PR.AC-03` is a CSF 1.1 artefact): quarantined.

## Pitfalls (CSF 2.0-specific)

- **`PR.AC-*` is RETIRED in CSF 2.0.** The Access Control category was restructured in 2.0; legacy `PR.AC-*` IDs map to the new `PR.AA-*` family (Authentication & Access). Any detector or persona that still emits `PR.AC-*` will quarantine — fix at source, do not silently rewrite to `PR.AA-*` in the report.
- **`GV.*` is new in 2.0.** The Govern function did not exist in 1.1. Reports generated against pre-2024 baselines will not have `GV.PO-01`-style citations; do not back-port.
- **Subcategory IDs were renumbered**, not renamed. `PR.IP-*` (1.1) does not equal `PR.PS-*` (2.0); `PR.DS-*` survived but its subcategory numbers shifted. Always verify against the published 2.0 SP 800-* mapping, not muscle memory.
- **`DE.AE-03` exists in both 1.1 and 2.0** but with different scope. Pinned-version check protects against accidental cross-version citation.
