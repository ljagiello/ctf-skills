<!-- ../detectors/risky-service.md -->
---
name: risky-service
description: Flag allow rules that permit cleartext / legacy / unauthenticated services (Telnet, FTP, HTTP-mgmt, SMBv1, NetBIOS, rsh/rlogin, TFTP, SNMPv1/v2c, LDAP-cleartext).
---

# Risky Service

**Reference implementation:** `fwrr.detectors.risky_service.RiskyService` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `risky-service:0.1.0`
**Default severity:** High

## What it checks
Matches each allow rule's service/protocol/port against a pinned catalogue of risky services:
- Telnet (tcp/23), FTP (tcp/21), rsh/rlogin (tcp/512-514), TFTP (udp/69)
- HTTP-management planes, cleartext LDAP (tcp/389 without STARTTLS)
- SMBv1 / NetBIOS (tcp/139, udp/137-138)
- SNMPv1 / SNMPv2c (udp/161)

## Why this matters
Cleartext, legacy, or unauthenticated protocols facilitate credential theft, man-in-the-middle interception, and lateral movement. They are standard targets for attacker tooling and internal reconnaissance — and every one of them has a modern encrypted/authenticated equivalent that an organization can adopt.

## Frameworks cited
- PCI DSS v4.0.1 — `2.2.5` (if any insecure services/protocols are present, business justification documented and additional security features implemented)
- CIS Controls v8.1 — `4.4` (secure configuration of network infrastructure)
- NIST CSF 2.0 — `PR.PS-01` (configuration management practices are established)
- ISO/IEC 27001:2022 — `A.8.21` (security of network services)

## v0.2 / v0.3 plans
- v0.2: allow auditors to extend the risky-service catalogue via `.claude/pending/` proposals (learning loop).
- v0.3: per-asset criticality weighting — a risky service toward a PCI-scoped asset escalates to Critical automatically.
