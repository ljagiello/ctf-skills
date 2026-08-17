<!-- ../detectors/admin-services-exposure.md -->
---
name: admin-services-exposure
description: Flag allow rules that expose administrative services (SSH, Telnet, RDP, SNMP, WinRM, VNC, admin HTTP/HTTPS). Critical when source is public (0.0.0.0/0, any, ::/0); High otherwise.
---

# Admin Services Exposure

**Reference implementation:** `fwrr.detectors.admin_services.AdminServicesExposure` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `admin-services-exposure:0.2.0`
**Default severity:** High (internal exposure) / Critical (public-source exposure)

## What it checks
Scans `action=allow` rules for destination ports in the admin-service set: 22 (SSH), 23 (Telnet), 80/443/8080/8443 (admin consoles), 161/162 (SNMP), 3389 (RDP), 5900 (VNC), 5985/5986 (WinRM). Port ranges that enclose an admin port also fire. Infrastructure-rule context filter (v0.2) suppresses loopback and established-state return-traffic noise.

## Why this matters
Administrative services grant device control when compromised. Exposure to the public internet enables credential stuffing and CVE chaining against the management plane. Internal any-source exposure enables lateral-movement pivoting after first foothold. Every network scanner enumerates these ports within seconds of reachability. Mature control frameworks require admin access to be gated by a jump host, MFA, and session recording — none of which are enforced at the firewall layer for flagged rules.

## Frameworks cited
- PCI DSS v4.0.1 — `8.4.2` (MFA for all access into the CDE), `2.2.7` (admin access over secure, unique channels)
- NIST CSF 2.0 — `PR.AA-05` (least privilege on access permissions)
- CIS Controls v8.1 — `5.3` (disable or secure dormant admin accounts / admin access)
- ISO/IEC 27001:2022 — `A.8.5` (secure authentication)

## v0.2 / v0.3 plans
- v0.2: infrastructure-rule sanity filter (shipped — skips `-i lo` and established-state returns).
- v0.3: management-zone detection — when a named management subnet object is present in the ruleset, downgrade internal-source admin exposures whose source matches the management zone to Info.
- v0.3: custom admin-port list override via policy file (teams that run admin panels on non-standard ports).
