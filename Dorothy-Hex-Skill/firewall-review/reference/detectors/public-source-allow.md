<!-- ../detectors/public-source-allow.md -->
---
name: public-source-allow
description: Flag inbound allow rules whose source is a public (non-RFC1918 / non-loopback) address range.
---

# Public-Source Allow

**Reference implementation:** `fwrr.detectors.public_source_allow.PublicSourceAllow` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `public-source-allow:0.1.0`
**Default severity:** Critical

## What it checks
For each `action=allow` rule with `direction=inbound`, tests whether the source CIDR falls outside RFC1918 (10/8, 172.16/12, 192.168/16), loopback (127/8), or link-local ranges. `any` and `0.0.0.0/0` are treated as public.

## Why this matters
Internet-facing allow rules are actively probed within minutes of exposure. An internal resource reachable from a public source bypasses every network-segmentation control the organization has built. Most breach post-mortems cite an un-audited public-source permit as the initial access vector.

## Frameworks cited
- NIST CSF 2.0 — `PR.IR-01` (networks protected from unauthorized logical access)
- PCI DSS v4.0.1 — `1.4.1` (NSCs implemented between trusted and untrusted networks)
- CIS Controls v8.1 — `12.2` (establish and maintain a secure network architecture)
- ISO/IEC 27001:2022 — `A.8.20` (networks security)

## v0.2 / v0.3 plans
- v0.2: integrate shared threat-intel feeds to auto-enrich public sources with known-malicious-ASN context.
- v0.3: detect allow-from-public on services that should never be internet-exposed (SMB, RDP, LDAP, database ports) and escalate to immediate-block recommendation.
