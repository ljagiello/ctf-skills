<!-- ../detectors/allow-icmp.md -->
---
name: allow-icmp
description: Flag allow rules permitting ICMP. Medium when source or destination is broad (`any`, `0.0.0.0/0`); Low when both sides are scoped.
---

# Allow ICMP

**Reference implementation:** `fwrr.detectors.allow_icmp.AllowIcmp` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `allow-icmp:0.2.0`
**Default severity:** Low (scoped both sides) / Medium (broad source or destination)

## What it checks
Scans `action=allow` rules whose `protocol` is `icmp` (case-insensitive). Emits one finding per rule. Severity lifts from Low to Medium when the source or destination contains `any`, `0.0.0.0/0`, or `::/0`. Infrastructure-rule filter suppresses loopback and state-established return traffic.

## Why this matters
ICMP has legitimate diagnostic uses — echo-request/reply, path-MTU discovery, destination-unreachable — but broad ICMP allows expose the network to three distinct attack classes. OS fingerprinting reads TTL and code fields to identify hosts. ICMP type-8 tunneling is a well-known covert-channel technique (icmpsh, ptunnel, loki) that bypasses L4 egress filtering. Smurf-class amplification attacks abuse broadcast ICMP replies. Restricting to named ICMP types (echo-request, fragmentation-needed, time-exceeded) and blocking type-13 (timestamp) from untrusted sources closes most of this surface without breaking diagnostics.

## Frameworks cited
- CIS Controls v8.1 — `12.2` (establish and maintain a secure network architecture)
- NIST CSF 2.0 — `PR.IR-01` (networks and environments are protected from unauthorized logical access)
- ISO/IEC 27001:2022 — `A.8.20` (network security)

## v0.2 / v0.3 plans
- v0.2: infrastructure-rule sanity filter (shipped).
- v0.3: ICMP-type awareness — parse `icmp-type echo-request` specifiers in Cisco/iptables/PAN-OS; downgrade to Info when only safe diagnostic types are permitted.
- v0.3: egress-direction weighting — outbound-ICMP-any from internal segments is the typical tunnel vector; surface that subset as Medium even when destination is scoped.
