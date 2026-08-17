<!-- ../detectors/port-range-too-broad.md -->
---
name: port-range-too-broad
description: Flag allow rules with destination port ranges wider than 32 ports. Medium up to 1024 ports, High beyond.
---

# Port Range Too Broad

**Reference implementation:** `fwrr.detectors.port_range_too_broad.PortRangeTooBroad` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `port-range-too-broad:0.1.0`
**Default severity:** Medium (33-1024 ports) / High (>1024 ports)

## What it checks
Scans `action=allow` rules for destination-port specifications using `-` or `:` as range separators (`1024-65535`, `49152:65535`). Computes the span as `hi - lo + 1`. Emits a finding when the widest range in the rule exceeds the 32-port threshold. Infrastructure-rule filter skips loopback and state-established returns.

## Why this matters
Wide port ranges usually indicate either a legacy fat-client protocol (that the architect never narrowed) or a copy-paste from a default template. Every extra port is an extra attack surface the business flow does not need. A 32000-port range opens 32000 opportunities for an attacker to find an unexpected service running in the destination VLAN. Port ranges also degrade SIEM correlation quality — alerting on "traffic to 445" is high-fidelity; alerting on "traffic to 1024-65535" is noise. The fix is usually to enumerate the 1-4 ports the flow actually needs. When a genuine range is required (ephemeral FTP-DATA, RPC), the rule comment should document the business case.

## Frameworks cited
- PCI DSS v4.0.1 — `1.2.1` (approved protocols, ports, and services with business justification)
- CIS Controls v8.1 — `4.4` (secure configuration of network infrastructure)
- NIST CSF 2.0 — `PR.AA-05` (access permissions enforced with least privilege)

## v0.2 / v0.3 plans
- v0.2: configurable threshold via policy file (default 32) — some orgs want stricter (>8) or looser (>256).
- v0.2: infrastructure-rule sanity filter (align with other detectors).
- v0.3: traffic-log intersection — when flow telemetry is supplied, report the actual port-usage percentile within the range and propose the narrowed set covering 99th-percentile observed traffic.
