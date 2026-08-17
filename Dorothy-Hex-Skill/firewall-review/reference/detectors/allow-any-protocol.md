<!-- ../detectors/allow-any-protocol.md -->
---
name: allow-any-protocol
description: Flag allow rules whose protocol field is `any`, `ip`, `-1`, or empty — the rule permits every IP-layer protocol regardless of how tight src/dst/port are.
---

# Allow Any Protocol

**Reference implementation:** `fwrr.detectors.allow_any_protocol.AllowAnyProtocol` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `allow-any-protocol:0.2.0`
**Default severity:** Medium

## What it checks
Scans `action=allow` rules whose `protocol` is `any`, `ip`, `-1` (AWS security-group wildcard), or empty string. Distinct from any-any-broadness — this fires on the protocol dimension alone, even when source, destination, and ports are all specifically scoped. Infrastructure-rule filter skips loopback and state-established returns.

## Why this matters
Most business flows need exactly one protocol — TCP for a web call, UDP for DNS, ICMP for ping. Allow-any-protocol usually indicates either the rule author did not know the destination's actual need or intentionally copied a permissive template. The hidden cost is that non-TCP/UDP protocols ride through unfiltered: GRE and IP-in-IP can tunnel arbitrary traffic the filter cannot inspect, ESP and AH bypass L4 proxies, and IPv6-in-IPv4 encapsulation defeats inspection stacks that only understand outer headers. The fix is always cheap — replace with the explicit `tcp` / `udp` / `icmp` the flow actually needs.

## Frameworks cited
- PCI DSS v4.0.1 — `1.2.1` (approved protocols, ports, and services with business justification)
- CIS Controls v8.1 — `4.4` (secure configuration of network infrastructure)
- NIST CSF 2.0 — `PR.AA-05` (access permissions enforced with least privilege)

## v0.2 / v0.3 plans
- v0.2: infrastructure-rule sanity filter (shipped).
- v0.3: protocol-usage heuristic from traffic logs — when flow telemetry is supplied, propose the narrowed protocol set that covers 99th-percentile observed traffic.
- v0.3: vendor-specific tuning — treat Cisco `ip` keyword differently from `any` (some ACL dialects use `ip` to mean "any IP protocol"; others mean "IPv4 only").
