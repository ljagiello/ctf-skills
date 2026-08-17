<!-- ../detectors/any-any-broadness.md -->
---
name: any-any-broadness
description: Flag allow rules whose source, destination, or port fields are set to `any`. Severity scales with the count of `any` fields (1 = Medium, 2 = High, 3 = Critical).
---

# Any-Any Broadness

**Reference implementation:** `fwrr.detectors.any_any_broadness.AnyAnyBroadness` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `any-any-broadness:0.1.0`
**Default severity:** Medium / High / Critical (scales with `any`-field count on an allow rule)

## What it checks
Counts how many of `{source, destination, port}` are set to `any` on each `action=allow` rule. Emits one finding per offending rule with severity scaling by breadth.

## Why this matters
Any-any allow rules directly violate least privilege. They inflate the blast radius of any compromise and are the single most common finding in mature audit reports — routinely exploited once an internal foothold is gained. Narrowing them is the highest-leverage remediation an auditor can recommend.

## Frameworks cited
- NIST CSF 2.0 — `PR.AA-05` (access permissions enforced with least privilege)
- PCI DSS v4.0.1 — `1.3.1` (restrict inbound/outbound traffic to that which is necessary)
- CIS Controls v8.1 — `4.4` (secure configuration of network infrastructure)
- ISO/IEC 27001:2022 — `A.8.22` (segregation of networks)

## v0.2 / v0.3 plans
- v0.2: weight severity by destination-asset criticality when asset inventory is supplied alongside the ruleset.
- v0.3: propose narrowed replacement rules using observed traffic logs (suggested src/dst/port tuples that cover 95th-percentile flows).
