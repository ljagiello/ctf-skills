---
name: aws-sg-parser
description: Parse AWS EC2 Security Group JSON exports from `aws ec2 describe-security-groups` into NormalizedRule objects, handling stateful semantics and SG-to-SG (source-group) references. Use when the engagement's Pre-requisites folder contains `.json` output of `describe-security-groups`; optionally pair with `describe-network-acls` for stateless NACL context.
---

# AWS Security Group Parser

**Reference implementation:** `fwrr.parsers.aws_sg.AwsSgParser` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `aws-sg:0.1.0`

## When this skill fires
The `fwrr launch` orchestrator dispatches this parser when a file in `Pre-requisites/aws-sg/` is `.json` and contains a top-level `SecurityGroups` array (the shape of `aws ec2 describe-security-groups --output json`). Optionally, `describe-network-acls` output may accompany it when NACL analysis was requested.

## Inputs it accepts
- `aws ec2 describe-security-groups --output json` (preferred, all SGs in region)
- Per-SG `aws ec2 describe-security-groups --group-ids sg-xxx -o json`
- Optional: `aws ec2 describe-network-acls --output json` for stateless NACL overlay (captured as a separate scope)

## Gotchas (v0.1 limitations)
- **Statefulness** — Security Groups are STATEFUL: return traffic for an allowed outbound connection is implicitly permitted, and vice versa. Detectors that compare inbound vs outbound must NOT flag missing mirror rules as gaps; the parser sets `stateful=true` on every SG rule so shadow/contradiction detectors can honour this.
- **SG-to-SG references** — a rule's source/destination can be another SG ID (`UserIdGroupPairs[*].GroupId`) instead of a CIDR. The parser records the referenced SG ID symbolically; effective-policy resolution (expanding to the ENIs/instances in that SG) is deferred to v0.3 and left to the `object-group-expansion` detector to rerun once a resolver is available.
- **Default SGs** — every VPC has a default SG with an implicit allow-all between members of the same SG; the parser captures this as a normal rule but tags `origin=default-sg` so detectors can recognise it.
- **No explicit deny** — AWS SGs only support ALLOW rules; deny is implicit. The `default-deny-presence` detector treats AWS SGs specially (implicit deny is acceptable HERE because it is a property of the platform, not operator intent).
- **NACLs** are stateless, numbered, per-subnet — when provided alongside, they are parsed into a sibling scope (`nacl:<id>`) and the `default-deny-presence` detector applies stricter rules (explicit deny IS expected on NACLs).

## Normalized schema it emits
See `fwrr.schema.NormalizedRule`. Rule IDs have the form `sg-<sg-id>:<direction>:<idx>` where direction is `ingress` or `egress`; scope is `sg:<sg-id>` (plus `vpc:<vpc-id>` on `raw`).

## Failure modes
- `UnsupportedFormatError` on invalid JSON or missing `SecurityGroups` array.
- Raw AWS JSON preserved on `raw` attribute of every rule — citation-verifier uses this for the audit-grade evidence trail.

## v0.2 / v0.3 plans
- v0.2: IAM-policy-aware analysis (does anyone have `ec2:AuthorizeSecurityGroupIngress`?).
- v0.3: SG-to-SG resolution by joining `describe-instances` + `describe-network-interfaces` to yield effective CIDR membership of referenced SGs.
