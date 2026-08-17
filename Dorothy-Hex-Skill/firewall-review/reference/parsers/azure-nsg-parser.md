---
name: azure-nsg-parser
description: Parse Azure Network Security Group (NSG) JSON exports from `az network nsg show` into NormalizedRule objects, preserving subnet- and NIC-level attachment scope. Use when the engagement's Pre-requisites folder contains one `.json` per NSG.
---

# Azure NSG Parser

**Reference implementation:** `fwrr.parsers.azure_nsg.AzureNsgParser` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `azure-nsg:0.1.0`

## When this skill fires
The `fwrr launch` orchestrator dispatches this parser when a file in `Pre-requisites/azure-nsg/` is `.json` and contains `"type": "Microsoft.Network/networkSecurityGroups"` (or the equivalent Azure REST body). Typical export command: `az network nsg show -g <RG> -n <NSG> -o json`, one JSON per NSG.

## Inputs it accepts
- Azure CLI `az network nsg show` output (preferred)
- ARM template / REST API response bodies with `securityRules` and `defaultSecurityRules` arrays
- NSGs exported from any Azure region / sovereign cloud

## Gotchas (v0.1 limitations)
- **Subnet vs NIC attachment** — an NSG can be attached at the subnet level AND/OR at individual NIC level. Traffic is evaluated against BOTH when both apply, with NIC rules evaluated after subnet rules. The parser records `subnetAttachments` and `networkInterfaceAttachments` on each rule's scope so downstream detectors can reason about cumulative effective policy. Missing attachment data (common when `--expand` is omitted) is captured but flagged on `raw.attachment_source = "missing"`.
- **Default rules** — every NSG has 6 Azure-managed `defaultSecurityRules` (AllowVnetInBound, AllowAzureLoadBalancerInBound, DenyAllInBound, AllowVnetOutBound, AllowInternetOutBound, DenyAllOutBound). The parser emits these but tags them `origin=default` so the `default-deny-presence` detector can recognise them without treating them as customer intent.
- **Priority + direction** — rules are evaluated per-direction (`Inbound` / `Outbound`) ordered by `priority` ascending. Rule IDs include direction to avoid shadow/contradiction false positives across directions.
- Service tags (`Internet`, `VirtualNetwork`, `AzureCloud.<region>`, etc.) are preserved as symbolic sources/destinations; IP-range resolution of service tags is deferred to v0.3.
- Application Security Groups (ASGs) are captured by name; membership expansion is v0.3.

## Normalized schema it emits
See `fwrr.schema.NormalizedRule`. Rule IDs have the form `nsg-<nsg-name>:<direction>:<priority>:<rule-name>`; scope is `nsg:<nsg-name>` plus `attached-to:` suffix for the subnet/NIC list.

## Failure modes
- `UnsupportedFormatError` on invalid JSON or missing `properties.securityRules` array.
- Raw Azure JSON preserved on `raw` attribute of every rule — citation-verifier uses this for the audit-grade evidence trail.

## v0.2 / v0.3 plans
- v0.2: Azure Firewall policy parser (separate skill, same family).
- v0.3: service-tag IP expansion + ASG membership resolution + composite subnet/NIC effective-policy evaluation.
