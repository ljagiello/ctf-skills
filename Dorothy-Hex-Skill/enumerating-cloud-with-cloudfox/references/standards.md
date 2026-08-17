# Standards and Framework Mapping

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| ID.AM-03 | Organizational communication and data flows are mapped (asset/inventory management) | CloudFox builds an attacker-centric inventory of cloud assets, identities, and trust relationships, informing asset-management gaps. |

## MITRE ATT&CK (Enterprise / Cloud)

| ID | Name | Rationale |
|----|------|-----------|
| T1526 | Cloud Service Discovery | CloudFox enumerates available cloud services and resources. |
| T1580 | Cloud Infrastructure Discovery | Inventory/instances/buckets map the infrastructure footprint. |
| T1087.004 | Account Discovery: Cloud Account | `principals`/`access-keys` enumerate cloud identities. |
| T1069.003 | Permission Groups Discovery: Cloud Groups | `permissions`/`role-trusts` reveal cloud entitlements. |
| T1538 | Cloud Service Dashboard | Aggregated cross-service situational awareness. |

## Supporting References

- BishopFox CloudFox — https://github.com/BishopFox/cloudfox
- NIST CSF 2.0 — https://www.nist.gov/cyberframework
