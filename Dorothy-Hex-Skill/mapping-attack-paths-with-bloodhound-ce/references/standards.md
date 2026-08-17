# Standards and Framework Mapping

## NIST CSF 2.0

| ID | Name | Rationale |
|----|------|-----------|
| ID.AM-03 | Organizational communication and data flows are mapped | BloodHound graphs the identity/permission "data flows" between principals across AD and Entra, mapping how privilege propagates through the environment. |

## MITRE ATT&CK

| ID | Name | Rationale |
|----|------|-----------|
| T1069 | Permission Groups Discovery | Core technique: SharpHound/AzureHound enumerate group memberships and inter-principal permissions to build the attack graph. |
| T1087 | Account Discovery | Collectors enumerate user, computer, and service-principal accounts. |
| T1482 | Domain Trust Discovery | Domain/forest trusts are collected and rendered as graph edges. |
| T1018 | Remote System Discovery | Domain computers and their session/local-admin relationships are enumerated. |

## Supporting References

- SpecterOps BloodHound CE documentation — https://bloodhound.specterops.io/
- SharpHound collection methods — https://bloodhound.specterops.io/collect-data/ce-collection/sharphound-flags
- AzureHound usage — https://github.com/SpecterOps/AzureHound
- MITRE ATT&CK Enterprise — https://attack.mitre.org/
