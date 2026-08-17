# Standards Mapping

## MITRE ATT&CK

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| T1528 | Steal Application Access Token | Credential Access | Device-code and illicit-consent phishing cause Entra ID to mint OAuth access/refresh tokens to the attacker; the stolen bearer tokens are then reused to access cloud services without re-authenticating. |

### Related techniques chained in this workflow
| ID | Name | Rationale |
|----|------|-----------|
| T1566 | Phishing | Delivery vector for the device-code message or consent URL. |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | Replaying the stolen OAuth tokens against M365 resources. |
| T1098.003 | Account Manipulation: Additional Cloud Roles | Illicit-consent grants persist as a service-principal OAuth grant surviving password resets. |

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| PR.AA-03 | Users, services, and hardware are authenticated | The attack defeats authentication assurance by abusing the OAuth device-code grant to bypass MFA; the control objective being tested is robust, phishing-resistant authentication. |

## References
- RFC 8628 — OAuth 2.0 Device Authorization Grant: https://datatracker.ietf.org/doc/html/rfc8628
- MITRE ATT&CK T1528: https://attack.mitre.org/techniques/T1528/
- NIST CSF 2.0: https://www.nist.gov/cyberframework
- Mandiant M-Trends: https://cloud.google.com/security/resources/m-trends
