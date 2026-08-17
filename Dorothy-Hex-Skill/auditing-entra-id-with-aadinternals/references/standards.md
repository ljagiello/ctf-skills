# Standards and Framework Mapping

## NIST CSF 2.0

| ID | Name | Rationale |
|----|------|-----------|
| ID.AM-03 | Organizational communication and data flows are mapped | Outsider recon and authenticated enumeration map the tenant's identity surface, federation trust flows, and which APIs/tokens reach which data. |

## MITRE ATT&CK

| ID | Name | Rationale |
|----|------|-----------|
| T1606.002 | Forge Web Credentials: SAML Tokens | Core technique: AADInternals' federation backdoor + `New-AADIntSAMLToken` forge SAML tokens (Golden SAML) for arbitrary users. |
| T1087.004 | Account Discovery: Cloud Account | Outsider/authenticated user enumeration. |
| T1528 | Steal Application Access Token | `Get-AADIntAccessTokenFor*` token acquisition and reuse. |
| T1556.007 | Modify Authentication Process: Hybrid Identity | Federation/PTA backdoor establishment. |

## Supporting References

- AADInternals documentation — https://aadinternals.com/aadinternals/
- Golden SAML / federation backdoor — https://aadinternals.com/post/aadbackdoor/
- MITRE T1606.002 — https://attack.mitre.org/techniques/T1606/002/
- NIST CSF 2.0 — https://www.nist.gov/cyberframework
