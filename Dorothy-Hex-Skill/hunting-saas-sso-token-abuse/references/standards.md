# Standards and Framework Mapping

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| DE.CM-01 | Networks and network services are monitored to find potentially adverse events | Hunting SSO/OAuth token replay across identity logs is continuous monitoring of authentication services for adverse events. |

## MITRE ATT&CK (Enterprise / Cloud)

| ID | Name | Rationale |
|----|------|-----------|
| T1550.001 | Use Alternate Authentication Material: Application Access Token | Core hunted technique — replaying stolen OAuth tokens/cookies. |
| T1539 | Steal Web Session Cookie | The cookie theft that enables pass-the-cookie. |
| T1528 | Steal Application Access Token | Token acquisition via phishing/illicit consent. |
| T1078.004 | Valid Accounts: Cloud Accounts | Replayed tokens provide valid-account SaaS access. |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | Follow-on persistence after token abuse. |

## Supporting References

- MITRE ATT&CK T1550.001 — https://attack.mitre.org/techniques/T1550/001/
- Microsoft Entra sign-in log schema — https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-azure-monitor-sign-ins-log-schema
- Okta System Log API — https://developer.okta.com/docs/reference/api/system-log/
- Mandiant M-Trends — https://www.mandiant.com/m-trends
- NIST CSF 2.0 — https://www.nist.gov/cyberframework
