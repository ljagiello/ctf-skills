# Standards and Framework Mapping

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| DE.CM-01 | Networks and network services are monitored to find potentially adverse events | Detonating Stratus techniques validates that cloud control-plane and network monitoring detects adversarial activity. |

## MITRE ATT&CK (Enterprise / Cloud)

| ID | Name | Rationale |
|----|------|-----------|
| T1078 | Valid Accounts | Stratus runs as a legitimate cloud identity; many techniques emulate abuse of valid accounts and credentials. |
| T1078.004 | Valid Accounts: Cloud Accounts | Credential-access and persistence techniques specifically abuse cloud account access. |
| T1580 | Cloud Infrastructure Discovery | Discovery-tactic techniques enumerate cloud resources. |
| T1530 | Data from Cloud Storage | Exfiltration techniques (e.g., EBS snapshot sharing) emulate cloud data theft. |
| T1098 | Account Manipulation | Persistence techniques create or modify privileged cloud principals. |

## Supporting References

- Datadog Stratus Red Team — https://stratus-red-team.cloud
- MITRE ATT&CK Cloud Matrix — https://attack.mitre.org/matrices/enterprise/cloud/
- NIST CSF 2.0 — https://www.nist.gov/cyberframework
