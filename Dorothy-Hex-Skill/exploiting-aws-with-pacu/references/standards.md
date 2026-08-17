# Standards and Framework Mapping

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| PR.AA-05 | Access permissions, entitlements, and authorizations are defined, managed, enforced, and reviewed | Pacu privesc scanning demonstrates where IAM entitlements are over-permissive and exploitable, driving least-privilege remediation. |

## MITRE ATT&CK (Enterprise / Cloud)

| ID | Name | Rationale |
|----|------|-----------|
| T1078.004 | Valid Accounts: Cloud Accounts | Pacu operates as a valid AWS principal abusing its granted permissions. |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | `iam__backdoor_users_keys` adds a second access key for persistence. |
| T1098.003 | Account Manipulation: Additional Cloud Roles | Role-trust backdoors and privesc via policy modification. |
| T1580 | Cloud Infrastructure Discovery | EC2/IAM enumeration modules. |
| T1530 | Data from Cloud Storage | S3 bucket download. |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Exploitation of EC2 IMDS-derived credentials. |

## Supporting References

- Pacu — https://github.com/RhinoSecurityLabs/pacu
- AWS IAM Privilege Escalation methods — https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- NIST CSF 2.0 — https://www.nist.gov/cyberframework
