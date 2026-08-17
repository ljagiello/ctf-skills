# Standards Mapping — Abusing Shadow Credentials for Privilege Escalation

## MITRE ATT&CK (Enterprise)

| ID | Name | Rationale |
|----|------|-----------|
| T1098.005 | Account Manipulation: Device Registration | Writing an attacker-controlled Key Credential to `msDS-KeyCredentialLink` registers an alternate device/certificate credential for the target, which is exactly the device-registration manipulation this sub-technique describes. |

Reference: https://attack.mitre.org/techniques/T1098/005/

Related techniques exercised in the chain:
- T1649 (Steal or Forge Authentication Certificates) — the PKINIT certificate used to authenticate.
- T1550.003 / T1558 — using the recovered TGT/hash for movement.

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| PR.AA-05 | Access permissions, entitlements, and authorizations are defined, managed, and enforced incorporating least privilege and separation of duties | The attack is only possible because of over-permissive ACEs (`GenericWrite`/`GenericAll`/`AddKeyCredentialLink`) on AD objects; remediation is least-privilege enforcement of who may write Key Credentials. |

Reference: https://csrc.nist.gov/projects/cybersecurity-framework
