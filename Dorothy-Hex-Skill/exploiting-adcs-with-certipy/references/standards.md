# Standards Mapping — Exploiting AD CS with Certipy

## MITRE ATT&CK (Enterprise)

| ID | Name | Rationale |
|----|------|-----------|
| T1649 | Steal or Forge Authentication Certificates | Certipy requests, relays, and forges AD CS certificates that map to privileged principals, enabling PKINIT authentication as those principals. |

Reference: https://attack.mitre.org/techniques/T1649/

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| PR.AA-05 | Access permissions, entitlements, and authorizations are defined, managed, and enforced incorporating least privilege and separation of duties | AD CS template enroll rights, CA management permissions, and PKI object ACLs are exactly the access-control surface this skill tests; ESC1-ESC16 all stem from over-permissive entitlements. |

Reference: https://csrc.nist.gov/projects/cybersecurity-framework

## Notes
- ESC8/ESC11 chain Forced Authentication (T1187) and Adversary-in-the-Middle (T1557) when combined with coercion + relay; those are covered in companion skills.
- Remediation maps to NIST PR.PS-01 (hardening baselines) for CA/template configuration.
