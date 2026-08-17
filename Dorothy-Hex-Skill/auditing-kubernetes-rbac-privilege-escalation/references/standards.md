# Standards and References - Kubernetes RBAC Privilege Escalation Audit

## MITRE ATT&CK

| Technique ID | Name | Tactic | Rationale |
|--------------|------|--------|-----------|
| T1078 | Valid Accounts | Defense Evasion / Privilege Escalation | RBAC abuse leverages legitimate service-account credentials to gain higher access. |
| T1098 | Account Manipulation | Persistence | `escalate`/`bind`/`impersonate` and token minting create or modify accounts/bindings. |
| T1528 | Steal Application Access Token | Credential Access | Reading `secrets` or `serviceaccounts/token` yields other accounts' tokens. |
| T1613 | Container and Resource Discovery | Discovery | Enumerating roles, bindings, and pod-to-SA mappings. |
| T1611 | Escape to Host | Privilege Escalation | `create pods` plus node access yields a privileged host-mounting pod. |

## NIST CSF 2.0

| ID | Name | Rationale |
|----|------|-----------|
| PR.AA-05 | Access permissions, entitlements, and authorizations are defined, managed, and enforced incorporating least privilege | The audit directly measures and enforces least-privilege RBAC, removing escalation primitives. |

## Official Resources

- Kubernetes RBAC Good Practices: https://kubernetes.io/docs/concepts/security/rbac-good-practices/
- Using RBAC Authorization: https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- Authorization Overview (`auth can-i`): https://kubernetes.io/docs/reference/access-authn-authz/authorization/
- rbac-police: https://github.com/PaloAltoNetworks/rbac-police
- kubectl-who-can: https://github.com/aquasecurity/kubectl-who-can
- rakkess: https://github.com/corneliusweig/rakkess
- rbac-lookup: https://github.com/FairwindsOps/rbac-lookup

## Key Research

- Unit 42: Kubernetes RBAC privilege escalation research
- Kubernetes SIG-Auth: documented privilege-escalation primitives (escalate, bind, impersonate)
