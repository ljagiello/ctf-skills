# Standards and Framework Mapping

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| PR.AA-05 | Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, incorporating least privilege and separation of duties | GraphRunner abuses over-broad Graph permissions, updatable groups, and OAuth consent; the engagement validates whether PR.AA-05 least-privilege controls actually constrain a token holder. |

## MITRE ATT&CK (Enterprise)

| ID | Name | Rationale |
|----|------|-----------|
| T1098 | Account Manipulation | Adding group members, cloning groups, inviting guests to retain/escalate access. |
| T1098.003 | Account Manipulation: Additional Cloud Roles | Adding members to privileged/updatable groups. |
| T1528 | Steal Application Access Token | `Get-GraphTokens` device-code token acquisition. |
| T1087.004 | Account Discovery: Cloud Account | `Get-AzureADUsers`, `Invoke-SearchUserAttributes`. |
| T1114.002 | Email Collection: Remote Email Collection | `Invoke-SearchMailbox` via Graph. |
| T1606.002 | Forge Web Credentials: SAML/OAuth | `Invoke-InjectOAuthApp` consent-grant persistence. |
| T1564.008 | Hide Artifacts: Email Hiding Rules | `Invoke-CreateInboxForwardingRule`. |

## Detection cross-reference

GraphRunner activity surfaces in `MicrosoftGraphActivityLogs` and `AADGraphActivityLogs`; OAuth app injection appears in audit logs as "Add service principal" / "Consent to application"; group manipulation appears as "Add member to group". These map to NIST DE.CM-09 (computing hardware/software/runtime monitoring) for the defensive counterpart.
