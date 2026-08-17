# Standards and Framework Mapping

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| ID.AM-03 | Representations of the organization's authorized network communication and internal/external network data flows are maintained | ROADrecon enumeration produces the directory/identity asset inventory that defenders must maintain and that attackers exploit; the engagement validates visibility of this asset surface. |

## MITRE ATT&CK (Enterprise)

| ID | Name | Rationale |
|----|------|-----------|
| T1087.004 | Account Discovery: Cloud Account | ROADrecon enumerates Entra ID user/account objects. |
| T1069.003 | Permission Groups Discovery: Cloud Groups | ROADrecon enumerates Entra groups and directory roles. |
| T1538 | Cloud Service Dashboard | GUI exploration of tenant configuration and policies. |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | roadtx refresh-token exchange across resources (FOCI). |
| T1528 | Steal Application Access Token | roadtx token/PRT acquisition. |

## Reference standards

| Standard | Relevance |
|----------|-----------|
| Microsoft identity platform (OAuth 2.0 / OIDC) | Defines the auth-code, ROPC, device-code, and refresh-token flows roadtx exercises. |
| FOCI (Family of Client IDs) | Microsoft first-party client family enabling cross-client refresh-token redemption. |
| Primary Refresh Token (PRT) | Device-bound SSO artifact abused via roadtx prt/prtauth. |
