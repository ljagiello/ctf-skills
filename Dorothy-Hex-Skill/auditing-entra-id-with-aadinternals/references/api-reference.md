# AADInternals Cmdlet Reference

## Installation

```powershell
Install-Module AADInternals -Scope CurrentUser
Import-Module AADInternals
```

## Reconnaissance (no credentials)

| Cmdlet | Key parameters | Purpose |
|--------|----------------|---------|
| `Invoke-AADIntReconAsOutsider` | `-DomainName <fqdn>` | Verified domains, tenant ID, federation type, brand, Desktop SSO |
| `Get-AADIntLoginInformation` | `-Domain <fqdn>` | getuserrealm login/realm details |
| `Get-AADIntTenantID` | `-Domain <fqdn>` | Tenant GUID |
| `Invoke-AADIntUserEnumerationAsOutsider` | `-UserName <upn>` | Validate user existence |

## Token Acquisition (credentials required)

| Cmdlet | Key parameters | Purpose |
|--------|----------------|---------|
| `Get-AADIntAccessTokenForAADGraph` | `-SaveToCache`, `-Credentials`, `-KerberosTicket` | Azure AD Graph (graph.windows.net) token |
| `Get-AADIntAccessTokenForMSGraph` | `-SaveToCache` | Microsoft Graph token |
| `Get-AADIntAccessTokenForEXO` | `-SaveToCache` | Exchange Online token |
| `Get-AADIntAccessTokenForOneDrive` | `-Tenant`, `-SaveToCache` | SharePoint/OneDrive token |
| `Get-AADIntAccessTokenForAzureCoreManagement` | `-SaveToCache` | Azure Resource Manager token |

## Authenticated Enumeration

| Cmdlet | Purpose |
|--------|---------|
| `Get-AADIntTenantDetails` | Tenant configuration overview |
| `Get-AADIntUsers` | Enumerate directory users (UPN, DirSync, ImmutableId) |
| `Get-AADIntGlobalAdmins` | List Global Administrators |
| `Get-AADIntServicePrincipals` | Enumerate service principals |

## Federation / AD FS / Golden SAML

| Cmdlet | Key parameters | Purpose |
|--------|----------------|---------|
| `Export-AADIntADFSSigningCertificate` | `-Path <pfx>` | Export AD FS token-signing certificate |
| `Get-AADIntADFSConfiguration` | `-Server <fqdn>` | Read AD FS configuration |
| `ConvertTo-AADIntBackdoor` | `-DomainName <fqdn>`, `-AccessToken` | Convert a domain to a federation backdoor (sets IssuerUri) |
| `New-AADIntBackdoor` | `-DomainName`, `-Issuer` | Create a backdoor federated domain |
| `New-AADIntSAMLToken` | `-ImmutableID`, `-Issuer`, `-UseBuiltInCertificate` | Forge a SAML token for a user |
| `Open-AADIntOffice365Portal` | `-SAMLToken` | Open a portal session as the impersonated user |

## Notes

- Many enumeration cmdlets consume the AAD Graph token cached by `-SaveToCache`.
- `ConvertTo-AADIntBackdoor` requires a Global Administrator AAD Graph token.
- The cross-platform AsOutsider-only reimplementation is `synacktiv/AADOutsider-py`.
