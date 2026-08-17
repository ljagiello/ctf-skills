# GraphRunner Module Reference

Import with `Import-Module .\GraphRunner.ps1`. Run `List-GraphRunnerModules` for the live list.

## Authentication
| Function | Purpose |
|----------|---------|
| `Get-GraphTokens` | Device-code login; returns `$tokens` object (access + refresh) |
| `Invoke-RefreshGraphTokens` | Refresh the access token from the refresh token |
| `Invoke-AutoTokenRefresh` | Background auto-refresh during long operations |
| `Invoke-ImportTokens` | Import externally captured access/refresh tokens |
| `Invoke-RefreshToSharePointToken` | Exchange a Graph token for a SharePoint token |
| `Get-AzureAppTokens` / `Invoke-RefreshAzureAppTokens` | App (consent-grant) token flow |
| `Invoke-AutoOAuthFlow` / `Invoke-BruteClientIDAccess` | OAuth consent flow helpers |

## Recon & Enumeration
| Function | Purpose |
|----------|---------|
| `Invoke-GraphRecon` | Tenant + current-user permission summary (`-PermissionEnum`) |
| `Invoke-DumpCAPS` | Dump conditional-access policies (`-ResolveGuids`) |
| `Invoke-DumpApps` | App registrations, service principals, consent grants, reply URLs |
| `Get-AzureADUsers` | Enumerate all users (`-OutFile`) |
| `Get-SecurityGroups` / `Get-DirectoryRoles` | Enumerate groups / directory roles |
| `Get-UpdatableGroups` | Groups the current principal can modify (privesc) |
| `Get-DynamicGroups` | Dynamic membership groups |
| `Invoke-SearchUserAttributes` | Search all user attributes for a term (`-SearchTerm`) |
| `Invoke-GraphOpenInboxFinder` | Find mailboxes readable by the current user |
| `Find-PermissiveCalendars` | Find over-shared calendars |
| `Invoke-CheckAccess` | Check token validity/scope |
| `Get-EntraIDGroupInfo` / `Invoke-GroupLookup` | Group detail lookups |

## Privilege Escalation / Account Manipulation
| Function | Purpose |
|----------|---------|
| `Invoke-AddGroupMember` | Add a member to a group (`-GroupId -UserId`) |
| `Invoke-RemoveGroupMember` | Remove a group member |
| `Invoke-SecurityGroupCloner` | Clone a group's membership into a controlled group |
| `Create-SecurityGroupWithMembers` | Create a group with chosen members |
| `Invoke-InviteGuest` | Invite an external guest account |

## Persistence
| Function | Purpose |
|----------|---------|
| `Invoke-InjectOAuthApp` | Deploy a malicious OAuth app (`-AppName -ReplyUrl -Scope`) |
| `Invoke-DeleteOAuthApp` | Remove an injected app (cleanup) |
| `Invoke-CreateInboxForwardingRule` | Hidden inbox forwarding rule (`-ForwardTo -RuleName`) |

## Pillage / Data Search
| Function | Purpose |
|----------|---------|
| `Invoke-SearchMailbox` | Search mailbox(es) (`-SearchTerm -MessageCount -OutFile`) |
| `Invoke-SearchSharePointAndOneDrive` | Search SharePoint/OneDrive (`-SearchTerm`) |
| `Get-SharePointSiteURLs` | Enumerate SharePoint sites |
| `Invoke-DriveFileDownload` | Download a drive item (`-DriveItemIDs -FileName`) |
| `Invoke-SearchTeams` | Search Teams messages (`-SearchTerm`) |
| `Get-TeamsChat` / `Get-TeamsChannels` / `Get-TeamsApps` | Teams enumeration |
| `Get-Inbox` / `Invoke-ImmersiveFileReader` | Read inbox / files |

## Orchestration
| Function | Purpose |
|----------|---------|
| `Invoke-GraphRunner` | Automated recon + pillage pass |
| `List-GraphRunnerModules` | Print all available modules |

## Underlying Graph endpoints (examples)
| Action | Endpoint |
|--------|----------|
| List users | `GET https://graph.microsoft.com/v1.0/users` |
| List groups | `GET https://graph.microsoft.com/v1.0/groups` |
| Add group member | `POST /groups/{id}/members/$ref` |
| Search mail | `GET /me/messages?$search="term"` |
| Create app | `POST /applications` |
| Mail forwarding rule | `POST /me/mailFolders/inbox/messageRules` |
