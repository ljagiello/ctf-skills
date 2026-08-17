# Standards and References — Abusing DPAPI for Credential Access

## NIST CSF 2.0

| ID | Name | Rationale |
|----|------|-----------|
| DE.CM-01 | Networks and network services are monitored to find potentially adverse events | DPAPI abuse generates detectable signals (MS-BKRP backup-key RPC to the DC, Protect/Credentials folder access, LSASS access) that monitoring must surface. |

## MITRE ATT&CK

| Technique ID | Name | Tactic | Rationale |
|--------------|------|--------|-----------|
| T1555.004 | Credentials from Password Stores: Windows Credential Manager | Credential Access | DPAPI protects Credential Manager/Vault entries; decrypting them recovers stored credentials. |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Credential Access | SharpChrome decrypts DPAPI-protected browser logins/cookies. |
| T1003 | OS Credential Dumping | Credential Access | Extracting master keys and the domain backup key dumps credential material. |

## Supporting Frameworks and Standards

- **MS-BKRP** — BackupKey Remote Protocol; the RPC interface used to retrieve the domain DPAPI backup key.
- **MS-DPSP / DPAPI** — Microsoft's Data Protection API specification governing master keys and blob protection.
- **D3FEND** — Credential Eviction / Password Rotation as mitigations after DPAPI compromise.

## Official Resources

- SharpDPAPI / SharpChrome: https://github.com/GhostPack/SharpDPAPI
- Mimikatz: https://github.com/gentilkiwi/mimikatz
- Impacket: https://github.com/fortra/impacket
- DonPAPI: https://github.com/login-securite/DonPAPI
- HackTricks DPAPI: https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords.html
- SpecterOps "Operational Guidance for Offensive User DPAPI Abuse": https://posts.specterops.io/operational-guidance-for-offensive-user-dpapi-abuse-1fb7fac8b107
