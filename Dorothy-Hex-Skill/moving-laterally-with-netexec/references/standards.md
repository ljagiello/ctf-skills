# Standards and References — Moving Laterally with NetExec

## MITRE ATT&CK References

| Technique ID | Name | Tactic | Rationale |
|-------------|------|--------|-----------|
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Lateral Movement | NetExec authenticates to `ADMIN$`/`C$` and runs code on remote hosts |
| T1110.003 | Brute Force: Password Spraying | Credential Access | `--continue-on-success` sprays one password across many accounts |
| T1003.002 | OS Credential Dumping: Security Account Manager | Credential Access | `--sam` extracts local account hashes |
| T1003.004 | OS Credential Dumping: LSA Secrets | Credential Access | `--lsa` extracts LSA secrets and cached domain creds |
| T1003.006 | OS Credential Dumping: DCSync | Credential Access | `--ntds` replicates the domain database via DRSUAPI |
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | Credential Access | `ldap --kerberoasting` requests crackable service tickets |
| T1087.002 | Account Discovery: Domain Account | Discovery | `--users` / `--rid-brute` enumerate domain accounts |
| T1135 | Network Share Discovery | Discovery | `--shares` enumerates accessible SMB shares |

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| DE.CM-01 | Networks and network services are monitored to find potentially adverse events | NetExec activity (mass auth, exec, dumping) is the adverse behavior defenders must detect; this skill informs detection coverage |

## Official Resources

- NetExec GitHub: https://github.com/Pennyw0rth/NetExec
- NetExec Wiki: https://www.netexec.wiki/
- Selecting a protocol: https://www.netexec.wiki/getting-started/selecting-and-using-a-protocol
- Impacket: https://github.com/fortra/impacket
- MITRE ATT&CK T1021.002: https://attack.mitre.org/techniques/T1021/002/

## Key Research

- Black Hills InfoSec: Getting Started with NetExec
- StationX: NetExec Cheat Sheet (2026 Guide)
- Vaadata: NetExec, the Tool for Auditing an Internal Network
