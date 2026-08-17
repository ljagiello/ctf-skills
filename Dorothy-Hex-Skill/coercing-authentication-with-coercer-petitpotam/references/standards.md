# Standards Mapping — Coercing Authentication with Coercer and PetitPotam

## MITRE ATT&CK (Enterprise)

| ID | Name | Rationale |
|----|------|-----------|
| T1187 | Forced Authentication | Coercer and PetitPotam abuse RPC methods (MS-EFSR, MS-RPRN, MS-DFSNM, MS-FSRVP) to force a target's machine account to authenticate to an attacker-controlled host — the textbook definition of forced authentication. |

Reference: https://attack.mitre.org/techniques/T1187/

Chained techniques:
- T1557.001 (Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB/NTLM Relay) — relaying the coerced auth.
- T1649 (Steal or Forge Authentication Certificates) — when relayed into AD CS web enrollment (ESC8).

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| DE.CM-01 | Networks and network services are monitored to find potentially adverse events | Coercion produces detectable RPC calls and inbound NTLM authentication to non-standard hosts; this skill exercises and validates the monitoring needed to catch forced-authentication and relay activity. |

Reference: https://csrc.nist.gov/projects/cybersecurity-framework

## Mitigation references
- Microsoft KB5005413 (NTLM relay to AD CS mitigation), Extended Protection for Authentication (EPA).
- Disable Print Spooler on DCs (MS-RPRN), enforce SMB/LDAP signing.
