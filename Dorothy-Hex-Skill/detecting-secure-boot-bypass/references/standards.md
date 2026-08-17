# Standards and Framework Mapping

## MITRE ATT&CK

| ID | Name | Rationale |
|----|------|-----------|
| T1542.003 | Pre-OS Boot: Bootkit | Core technique — bootkit subverts the boot chain below the OS to persist. |
| T1542 | Pre-OS Boot | Parent technique for firmware/boot-component tampering. |
| T1542.001 | Pre-OS Boot: System Firmware | Firmware modification used to weaken or bypass Secure Boot. |
| T1014 | Rootkit | Bootkits deliver rootkit-level stealth and persistence. |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Post-bypass, BlackLotus disables BitLocker/HVCI/Defender. |

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| DE.CM-01 | Networks and network services are monitored to find potentially adverse events | Applied here to boot-chain/firmware integrity monitoring — verifying Secure Boot, dbx, and EFI binaries surfaces tampering. |

## Supporting Standards and References

- **CVE-2022-21894 (Baton Drop).** Vulnerable signed Windows boot manager abused by BlackLotus to bypass Secure Boot.
- **CVE-2023-24932.** Secure Boot Security Feature Bypass; remediated via phased dbx revocation rollout (Microsoft KB5025885).
- **NSA UEFI Secure Boot Customization guidance.** Hardening and verification of the UEFI Secure Boot trust chain.
- **NIST SP 800-147 / 800-193 — Platform Firmware Resiliency.** Protection, detection, and recovery requirements for firmware integrity.
- **UEFI Specification — Secure Boot (db/dbx/KEK/PK).** Authoritative source for the variable model checked in this skill.
