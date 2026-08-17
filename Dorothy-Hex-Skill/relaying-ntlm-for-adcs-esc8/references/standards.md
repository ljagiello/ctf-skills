# Standards and References — Relaying NTLM for ADCS ESC8

## NIST CSF 2.0

| ID | Name | Rationale |
|----|------|-----------|
| DE.CM-01 | Networks and network services are monitored to find potentially adverse events | ESC8 produces detectable network signals: forced authentication (coercion), NTLM relay to the AD CS HTTP endpoint, and anomalous machine-account certificate enrollment. |

## MITRE ATT&CK

| Technique ID | Name | Tactic | Rationale |
|--------------|------|--------|-----------|
| T1557.001 | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay | Credential Access / Collection | Core ESC8 primitive — relaying coerced NTLM auth to AD CS web enrollment. |
| T1187 | Forced Authentication | Credential Access | PetitPotam/printerbug coerce the DC to authenticate. |
| T1649 | Steal or Forge Authentication Certificates | Credential Access | The attack yields a DC machine-account certificate. |
| T1003.006 | OS Credential Dumping: DCSync | Credential Access | The recovered DC identity enables DCSync. |

## Supporting Frameworks and Standards

- **MS-EFSRPC** — protocol abused by PetitPotam for coercion.
- **MS-RPRN** — Print System Remote Protocol abused by printerbug.py.
- **MS-WCCE** — Windows Client Certificate Enrollment, the target enrollment protocol.
- **Microsoft KB5005413 / ADV210003** — mitigations for NTLM relay to AD CS (EPA, disable NTLM on enrollment).
- **D3FEND** — Certificate-based authentication hardening and network traffic analysis as countermeasures.

## Official Resources

- Impacket: https://github.com/fortra/impacket
- Certipy: https://github.com/ly4k/Certipy
- PetitPotam: https://github.com/topotam/PetitPotam
- Coercer: https://github.com/p0dalirius/Coercer
- Certified Pre-Owned: https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf
- dirkjanm "NTLM relaying to AD CS": https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/
