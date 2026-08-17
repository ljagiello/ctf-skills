# Standards Mapping — Hunting Bootkits in the EFI System Partition

## MITRE ATT&CK

| ID | Name | Rationale |
|----|------|-----------|
| T1542.003 | Pre-OS Boot: Bootkit | Adversaries install malicious boot loaders on the ESP to execute before the OS and security tooling; this skill hunts and validates those ESP boot artifacts. |

## NIST Cybersecurity Framework (CSF 2.0)

| ID | Name | Rationale |
|----|------|-----------|
| DE.CM-01 | Networks and network services are monitored to find potentially adverse events (extended here to host boot-chain integrity monitoring) | Continuous baselining and integrity monitoring of ESP boot binaries detects out-of-band bootkit persistence. |

## Supporting References

- Eclypsium — "Enhanced Threat Detection: Bootloaders, Bootkits, and Secure Boot": https://eclypsium.com/blog/threat-detection-bootloaders-bootkits-secureboot/
- Eclypsium — "Bootkitty and Linux Bootkits": https://eclypsium.com/blog/bootkitty-linux-bootkit/
- ESET — "UEFI threats moving to the ESP: Introducing ESPecter bootkit": https://www.welivesecurity.com/2021/10/05/uefi-threats-moving-esp-introducing-especter-bootkit/
- Rapid7 — "How To Hunt For UEFI Malware Using Velociraptor": https://www.rapid7.com/blog/post/2024/02/29/how-to-hunt-for-uefi-malware-using-velociraptor/
- NSA — "UEFI Secure Boot Customization" guidance
- UEFI Specification — EFI System Partition layout (`\EFI\` directory structure)
