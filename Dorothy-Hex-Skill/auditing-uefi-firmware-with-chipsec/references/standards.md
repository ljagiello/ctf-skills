# Standards and References - Auditing UEFI Firmware with CHIPSEC

## MITRE ATT&CK

| Technique ID | Name | Tactic | Rationale |
|--------------|------|--------|-----------|
| T1542.001 | Pre-OS Boot: System Firmware | Persistence / Defense Evasion | CHIPSEC verifies the SPI flash and BIOS write-protection locks whose absence enables adversaries to modify system firmware for stealthy, OS-survivable persistence. |

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| ID.AM-02 | Inventories of software, services, and systems managed by the organization are maintained | Firmware version, SPI flash image, and platform-security configuration are part of the asset/software inventory that CHIPSEC enumerates and baselines. |

## Official Resources

- CHIPSEC project: https://github.com/chipsec/chipsec
- CHIPSEC documentation: https://chipsec.github.io/
- Running CHIPSEC: https://chipsec.github.io/usage/Running-Chipsec.html
- common.bios_wp module: https://chipsec.github.io/modules/
- common.secureboot.variables module docs
- UEFITool: https://github.com/LongSoft/UEFITool
- Binarly fwhunt-scan: https://github.com/binarly-io/fwhunt-scan

## Key Research

- Intel ATR: original CHIPSEC framework and BlackHat arsenal presentations
- "Exploring Your System Deeper with CHIPSEC" (CSW)
- NSA UEFI Secure Boot Customization / firmware hardening guidance
