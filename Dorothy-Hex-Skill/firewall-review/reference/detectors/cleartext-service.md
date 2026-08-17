<!-- ../detectors/cleartext-service.md -->
---
name: cleartext-service
description: Flag allow rules permitting cleartext protocols (FTP, Telnet, HTTP, SMTP, POP3, IMAP, LDAP, SNMPv1/v2c, plain syslog, plain MSSQL, plain DNS, TFTP). One finding per rule, always High.
---

# Cleartext Service

**Reference implementation:** `fwrr.detectors.cleartext_service.CleartextService` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `cleartext-service:0.2.0`
**Default severity:** High

## What it checks
Scans `action=allow` rules for destination ports carrying unencrypted protocols: 20/21 (FTP), 23 (Telnet), 25 (SMTP), 53 (DNS plain), 69 (TFTP), 80 (HTTP), 110 (POP3), 143 (IMAP), 161 (SNMPv1/v2c), 389 (LDAP), 514 (plain syslog), 1433 (plain MSSQL). Emits one finding per rule (breaks after the first cleartext-port match). Distinct from admin-services-exposure — captures cleartext whether or not it is administrative.

## Why this matters
Cleartext protocols transmit credentials and payload in plain text. Any on-path attacker — ARP-poisoned LAN, compromised switch, open wireless, compromised ISP hop — can harvest session data passively. Data-in-transit tampering is also trivial on these flows. Most encryption-in-transit controls in modern frameworks (PCI DSS 4.2.1, HIPAA §164.312(e)(1)) explicitly require the encrypted alternative. The recommendation always names the encrypted equivalent (SSH for Telnet, HTTPS for HTTP, LDAPS for LDAP, etc.).

## Frameworks cited
- PCI DSS v4.0.1 — `4.2.1` (strong cryptography during transmission), `8.3.2` (strong cryptography for authentication factors in transit)
- HIPAA — `164.312(e)(1)` (transmission security — integrity + encryption)
- NIST CSF 2.0 — `PR.DS-02` (data in transit protection)
- ISO/IEC 27001:2022 — `A.8.24` (use of cryptography)

## v0.2 / v0.3 plans
- v0.2: infrastructure-rule sanity filter (shipped — skips loopback and state-established returns).
- v0.3: STARTTLS awareness — when a rule comment or object name references `*-starttls` or port 587/465/993/995 is already allowed to the same host pair, downgrade the cleartext SMTP/IMAP/POP3 finding to Info.
- v0.3: internal-to-internal downgrade option when a policy file marks specific segments as "trusted-transport" (VPN-overlay, IPsec tunnels).
