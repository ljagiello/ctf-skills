---
name: infrastructure
description: Network infrastructure testing - port scanning, DNS attacks, MITM, VLAN hopping, IPv6, SMB/NetBIOS, sniffing, and DoS assessment.
---

# Infrastructure

Test network infrastructure for vulnerabilities including network services, protocols, and perimeter security.

## Techniques

| Type | Key Vectors |
|------|-------------|
| **Port Scanning** | SYN scan, UDP scan, service detection, OS fingerprinting |
| **DNS** | Zone transfers, cache poisoning, subdomain takeover, DNS rebinding |
| **MITM** | ARP spoofing, DNS spoofing, SSL stripping, LLMNR/NBT-NS poisoning |
| **VLAN Hopping** | Switch spoofing, double tagging |
| **IPv6** | RA flooding, neighbor spoofing, tunneling attacks |
| **SMB/NetBIOS** | Null sessions, relay attacks, enumeration |
| **Sniffing** | Packet capture, credential harvesting, protocol analysis |
| **DoS** | Resource exhaustion, amplification, application-layer |
| **ICS/SCADA** | Modbus TCP, PLC exploitation, coil/register manipulation, session hijacking |
| **UPnP / IoT / CPE** | rootDesc/SCPD enumeration, vendor SOAP info disclosure (`GetPassword`), command injection via vendor actions, cross-action auth-key reuse |
| **Hardware / Embedded** | Logic captures (Saleae `.sal`), CAN/UART decoding, side-channel password recovery, legacy CPU errata, i386 tools via docker |

## Workflow

1. Network discovery and topology mapping
2. Port scanning and service enumeration
3. Protocol-specific vulnerability testing
4. Network attack execution (authorized scope only)
5. Evidence capture with packet captures and logs

## Reference

**Quickstart guides** (per attack type):
- `reference/port-scanning-quickstart.md` - Port scanning and service discovery
- `reference/dns-quickstart.md` - DNS attacks and enumeration
- `reference/mitm-quickstart.md` - Man-in-the-middle attacks
- `reference/vlan-hopping-quickstart.md` - VLAN hopping techniques
- `reference/ipv6-quickstart.md` - IPv6 attack vectors
- `reference/smb-netbios-quickstart.md` - SMB/NetBIOS exploitation
- `reference/sniffing-quickstart.md` - Network sniffing and capture
- `reference/dos-quickstart.md` - DoS assessment
- `reference/ics-modbus-quickstart.md` - ICS/SCADA Modbus PLC exploitation
- `reference/upnp-iot-quickstart.md` - UPnP / IoT / CPE firmware web UI enumeration and exploitation
- `reference/hardware-embedded-quickstart.md` - Logic captures, CAN/UART decoding, side-channel char-by-char recovery, legacy CPU bugs (6502), i386 tooling on ARM macOS

**Scan techniques**: `reference/syn-scan.md`, `reference/udp-scan.md`, `reference/icmp-scan.md`, `reference/os-fingerprint.md`
**Other**: `reference/firewall-detection.md`, `reference/service-enum.md`, `reference/ip-reputation.md`, `reference/overview.md`
