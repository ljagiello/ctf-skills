# Standards Mapping: Operating Sliver C2

## MITRE ATT&CK

| ID | Name | Rationale |
|----|------|-----------|
| T1071.001 | Application Layer Protocol: Web Protocols | Sliver's HTTP(S) C2 listeners tunnel implant traffic over web protocols to blend with legitimate browsing and evade egress filtering. |

### Related techniques exercised

| ID | Name | Rationale |
|----|------|-----------|
| T1572 | Protocol Tunneling | WireGuard and pivot tunnels encapsulate C2 inside other protocols. |
| T1090.001 | Proxy: Internal Proxy | TCP/named-pipe pivots and SOCKS proxies route operator traffic through compromised internal hosts. |
| T1059 | Command and Scripting Interpreter | Implant `execute`/`shell` runs commands on the target. |
| T1620 | Reflective Code Loading | `inline-execute-assembly` and BOFs load and run code in-memory without touching disk. |

## NIST CSF 2.0

| ID | Name | Rationale |
|----|------|-----------|
| DE.CM-01 | Networks and network services are monitored to find potentially adverse events | This skill validates that network monitoring detects Sliver's mTLS/HTTPS/DNS C2 channels and beaconing patterns, which is the defensive control DE.CM-01 governs. |

## References

- BishopFox Sliver: https://github.com/BishopFox/sliver
- Sliver Wiki: https://github.com/BishopFox/sliver/wiki
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1071/001/
- NIST CSF 2.0: https://www.nist.gov/cyberframework
