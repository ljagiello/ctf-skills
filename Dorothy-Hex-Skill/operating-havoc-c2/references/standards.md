# Standards Mapping: Operating Havoc C2

## MITRE ATT&CK

| ID | Name | Rationale |
|----|------|-----------|
| T1071.001 | Application Layer Protocol: Web Protocols | The Havoc Demon's HTTP(S) listener carries C2 over web protocols to blend with legitimate traffic and evade egress filtering. |

### Related techniques exercised

| ID | Name | Rationale |
|----|------|-----------|
| T1027.007 | Obfuscated Files or Information: Dynamic API Resolution | The Demon resolves syscalls indirectly (Hell's/Halo's Gate) to bypass user-mode hooks. |
| T1620 | Reflective Code Loading | `dotnet inline-execute` and BOFs run code in-memory without touching disk. |
| T1055 | Process Injection | The Demon injects shellcode into spawned/sacrificial processes. |
| T1090.001 | Proxy: Internal Proxy | SOCKS and reverse port-forwards route operator traffic through the compromised host. |

## NIST CSF 2.0

| ID | Name | Rationale |
|----|------|-----------|
| DE.CM-01 | Networks and network services are monitored to find potentially adverse events | This skill validates that network and endpoint monitoring detect Havoc's HTTP(S) C2 and in-memory evasion techniques, the controls DE.CM-01 governs. |

## References

- Havoc Framework: https://github.com/HavocFramework/Havoc
- Havoc Documentation: https://havocframework.com/docs
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1071/001/
- NIST CSF 2.0: https://www.nist.gov/cyberframework
