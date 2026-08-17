# Standards and Framework Mapping — Fleet Hunting with Velociraptor

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| DE.CM-01 | Networks and network services are monitored to find potentially adverse events | Velociraptor provides continuous endpoint visibility and on-demand fleet hunts that surface adverse events (anomalous execution, persistence, lateral movement) across monitored assets. |

## MITRE ATT&CK

| ID | Name | Rationale |
|----|------|-----------|
| T1059 | Command and Scripting Interpreter | VQL hunts commonly target abuse of interpreters (PowerShell, cmd, WScript) — a frequent adversary technique that Velociraptor detects fleet-wide. |

## Supporting References

- Velociraptor Documentation: https://docs.velociraptor.app/
- VQL Reference: https://docs.velociraptor.app/vql_reference/
- Velociraptor Artifact Exchange: https://docs.velociraptor.app/exchange/
- NIST SP 800-61r2 Computer Security Incident Handling Guide
- NIST SP 800-92 Guide to Computer Security Log Management
