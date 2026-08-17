# Standards and Framework Mapping — Parsing Artifacts with Eric Zimmerman Tools

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| RS.AN-03 | Analysis is performed to establish what has taken place during an incident and the root cause of the incident | EZ Tools parse Windows artifacts (MFT, prefetch, registry, shellbags, amcache) into structured evidence that establishes attacker execution, access, and persistence during incident analysis. |

## MITRE ATT&CK

| ID | Name | Rationale |
|----|------|-----------|
| T1112 | Modify Registry | RECmd, AmcacheParser, and AppCompatCacheParser parse registry artifacts where adversary registry modifications (persistence, evasion) are recorded and recovered. |

## Supporting References

- Eric Zimmerman's Tools: https://ericzimmerman.github.io/
- Get-ZimmermanTools: https://github.com/EricZimmerman/Get-ZimmermanTools
- SANS — Running EZ Tools Natively on Linux: https://www.sans.org/blog/running-ez-tools-natively-on-linux-a-step-by-step-guide
- NIST SP 800-86 Guide to Integrating Forensic Techniques into Incident Response
- NIST SP 800-101r1 Guidelines on Mobile Device Forensics (artifact methodology reference)
