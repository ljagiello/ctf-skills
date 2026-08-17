# Standards and Framework Mapping — Building Super Timelines with Plaso

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| RS.AN-03 | Analysis is performed to establish what has taken place during an incident and the root cause of the incident | Plaso super timelines fuse all host artifacts into one chronological view, the primary method for reconstructing the sequence and root cause of an incident. |

## MITRE ATT&CK

| ID | Name | Rationale |
|----|------|-----------|
| T1070 | Indicator Removal | Unified timelines expose anti-forensic actions (log clearing, file deletion, timestomping) via contradictions between MACB times, the USN journal, and event logs. |

## Supporting References

- Plaso documentation: https://plaso.readthedocs.io/
- Plaso GitHub: https://github.com/log2timeline/plaso
- Timesketch: https://timesketch.org/
- NIST SP 800-86 Guide to Integrating Forensic Techniques into Incident Response
- NIST SP 800-61r2 Computer Security Incident Handling Guide
