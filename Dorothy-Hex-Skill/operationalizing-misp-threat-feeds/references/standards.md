# Standards and Framework Mapping

## MITRE ATT&CK

| ID | Name | Rationale |
|----|------|-----------|
| T1589 | Gather Victim Identity Information | Feeds catalog adversary reconnaissance/identity indicators; operationalizing them detects and contextualizes such activity. |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 domain/URL IOCs become Suricata/Sigma web detections. |
| T1071.004 | Application Layer Protocol: DNS | Malicious-domain IOCs drive DNS-based Wazuh/Suricata detection. |
| T1105 | Ingress Tool Transfer | File-hash IOCs detect known malicious payload delivery. |

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| ID.RA-02 | Cyber threat intelligence is received from information sharing forums and sources | MISP feed curation, caching, and operationalization is the direct implementation of receiving and applying shared cyber threat intelligence. |

## Supporting Standards and References

- **Traffic Light Protocol (TLP 2.0).** Governs how ingested/shared intelligence may be redistributed; enforced via MISP taxonomies.
- **STIX 2.1 / TAXII 2.1.** Interoperable representation/transport of CTI that MISP can import/export.
- **NIST SP 800-150 — Guide to Cyber Threat Information Sharing.** Frames the feed-ingestion and sharing lifecycle this skill operationalizes.
- **SigmaHQ specification.** Detection rule format generated from MISP attributes.
- MISP automation & REST return formats: https://www.circl.lu/doc/misp/automation/
- PyMISP documentation: https://pymisp.readthedocs.io/
