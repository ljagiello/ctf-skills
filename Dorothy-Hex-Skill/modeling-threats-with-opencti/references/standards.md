# Standards Mapping — Modeling Threats with OpenCTI

## MITRE ATT&CK

| ID | Name | Rationale |
|----|------|-----------|
| T1589 | Gather Victim Identity Information | OpenCTI consolidates reconnaissance/targeting intelligence and adversary tradecraft from many sources into a single STIX 2.1 knowledge graph for analysis and attribution. |

## NIST Cybersecurity Framework (CSF 2.0)

| ID | Name | Rationale |
|----|------|-----------|
| ID.RA-03 | Internal and external threats to the organization are identified and recorded | Modeling threat actors, intrusion sets, campaigns, and TTPs as a structured knowledge graph is precisely the identification and recording of threats this control requires. |

## Supporting References

- OpenCTI documentation: https://docs.opencti.io/latest/
- pycti Python client: https://github.com/OpenCTI-Platform/client-python
- OpenCTI connectors library: https://github.com/OpenCTI-Platform/connectors
- OpenCTI Docker deployment: https://github.com/OpenCTI-Platform/docker
- OASIS STIX 2.1 specification: https://oasis-open.github.io/cti-documentation/
- MITRE ATT&CK: https://attack.mitre.org/
