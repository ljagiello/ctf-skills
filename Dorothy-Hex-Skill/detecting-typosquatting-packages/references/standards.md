# Standards and References - Detecting Typosquatting Packages

## MITRE ATT&CK

| Technique ID | Name | Tactic | Rationale |
|--------------|------|--------|-----------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Initial Access | A typosquatted package is the malicious artifact the attacker gets installed in place of the legitimate dependency, compromising the victim's software supply chain at install time. |

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| ID.RA-09 | The authenticity and integrity of hardware and software is assessed prior to acquisition and use | Pre-installation typosquat screening is exactly the activity of assessing a package's authenticity before it enters the environment. |

## Official Resources

- typomania (Rust Foundation): https://github.com/rustfoundation/typomania
- typogard (original research tool): https://github.com/mt3443/typogard
- "Defending Against Package Typosquatting" (Taylor et al., University of Kansas)
- Microsoft OSSGadget: https://github.com/microsoft/OSSGadget
- IQTLabs pypi-scan: https://github.com/IQTLabs/pypi-scan
- ecosyste-ms typosquatting-dataset: https://github.com/ecosyste-ms/typosquatting-dataset
- OWASP CI/CD Security Top 10: https://owasp.org/www-project-top-10-ci-cd-security-risks/
- top-pypi-packages corpus: https://hugovk.github.io/top-pypi-packages/

## Key Research

- Rust Foundation: typomania powers crates.io typosquatting detection
- JFrog / Sonatype: annual reports on registry typosquatting and "slopsquatting" trends
