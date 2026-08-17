# API Reference: CISA Ransomware Playbook Framework

## CISA StopRansomware Guide

### Primary Resource
```
URL: https://www.cisa.gov/stopransomware/ransomware-guide
PDF: https://www.cisa.gov/sites/default/files/2025-03/StopRansomware-Guide%20508.pdf
```

### Guide Structure
| Part | Content | Focus |
|------|---------|-------|
| Part 1 | Ransomware and Data Extortion Prevention Best Practices | Preparation |
| Part 2 | Ransomware and Data Extortion Response Checklist | Response |

## CISA Reporting

### Report an Incident
```
URL: https://report.cisa.gov
```

### FBI Internet Crime Complaint Center
```
URL: https://www.ic3.gov
```

## NIST Cybersecurity Framework Mapping

| NIST Function | Ransomware Application |
|---------------|----------------------|
| **Identify** | Asset inventory, risk assessment, data classification |
| **Protect** | Backups, MFA, patching, email filtering, AppLocker |
| **Detect** | EDR alerts, SIEM monitoring, anomaly detection |
| **Respond** | Containment, forensics, notification, communication |
| **Recover** | Backup restoration, system rebuild, validation |

## ID Ransomware Service

### Identify Ransomware Family
```
URL: https://id-ransomware.malwarehunterteam.com/
Upload: Encrypted file sample + ransom note
```

### Response
Returns ransomware family name, available decryptors, and known TTPs.

## CISA Preparation Checklist Controls

| Control ID | Control | Priority |
|-----------|---------|----------|
| PREP-01 | Offline encrypted backups | Critical |
| PREP-02 | Incident response plan | Critical |
| PREP-03 | Network segmentation | High |
| PREP-04 | Multi-factor authentication | Critical |
| PREP-05 | Endpoint detection and response | High |
| PREP-06 | RDP restrictions | Critical |
| PREP-07 | Patch management | High |
| PREP-08 | Email security (DMARC/DKIM/SPF) | High |
| PREP-09 | Application allowlisting | Medium |
| PREP-10 | Security awareness training | Medium |

## Response Phase Timelines (CISA Recommended)

| Phase | Target Timeline | Key Actions |
|-------|----------------|-------------|
| Detection | 0-2 hours | Identify scope, capture evidence |
| Containment | 1-4 hours | Isolate systems, block IOCs |
| Eradication | 1-7 days | Rebuild, restore, reset credentials |
| Recovery | 1-4 weeks | Monitor, validate, document |
| Post-Incident | 30-90 days | Lessons learned, playbook updates |

## Regulatory Notification Timelines

| Regulation | Timeline | Authority |
|-----------|----------|-----------|
| GDPR | 72 hours | Data Protection Authority |
| HIPAA | 60 days | HHS Office for Civil Rights |
| SEC | 4 business days | Securities and Exchange Commission |
| PCI DSS | Immediately | Card brands / acquiring bank |
| State breach laws | Varies (30-90 days) | State Attorney General |

## MITRE ATT&CK Ransomware Techniques

| Technique ID | Name | Phase |
|-------------|------|-------|
| T1486 | Data Encrypted for Impact | Impact |
| T1490 | Inhibit System Recovery | Impact |
| T1489 | Service Stop | Impact |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| T1059.001 | PowerShell | Execution |
| T1566.001 | Spearphishing Attachment | Initial Access |
