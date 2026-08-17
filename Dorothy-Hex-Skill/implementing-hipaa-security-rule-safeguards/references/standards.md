# HIPAA Security Rule — Standards & Reference

## Primary regulation
### HIPAA Security Rule — 45 CFR Part 164, Subpart C
- **Regulator**: U.S. Department of Health and Human Services, **Office for Civil Rights (OCR)**
- **Scope**: Security of **electronic** protected health information (ePHI) held or transmitted by covered entities and business associates.
- **Statutory basis**: HIPAA (1996) as amended by **HITECH** (2009).
- **eCFR**: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C

## Rule structure (key sections)
| Section | Title |
|---|---|
| §164.302 | Applicability |
| §164.304 | Definitions |
| §164.306 | Security standards: general rules (flexibility, scalability) |
| §164.308 | **Administrative safeguards** |
| §164.310 | **Physical safeguards** |
| §164.312 | **Technical safeguards** |
| §164.314 | Organizational requirements (BAAs, group health plans) |
| §164.316 | Policies, procedures, and documentation (6-year retention) |

Breach Notification Rule: **45 CFR §§164.400–414** (Subpart D).

## Administrative safeguards (§164.308) — standards
- Security Management Process — **Risk Analysis (R)**, **Risk Management (R)**, Sanction Policy (R), Information System Activity Review (R)
- Assigned Security Responsibility (named Security Official)
- Workforce Security (authorization/supervision, clearance, termination — Addressable)
- Information Access Management (isolating clearinghouse functions (R); access authorization/establishment/modification — Addressable)
- Security Awareness and Training (reminders, malware protection, log-in monitoring, password management — Addressable)
- Security Incident Procedures — Response and Reporting (R)
- Contingency Plan — **Data Backup Plan (R)**, **Disaster Recovery Plan (R)**, **Emergency Mode Operation Plan (R)**, Testing/Revision (A), Applications/Data Criticality Analysis (A)
- Evaluation (periodic)
- Business Associate Contracts (§164.308(b))

## Physical safeguards (§164.310) — standards
- Facility Access Controls (contingency operations, facility security plan, access control/validation, maintenance records — all Addressable)
- Workstation Use (R)
- Workstation Security (R)
- Device and Media Controls — **Disposal (R)**, **Media Re-use (R)**, Accountability (A), Data Backup and Storage (A)

## Technical safeguards (§164.312) — standards
- Access Control — **Unique User Identification (R)**, **Emergency Access Procedure (R)**, Automatic Logoff (A), Encryption and Decryption (A)
- Audit Controls (R)
- Integrity — Mechanism to Authenticate ePHI (A)
- Person or Entity Authentication (R)
- Transmission Security — Integrity Controls (A), Encryption (A)

> (R) = Required, (A) = Addressable, under the **current** rule.

## Required vs Addressable
- **Required**: must be implemented as specified.
- **Addressable**: assess whether the specification is reasonable and appropriate; if yes, implement; if no, **document why** and implement an **equivalent alternative measure** if reasonable. Addressable is **not** optional.

## Breach Notification (45 CFR §§164.400–414)
- Applies to breaches of **unsecured PHI**.
- **Four-factor risk assessment** to determine whether a breach occurred (nature/extent of PHI, who used/received it, whether it was actually acquired/viewed, mitigation).
- Notify **individuals without unreasonable delay and within 60 days**; notify **HHS** (annually for <500; without unreasonable delay and within 60 days for 500+); notify **media** for breaches affecting **500+** residents of a state/jurisdiction.
- **Safe harbor**: PHI encrypted to HHS/NIST-specified standards is "secured" and not subject to breach notification.

## 2025 NPRM — PROPOSED changes (NOT yet final)
- **Citation**: 90 FR 800, RIN 0945-AA22, published **January 6, 2025**; comment period closed March 7, 2025.
- **Status**: **Proposed only.** The current Security Rule remains in force until a final rule is published and becomes effective. Track at https://www.federalregister.gov.
- **Notable proposals**:
  - Remove the **required/addressable** distinction — make (nearly) all implementation specifications **required**.
  - Mandatory **multi-factor authentication**.
  - Mandatory **encryption of ePHI at rest and in transit**.
  - **Asset inventory** and **network maps**, updated regularly.
  - **Vulnerability scans at least every 6 months** and **penetration testing at least annually**.
  - **72-hour restoration** of certain systems/data after an incident.
  - **Annual** risk-analysis updates and written documentation of compliance reviews.
- **Typical effective/compliance timing if finalized**: effective ~60 days after publication; compliance ~180 days after effective (subject to the final rule).

## Supporting NIST guidance
| Document | Role |
|---|---|
| NIST SP 800-66 Rev 2 (2024) | Implementing the HIPAA Security Rule; maps safeguards to SP 800-53 controls. |
| NIST SP 800-30 Rev 1 | Risk-assessment methodology underpinning the required risk analysis. |
| HHS SRA Tool | Free guided Security Risk Assessment for smaller organizations. |

## NIST CSF 2.0 alignment
| CSF 2.0 ID | Relevance |
|---|---|
| GV.OC-03 | Legal/regulatory (HIPAA) requirements understood. |
| GV.RM-01 | Risk-management objectives established. |
| ID.RA-01 / ID.RA-05 | Vulnerabilities identified; risk informs prioritization (the risk analysis). |
| PR.DS-01 | Data-at-rest protection (encryption of ePHI). |
| PR.AA-01 | Identity/authentication (unique IDs, MFA). |
| DE.CM-01 | Monitoring (audit controls, activity review). |
