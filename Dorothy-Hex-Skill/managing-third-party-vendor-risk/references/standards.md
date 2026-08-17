# Third-Party / Vendor Risk Management — Standards & Reference

## Primary standards & frameworks
| Source | Role |
|---|---|
| **NIST SP 800-161 Rev 1** (May 2022) | Cybersecurity Supply Chain Risk Management (C-SCRM) practices for systems and organizations. URL: https://csrc.nist.gov/pubs/sp/800/161/r1/final |
| **NIST CSF 2.0 — GV.SC** | The Cybersecurity Supply Chain Risk Management category; the governance backbone for a TPRM program. |
| **NIST SP 800-37 / 800-53 (SR family)** | Supply Chain Risk Management controls (SR-x) within the broader control catalog. |
| **ISO/IEC 27036** | Information security for supplier relationships. |
| **Shared Assessments** | SIG questionnaire + Third Party Risk Management framework. |
| **CSA CAIQ / Cloud Controls Matrix (CCM) / STAR** | Cloud-vendor self-assessment and registry. |

## NIST CSF 2.0 — GV.SC subcategories (selected)
| ID | Outcome |
|---|---|
| GV.SC-01 | A cyber supply-chain risk-management program/strategy is established and agreed. |
| GV.SC-03 | Supply-chain risk management is integrated into cybersecurity and ERM. |
| GV.SC-04 | Suppliers are known and prioritized by criticality. |
| GV.SC-05 | Requirements to address supply-chain risk are established in contracts. |
| GV.SC-06 | Due diligence is performed to reduce risk before entering relationships. |
| GV.SC-07 | Supplier risks are understood, monitored, and managed over the relationship. |
| GV.SC-08 | Suppliers are included in incident planning, response, and recovery. |
| GV.SC-10 | Supply-chain risk is managed through to relationship termination. |

## Vendor tiering — typical inherent-risk factors
- **Data sensitivity** handled (regulated PII/PHI/CHD, IP, none).
- **Access type** (network/system access, physical access, none).
- **Business criticality** (would an outage stop operations?).
- **Regulatory scope** (HIPAA, PCI, GDPR, CMMC flowdown).
- **Integration depth** (API/identity federation vs standalone).
- **Concentration / spend** (single-source, large dependency).

Tiers commonly: **Critical / High / Moderate / Low** — each mapped to an assessment depth and a reassessment cadence.

## Due-diligence instruments
| Instrument | What it is |
|---|---|
| SIG (Full / Core / Lite) | Shared Assessments standardized questionnaire; depth scales with tier. |
| CAIQ | CSA questionnaire mapped to the Cloud Controls Matrix. |
| SOC 2 Type II | AICPA attestation on control **design and operating effectiveness over a period** (Trust Services Criteria: Security required; Availability, Confidentiality, Processing Integrity, Privacy optional). |
| SOC 2 Type I | Design only, at a point in time (weaker assurance than Type II). |
| ISO/IEC 27001 certificate + SoA | Certified ISMS; check the **scope statement** covers the purchased service. |
| Penetration-test summary | Independent testing; check age, scope, and remediation of highs/criticals. |
| PCI AOC | Attestation of Compliance for card-data handlers. |

## Reading a SOC 2 critically
- Confirm the **report type** (II > I) and the **audit period** length.
- Check the **scope / system description** matches the service you buy.
- Read the **exceptions / deviations** and the auditor's opinion (unqualified vs qualified).
- Review **complementary user-entity controls (CUECs)** — what the vendor expects **you** to do.
- Note the **subservice organizations** (their critical fourth parties).

## Contractual security terms to require
- Security control obligations (map to your baseline).
- **Breach-notification timeline** (e.g., notify within X hours of discovery).
- Data handling, location, and **return/certified destruction** on exit.
- **Right to audit** or to receive current assessment evidence.
- **Subcontractor (Nth-party) flowdown** and prior-approval of new subprocessors.
- Liability, indemnity, and cyber-insurance requirements.
- Regulatory instruments: **DPA** (GDPR), **BAA** (HIPAA), CMMC flowdown.

## Continuous monitoring signals
Security-ratings feeds, breach/news monitoring, certificate/attestation expiry, new subprocessor notices, ownership/region changes, and periodic re-questionnaire on cadence by tier.

## Nth-party & concentration risk
- **Fourth-party** = your vendor's vendors; map the critical ones.
- **Concentration risk** = many vendors depending on the same upstream (e.g., one cloud region or one auth provider) — a single upstream failure can be systemic.
