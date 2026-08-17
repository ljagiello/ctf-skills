# CMMC Level 2 — Standards & Reference

## Governing rules
| Rule | Citation | Status / effective date |
|---|---|---|
| CMMC Program rule | 32 CFR Part 170 | Effective **December 16, 2024** |
| CMMC acquisition rule (DFARS) | 48 CFR; DFARS clause **252.204-7021** (and 204.7503) | Published Sept 10, 2025; effective **November 10, 2025** |
| Safeguarding CUI / incident reporting | DFARS **252.204-7012** | In effect |
| NIST 800-171 self-assessment + SPRS posting | DFARS **252.204-7019 / -7020** | In effect |

> Always confirm current status at the source — acquisition rules and phase dates have moved before. Authoritative: https://dodcio.defense.gov/CMMC/ and the eCFR for 32 CFR Part 170.

## Phased rollout (per the acquisition rule)
| Phase | Begins | What applies |
|---|---|---|
| Phase 1 | **Nov 10, 2025** | Level 1 and some Level 2 **self-assessment** required in solicitations |
| Phase 2 | **Nov 10, 2026** | Level 2 **C3PAO certification** required for applicable contracts |
| Phase 3 | **Nov 10, 2027** | Level 2 C3PAO + Level 3 **DIBCAC** assessment phased in |
| Phase 4 | **Nov 10, 2028** | Full implementation across applicable DoD contracts |

## The three CMMC levels
| Level | Protects | Requirements | Assessment |
|---|---|---|---|
| Level 1 | FCI | 15 requirements (FAR 52.204-21) | Annual self-assessment + affirmation |
| Level 2 | CUI | **110 requirements (NIST SP 800-171 Rev 2)** | Self **or** triennial C3PAO certification |
| Level 3 | CUI (high priority) | 110 + selected **SP 800-172** enhanced | DoD (DIBCAC) assessment |

Certification validity: **3 years**, with **annual affirmation** by a senior official in SPRS.

## NIST SP 800-171 Rev 2 — the 14 families (110 requirements)
| § | Family | # reqs |
|---|---|---|
| 3.1 | Access Control | 22 |
| 3.2 | Awareness and Training | 3 |
| 3.3 | Audit and Accountability | 9 |
| 3.4 | Configuration Management | 9 |
| 3.5 | Identification and Authentication | 11 |
| 3.6 | Incident Response | 3 |
| 3.7 | Maintenance | 6 |
| 3.8 | Media Protection | 9 |
| 3.9 | Personnel Security | 2 |
| 3.10 | Physical Protection | 6 |
| 3.11 | Risk Assessment | 3 |
| 3.12 | Security Assessment | 4 |
| 3.13 | System and Communications Protection | 16 |
| 3.14 | System and Information Integrity | 7 |
| | **Total** | **110** |

(Assessment objectives for each requirement are in **NIST SP 800-171A**.)

## DoD Assessment Methodology — SPRS scoring
- Start at **110**. Subtract the weighted value of each **NOT MET** requirement.
- Weights: **1, 3, or 5 points**. The most security-significant requirements are weighted 3 or 5.
- **Partial credit** applies to a small number of requirements (notably MFA at 3.5.3 and FIPS-validated cryptography at 3.13.11) where partial implementation reduces the deduction.
- Maximum score **110**; the methodology floor is **−203** (more is deducted than the 110 starting points because of the weighting).
- The complete per-requirement point assignment is published in the **DoD NIST SP 800-171 Assessment Methodology** — use that document for the authoritative weight of each control rather than estimating.

## POA&M rules under the CMMC rule (32 CFR Part 170)
- A **Conditional** Level 2 status is allowed only if the assessment score is **at least 80% (≥ 88 of 110)**.
- Only **POA&M-eligible** requirements may be deferred. The highest-weighted security requirements generally **must be fully met** and **cannot** sit on a POA&M — verify each item's eligibility against the rule.
- All POA&M items must be **closed within 180 days**; a closeout assessment then converts **Conditional → Final**.

## Scoping categories (CMMC Level 2 Scoping Guide)
| Category | Treatment |
|---|---|
| CUI Assets | Process/store/transmit CUI — assessed against applicable requirements. |
| Security Protection Assets | Provide security to the CUI environment — in scope. |
| Contractor Risk Managed Assets | Capable of handling CUI but not intended to — managed by policy/config. |
| Specialized Assets | IoT/OT, GFE, test equipment — documented, limited assessment. |
| Out-of-Scope Assets | Isolated from CUI — not assessed. |

## External Service Providers / cloud
- Cloud services that store/process/transmit CUI must be **FedRAMP Moderate authorized or meet FedRAMP Moderate equivalency**.
- Document the customer/provider responsibility split (CRM) and inherited controls in the SSP.

## NIST CSF 2.0 alignment
| CSF 2.0 ID | Relevance |
|---|---|
| GV.OC-03 | Legal/regulatory (DFARS/CMMC) requirements understood. |
| GV.SC-01 | Supply-chain risk management — flowdown to subs / ESPs. |
| ID.AM-08 | Assets managed across the lifecycle (scoping). |
| ID.RA-05 | Risk informs prioritization of unmet requirements. |
| PR.AA-01 | Identity and access (3.1 / 3.5 families). |
| PR.DS-01 | Data-at-rest protection (FIPS crypto, media protection). |
