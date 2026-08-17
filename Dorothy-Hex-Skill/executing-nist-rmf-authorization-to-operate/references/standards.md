# NIST RMF / ATO — Standards & Reference

## Primary standard
### NIST SP 800-37 Revision 2 — Risk Management Framework for Information Systems and Organizations
- **Publisher**: NIST
- **Published**: December 2018
- **Scope**: A 7-step lifecycle for managing security and privacy risk and authorizing systems to operate.
- **URL**: https://csrc.nist.gov/pubs/sp/800/37/r2/final

## The seven RMF steps
| # | Step | Core question | Key inputs |
|---|---|---|---|
| 1 | Prepare | Are roles, strategy, and boundary set? | SP 800-39 risk strategy, common controls |
| 2 | Categorize | How bad is a loss of C/I/A? | FIPS 199, SP 800-60 |
| 3 | Select | Which controls apply? | FIPS 200, SP 800-53B baselines, SP 800-53 Rev 5 |
| 4 | Implement | How is each control built? | SSP implementation statements |
| 5 | Assess | Do the controls work? | SP 800-53A Rev 5; produces the SAR |
| 6 | Authorize | Is residual risk acceptable? | Package (SSP+SAR+POA&M); AO decision |
| 7 | Monitor | Is it still effective? | ConMon plan, scans, change management |

## Companion standards
| Document | Role |
|---|---|
| FIPS 199 | Security categorization — Low/Moderate/High per confidentiality, integrity, availability. |
| FIPS 200 | Minimum security requirements for federal information and systems. |
| NIST SP 800-60 Vol 1 & 2 | Maps information types to impact levels (input to FIPS 199). |
| NIST SP 800-53 Rev 5 | Control catalog — 20 control families. |
| NIST SP 800-53B | Control baselines (Low / Moderate / High) and the privacy baseline. |
| NIST SP 800-53A Rev 5 | Assessment procedures (examine / interview / test). |
| NIST SP 800-39 | Organization-wide risk management context (three tiers). |
| NIST SP 800-137 | Information Security Continuous Monitoring (ISCM) — the Monitor step. |
| OSCAL | Open Security Controls Assessment Language — machine-readable SSP/SAP/SAR/POA&M. |

## FIPS 199 categorization
For each information type, rate the impact of a loss of:
- **Confidentiality** — unauthorized disclosure
- **Integrity** — unauthorized modification/destruction
- **Availability** — disruption of access/use

Each at **Low / Moderate / High**. The **overall system impact level = the high-water mark** (highest single value) across all information types and all three objectives. That overall level selects the SP 800-53B baseline.

## SP 800-53 Rev 5 control families (20)
AC (Access Control), AT (Awareness & Training), AU (Audit & Accountability), CA (Assessment, Authorization & Monitoring), CM (Configuration Management), CP (Contingency Planning), IA (Identification & Authentication), IR (Incident Response), MA (Maintenance), MP (Media Protection), PE (Physical & Environmental Protection), PL (Planning), PM (Program Management), PS (Personnel Security), PT (PII Processing & Transparency), RA (Risk Assessment), SA (System & Services Acquisition), SC (System & Communications Protection), SI (System & Information Integrity), SR (Supply Chain Risk Management).

## Control allocation
- **Common (inherited)** — provided by another provider/platform; the system inherits the implementation and the evidence.
- **System-specific** — implemented and owned by this system.
- **Hybrid** — partly inherited, partly system-specific (responsibility split documented, e.g., in a FedRAMP CRM).

## Core authorization artifacts
| Artifact | Produced in step | Contents |
|---|---|---|
| SSP — System Security Plan | Select/Implement | System description, boundary, categorization, control implementation statements. |
| SAR — Security Assessment Report | Assess | Assessor findings: satisfied / other-than-satisfied, with evidence. |
| POA&M — Plan of Action & Milestones | Assess → Authorize | Open weaknesses, risk, remediation owner, milestone dates. |
| Authorization Decision Document | Authorize | ATO/cATO/DATO, term, conditions, residual-risk acceptance, AO signature. |
| ConMon Plan | Monitor | What's monitored, frequency, reporting cadence, reassessment triggers. |

## Authorization outcomes
- **ATO** — Authorization to Operate (often time-bound, e.g., up to 3 years, with ConMon).
- **cATO** — Conditional / ongoing authorization under an approved continuous model (increasingly preferred in DoD).
- **DATO** — Denial of Authorization to Operate.

## NIST CSF 2.0 alignment
| CSF 2.0 ID | Relevance |
|---|---|
| GV.OC-03 | Legal/regulatory requirements (FISMA) understood and managed. |
| GV.RM-01 | Risk-management objectives established and agreed. |
| ID.AM-08 | Systems managed across the lifecycle (authorization boundary). |
| ID.RA-05 | Risk used to inform prioritization and the authorization decision. |
| PR.IR-01 | Protective technology / controls implemented per the baseline. |
