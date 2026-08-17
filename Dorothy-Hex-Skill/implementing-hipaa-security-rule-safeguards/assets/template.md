# HIPAA Security Rule Gap Assessment — Worked Example

> Filled example for a small outpatient clinic (covered entity).
> Replace bracketed content for your own organization.

## 1. Role & ePHI Scope
- **Role:** Covered Entity (outpatient provider doing electronic transactions).
- **ePHI locations:** EHR SaaS, the clinic's clearing workstation, encrypted backups, and a billing vendor (business associate).
- **ePHI data map:** Patient intake → EHR (SaaS, BAA in place) → claims to billing BA → encrypted backup. Reference diagram `ephi-flow-v2`.

## 2. Risk Analysis Summary (feeds Risk Management)
| Top risk to ePHI | Likelihood | Impact | Note |
|---|---|---|---|
| Phishing → EHR credential theft | High | High | No MFA on remote EHR access |
| Lost/stolen laptop with cached ePHI | Moderate | High | Disk encryption not enforced fleet-wide |
| Billing BA mishandles ePHI | Low | High | BAA present; vendor safeguards unverified |

> The risk analysis is **dated and documented** — this is the first artifact OCR requests.

## 3. Safeguard Status
*(scored by `scripts/process.py`; weighted readiness ≈ 62% in this example)*

| Specification | Section | Requirement | Status | Alt. documented |
|---|---|---|---|---|
| 164.308(a)(1)(ii)(A) Risk Analysis | Administrative | required | **gap** | — |
| 164.308(a)(1)(ii)(B) Risk Management | Administrative | required | partial | — |
| 164.308(a)(2) Assigned Security Responsibility | Administrative | required | implemented | — |
| 164.310(d)(2)(i) Disposal | Physical | required | implemented | — |
| 164.312(a)(1) Unique User ID | Technical | required | implemented | — |
| 164.312(a)(2)(iv) Encryption/Decryption | Technical | addressable | partial | no |
| 164.312(a)(2)(iii) Automatic Logoff | Technical | addressable | gap | **yes** (equivalent timeout via MDM documented) |

**OCR-priority flag:** Risk Analysis is a gap → remediate first.

## 4. BAA Inventory
| Business associate | Service | BAA status |
|---|---|---|
| EHR SaaS vendor | Records system | Signed, current |
| Billing vendor | Claims processing | Signed; request SOC 2 / safeguards attestation |
| Backup provider | Encrypted offsite backup | Signed, current |

## 5. Breach-Notification Readiness (§§164.400–414)
- **Detection:** EHR + endpoint alerts route to the Security Official.
- **Assessment:** Documented **four-factor** procedure to decide whether a breach of unsecured PHI occurred.
- **Notification workflow:** Individuals within 60 days; HHS (annual log for <500, prompt for 500+); media for 500+ in-jurisdiction.
- **Safe harbor:** Enforce NIST-standard encryption so lost/stolen encrypted devices are "secured" and exempt from notification.

## 6. 2025 NPRM Gap View (PROPOSED — not yet final)
| Proposed mandate | Current state | Pre-position action |
|---|---|---|
| Mandatory MFA | Not enforced | Roll out MFA on all ePHI access |
| Encryption at rest & in transit | Partial | Enforce full-disk + TLS everywhere |
| Asset inventory + network map | Informal | Formalize and keep current |
| Vuln scans every 6 mo / annual pentest | Ad hoc | Schedule recurring scans + annual test |
| 72-hour restoration | Untested | Add RTO target + restore drills |
| Annual risk-analysis update | Irregular | Calendar annual refresh |

> These are **proposals**; comply with the current rule today and treat this column as a readiness runway.

## 7. Remediation Plan (prioritized)
1. **Risk Analysis (164.308(a)(1)(ii)(A)) — required gap, OCR-priority.** Complete and date a full SRA (use HHS SRA Tool + NIST 800-30). **Owner:** Security Official. **Due:** 30 days.
2. **Risk Management (164.308(a)(1)(ii)(B)) — required, partial.** Build the remediation plan that flows from the SRA. **Due:** 45 days.
3. **Encryption (164.312(a)(2)(iv)) — addressable, partial.** Enforce full-disk + in-transit encryption (also clears NPRM + breach safe harbor). **Due:** 60 days.
4. Verify the billing BA's safeguards (request SOC 2). **Due:** 60 days.
5. Re-run the scorer after each fix; target ≥ 95% weighted readiness with zero required gaps.
