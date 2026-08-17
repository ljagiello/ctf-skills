# Vendor Risk Assessment — Worked Example

> Filled example for a payroll-processing vendor (regulated PII, deep integration).
> Replace bracketed content for your own vendor.

## 1. Vendor Profile
- **Vendor:** PayWorks
- **Service:** Payroll processing (SaaS)
- **Data handled:** Employee PII, bank details (regulated).
- **Access type:** System access (API + SSO into HRIS).
- **Business criticality:** High — a multi-day outage would block payroll.
- **Regulatory scope:** PII / state payroll requirements.

## 2. Inherent-Risk Tier
*(scored by `scripts/process.py`)*

| Factor | Value | Points |
|---|---|---|
| Data sensitivity | regulated | 4 |
| Access | system | 4 |
| Criticality | high | 4 |
| Integration | deep | 2 |
| Regulated scope | PII | 2 |
| Concentration | single payroll source | 1 |
| **Total** | | **17 → Tier: Critical** |

**Rationale:** regulated data + system access + high criticality place this in the top tier; assess deeply and monitor continuously.

## 3. Due Diligence Performed
- **Questionnaire:** Full SIG requested.
- **SOC 2:** Type II, **12-month** period obtained.
- **ISO 27001:** Certificate obtained — scope statement confirmed to cover the payroll service.
- **Pen-test:** Summary from 5 months ago; highs/criticals remediated.

## 4. Findings
| Finding | Severity | Note |
|---|---|---|
| SOC 2 exception: one quarter of incomplete access reviews | Moderate | Vendor provided remediation evidence; accept with monitoring |
| No customer-managed encryption keys | Low | Within risk tolerance for this data set |
| Two critical fourth parties (cloud + email) | Info | Concentration noted (see §8) |

> The SOC 2 cover page was clean — the exception was found in the body. Always read the deviations and CUECs.

## 5. Decision & Residual Risk
- **Decision:** **Approve — Conditional.**
- **Condition:** Vendor confirms completion of the access-review remediation within 60 days.
- **Residual risk:** **Moderate, accepted** by [data owner / risk owner], [date].

## 6. Contractual Requirements
- Security obligations mapped to our baseline (encryption, access control, logging).
- **Breach notification within 48 hours** of discovery.
- Data return / **certified destruction** within 30 days of termination.
- **Right to audit** or to receive a current SOC 2 annually.
- **Subprocessor flowdown** + prior notice of new subprocessors.
- Cyber-insurance minimum and liability terms.
- **DPA** executed (PII processing).

## 7. Monitoring & Reassessment Plan
- **Cadence:** Full reassessment **annually** (Critical tier).
- **Continuous signals:** security-ratings feed, breach/news monitoring, SOC 2 / ISO expiry tracking.
- **Re-tier triggers:** ownership change, new region/subprocessor, material breach, scope expansion.

## 8. Nth-Party / Concentration Notes
- **Critical fourth parties:** cloud IaaS provider and transactional email provider (from the SOC 2 subservice list).
- **Concentration risk:** our HRIS and PayWorks both ride the same cloud region — a single regional outage hits payroll and HR together. Contingency: documented manual-payroll fallback for one cycle.
