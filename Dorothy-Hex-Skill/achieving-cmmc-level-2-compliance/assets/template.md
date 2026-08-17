# CMMC Level 2 Readiness Report — Worked Example

> Filled example for a small DIB manufacturer handling CUI on a segmented enclave.
> Replace bracketed content for your own organization.

## 1. Applicability & CUI Categories
- **Contract drivers:** Prime subcontract with DFARS **252.204-7012** and **-7021**; CUI present → **CMMC Level 2** required.
- **CUI categories (from contract + DoD CUI Registry):** Controlled Technical Information (CTI), Export Controlled (EAR).
- **Target assessment path:** Triennial **C3PAO** certification (Phase 2 applies from Nov 10, 2026).

## 2. Scope (CMMC Level 2 Scoping Guide)
| Category | Examples in this environment |
|---|---|
| CUI Assets | Engineering workstations, CUI file share, the segmented "Enclave-1" VLAN |
| Security Protection Assets | EDR console, SIEM, firewall, IdP/MFA, jump host |
| Contractor Risk Managed | General corporate laptops (policy-blocked from CUI) |
| Specialized Assets | CNC machine controllers (documented, isolated) |
| Out-of-Scope | Guest Wi-Fi, marketing SaaS |

**Boundary note:** CUI is confined to Enclave-1 behind segmentation and MFA. Deliberately minimized to shrink the assessment surface. See network diagram `CUI-boundary-v3`.

## 3. Control Status by Family (NIST SP 800-171 Rev 2)
*(summary; full per-requirement status lives in the SSP)*

| Family | Met | Partial | Not Met | N/A |
|---|---|---|---|---|
| 3.1 Access Control | 22 | 0 | 0 | 0 |
| 3.3 Audit & Accountability | 8 | 0 | 1 | 0 |
| 3.5 Identification & Auth | 10 | 1 | 0 | 0 |
| 3.8 Media Protection | 8 | 0 | 1 | 0 |
| 3.13 System & Comms Protection | 15 | 0 | 1 | 0 |
| 3.14 System & Info Integrity | 6 | 0 | 1 | 0 |
| *(others)* | all met | — | — | — |

## 4. SPRS Score
*(computed by `scripts/process.py` from the control-status JSON)*

- **Score: 97 / 110** (started at 110; deducted 13).
- **Gap to perfect:** 13 points across 4 not-met + 1 partial requirement.
- **Conditional threshold (≥ 88):** **MET** (margin 9) — eligible for Conditional status *if* the remaining items are POA&M-eligible.
- **Posted to SPRS:** score, SSP date, and assessment scope.

## 5. POA&M (eligibility-checked)
| ID | Requirement | Points | Eligibility | Remediation | Owner | Milestone (≤180d) |
|---|---|---|---|---|---|---|
| 3.3.1 | Audit log generation/coverage | 5 | **Verify** — high weight; confirm against 32 CFR 170 | Enable full audit policy + ship to SIEM | SecOps | 2026-07-30 |
| 3.13.11 | FIPS-validated cryptography | 3 | **Verify** eligibility | Replace non-validated module with FIPS 140-validated | Infra | 2026-08-15 |
| 3.5.3 | MFA (partial) | 3 | Partial-credit control | Extend MFA to remaining admin paths | IAM | 2026-07-20 |
| 3.8.9 | Backup CUI protection | 1 | Eligible | Encrypt + access-control backup store | Infra | 2026-08-31 |
| 3.14.1 | Flaw remediation | 1 | Eligible | Formalize patch SLA + tracking | IT | 2026-08-31 |

> The two 3-point and one 5-point items must clear eligibility review; the highest-weighted security requirements generally cannot remain on a POA&M. All items close within **180 days** to convert Conditional → **Final**.

## 6. Assessment Path
- **Type:** C3PAO certification assessment.
- **Target window:** Q4 2026, after POA&M closure of the high-weight items.
- **Affirmation owner:** [senior official] files the annual affirmation in SPRS.

## 7. Remediation Roadmap (sequenced by point value, then effort)
1. **3.3.1 audit logging (5 pts)** — biggest score lever and likely POA&M-ineligible → do first.
2. **3.13.11 FIPS crypto (3 pts)** and **3.5.3 MFA gap (3 pts)** — close to remove eligibility risk.
3. **3.8.9, 3.14.1 (1 pt each)** — low-effort cleanups before the C3PAO date.
4. Re-run the SPRS calculator after each closure; goal is **110** before assessment.
