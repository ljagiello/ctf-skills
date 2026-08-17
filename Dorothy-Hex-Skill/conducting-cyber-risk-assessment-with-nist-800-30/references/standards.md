# NIST SP 800-30 — Standards & Reference

## Primary standard
### NIST SP 800-30 Revision 1 — Guide for Conducting Risk Assessments
- **Publisher**: NIST
- **Published**: September 2012
- **Scope**: The risk-assessment component of the broader risk-management process.
- **URL**: https://csrc.nist.gov/pubs/sp/800/30/r1/final

## Companion standards
| Document | Role |
|---|---|
| NIST SP 800-39 | Managing Information Security Risk — three-tier context (Tier 1 organization, Tier 2 mission/business process, Tier 3 information system). |
| NIST SP 800-37 Rev 2 | Risk Management Framework — risk assessment feeds the Prepare, Select, and Authorize steps. |
| NIST SP 800-53 Rev 5 | Control catalog — source of mitigating controls chosen in risk treatment. |
| FIPS 199 / FIPS 200 | Security categorization (L/M/H per C/I/A) and minimum requirements. |
| MITRE ATT&CK | Adversarial threat-event enumeration and traceability. |
| FAIR (Open Group) | Optional quantitative risk model (dollar-range loss exposure). |

## The four-step process (800-30 Rev 1)
1. **Prepare** — purpose, scope, assumptions/constraints, sources, risk model and scales.
2. **Conduct** — tasks 2a–2f below.
3. **Communicate** — risk register + briefing.
4. **Maintain** — monitoring and refresh.

### Conduct tasks and their reference appendices
| Task | Appendix | Output |
|---|---|---|
| Identify threat sources | D | Adversarial / Accidental / Structural / Environmental sources |
| Identify threat events | E | Specific events (map adversarial to ATT&CK) |
| Identify vulnerabilities & predisposing conditions | F | Weaknesses + conditions affecting impact likelihood |
| Determine likelihood | G | Likelihood of initiation/occurrence and of adverse impact |
| Determine impact | H | Magnitude of harm |
| Determine risk | I | Risk level = f(likelihood, impact) |

## Threat source types (Appendix D)
- **Adversarial** — individuals, groups, organizations, nation-states. Characterize by capability, intent, and targeting.
- **Accidental** — erroneous actions by authorized users.
- **Structural** — failures of equipment, software, or environmental controls.
- **Environmental** — natural or man-made disasters, infrastructure outages.

## Assessment scales (qualitative / semi-quantitative)
800-30 uses five-level scales. A common qualitative mapping:

| Level | Semi-quantitative (0–10) |
|---|---|
| Very Low | 0–4 |
| Low | 5–20 |
| Moderate | 21–79 |
| High | 80–95 |
| Very High | 96–100 |

### Reference 5×5 risk matrix (likelihood × impact → risk)
| Likelihood ↓ / Impact → | Very Low | Low | Moderate | High | Very High |
|---|---|---|---|---|---|
| Very High | Very Low | Low | Moderate | High | Very High |
| High | Very Low | Low | Moderate | High | Very High |
| Moderate | Very Low | Low | Moderate | Moderate | High |
| Low | Very Low | Low | Low | Low | Moderate |
| Very Low | Very Low | Very Low | Very Low | Low | Low |

> Document whichever matrix the organization adopts during Prepare; the engine in `scripts/process.py` defaults to the table above and is configurable.

## NIST CSF 2.0 alignment
| CSF 2.0 ID | Relevance |
|---|---|
| GV.RM-01 | Risk management objectives established |
| ID.RA-01 | Vulnerabilities in assets identified |
| ID.RA-03 | Internal and external threats identified |
| ID.RA-04 | Potential impacts and likelihoods identified |
| ID.RA-05 | Threats, vulnerabilities, likelihoods, and impacts used to understand inherent risk and prioritize response |

## Risk treatment options
- **Mitigate** — implement/strengthen controls (re-score residual risk).
- **Transfer** — insurance or contractual shift.
- **Avoid** — discontinue the risk-generating activity.
- **Accept** — document residual risk with an authorizing signature within risk tolerance.
