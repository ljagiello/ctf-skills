# Adversary Engagement Operation Plan

> Worked example. Replace bracketed values. Do not deploy any Activity before legal sign-off and approved gating criteria.

## 1. Strategic context
- **Operation name:** Crown-Jewel Repo Watch
- **Strategic goal (Prepare):** Reduce dwell time of unauthorized access around the source-code repository and produce first-party CTI on whoever reaches it.
- **Where DD&AE fits the strategy:** Additive layer behind EDR + network segmentation; activates only if a primary control is bypassed.
- **Executive sponsor:** [CISO name]
- **Legal sign-off reference:** [Legal ticket / memo ID] — REQUIRED before deployment

## 2. Engagement Goals + Operational Objectives
| Goal (EGO) | Operational Objective (falsifiable, time-bound) |
|---|---|
| Expose | Alert the SOC within 5 minutes of any touch on a decoy repo credential or decoy commit. |
| Affect | Redirect lateral-movement attempts away from 2 unpatchable build servers for the duration of the operation. |
| Elicit | Obtain ≥10 new indicators and, if possible, one second-stage tool sample within 30 days. |

## 3. Threat model
- **Target adversary:** Suspected initial-access broker reselling dev-environment footholds.
- **Prioritized ATT&CK techniques:** T1078 (Valid Accounts), T1552 (Unsecured Credentials), T1083 (File & Directory Discovery), T1021 (Remote Services), T1046 (Network Service Discovery).

## 4. Activity selection matrix
| ATT&CK | Weakness exposed | Engage Activity (resolve EAC on live matrix) | Deployment owner | Tactical skill |
|---|---|---|---|---|
| T1078 | Must test credentials | Decoy Credentials, Lures | [Detection eng.] | deploying-active-directory-honeytokens |
| T1552 | Harvests secrets | Decoy Credentials, Artifact Diversity | [Detection eng.] | implementing-honeytokens-for-breach-detection |
| T1083 | Enumerates files | Decoy Content, Pocket Litter | [Blue team] | deploying-decoy-files-for-ransomware-detection |
| T1021 | Moves laterally | Network Manipulation, Decoy Systems | [Network eng.] | implementing-network-deception-with-honeypots |
| T1046 | Scans the network | Network Diversity | [Network eng.] | implementing-network-deception-with-honeypots |

## 5. Engagement environment design
- **Honeynet type:** Connected honeynet (reachable from the dev VLAN, isolated from prod data).
- **Realism / artifact plan:** Decoy repo with believable Pocket Litter (fake CI tokens, stale branches), Persona Creation for a fake "build-bot" account, Application Diversity to mimic the real toolchain.

## 6. Gating criteria & rules of engagement
- **Max blast radius:** Decoy VLAN only; no route to production data stores.
- **Tear-down / IR hand-off trigger:** Any attempt to pivot toward a real prod subnet, OR collection of the second-stage sample, whichever first.
- **Evidence handling:** Full pcap + host telemetry preserved to WORM storage; chain-of-custody log maintained.
- **Escalation authority:** [IR lead] may halt the operation at any time.
- **Affect Activities restricted to defender-owned network.** (Hard constraint — never act on infrastructure you do not own.)

## 7. Measurement plan
| Objective | Metric | Baseline | Result |
|---|---|---|---|
| Expose latency | Minutes from decoy touch to SOC alert | n/a (new) | [fill post-op] |
| Affect redirect | Lateral attempts steered from build servers | 0 | [fill post-op] |
| Elicit intel | New indicators / samples obtained | 0 | [fill post-op] |

## 8. After-action report (complete post-operation)
- **Objectives met/missed:** [ ]
- **Intel produced (indicators, samples, TTPs):** [ ]
- **Detections promoted to production:** [ ]
- **Threat-model updates for next cycle:** [ ]
