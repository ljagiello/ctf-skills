# MITRE Engage — Standards & Framework Reference

## Primary framework
### MITRE Engage™ v1.0
- **Publisher**: The MITRE Corporation
- **Version**: 1.0, last updated 2022-02-28
- **Home**: https://engage.mitre.org
- **Live Matrix**: https://engage.mitre.org/matrix/ (authoritative source for all Goal/Approach/Activity names and IDs)
- **Starter Kit**: https://engage.mitre.org/starter-kit/ (10-Step Process, planning worksheets, whitepapers)
- **Predecessor**: MITRE Shield (Engage supersedes and restructures Shield).
- **Note**: Engage is a framework for *planning and discussing* denial, deception, and adversary engagement. It is not a tool; it provides a shared language across defenders, vendors, and decision-makers.

## Engage Matrix structure
Five columns (Goals): **Prepare · Expose · Affect · Elicit · Understand**
- **Prepare** and **Understand** are *strategic* bookends (operation inputs and outputs).
- **Expose**, **Affect**, **Elicit** are the three *Engagement* goals; together they form the default **Operate** view and are mapped to MITRE ATT&CK.

### ID prefixes (verified from engage.mitre.org)
| Component | Strategic prefix | Engagement prefix |
|---|---|---|
| Goals | SGO | EGO |
| Approaches | SAP | EAP |
| Activities | SAC | EAC |

Always resolve specific numeric IDs (e.g., the EAC for "Decoy Credentials") against the live matrix rather than from memory.

### Engagement Approaches (EAP) by Goal
- **Expose** → Collection, Detection
- **Affect** → Prevention, Direction, Disruption
- **Elicit** → Reassurance, Motivation

### Representative Engagement Activities (EAC), by name
Decoy Credentials · Decoy Content · Decoy Account · Decoy Diversity · Lures · Pocket Litter ·
Persona Creation · Artifact Diversity · Network Diversity · Application Diversity ·
Email Manipulation · Network Manipulation · Software Manipulation · Hardware Manipulation ·
Security Controls · Isolation · Attack Vector Migration · Peripheral Management · Baseline ·
Network Monitoring · System Activity Monitoring · API Monitoring · Malware Detonation ·
Burn-In · Introduced Vulnerabilities.

> The matrix maps each Activity to the ATT&CK techniques whose execution exposes an adversary weakness. Use the Navigator overlay to confirm current mappings.

## Operating principle: Affect is defender-network-only
All Affect Activities are constrained to infrastructure the defender owns and controls. Acting on adversary or third-party infrastructure is out of scope and creates legal exposure.

## Complementary frameworks

### MITRE ATT&CK
- https://attack.mitre.org — the technique catalog used to model the target adversary. Engagement Activities exist to exploit the weaknesses adversary techniques create.

### MITRE D3FEND — `Deceive` tactic
D3FEND (https://d3fend.mitre.org) provides defensive-technique naming that pairs with Engage. The `Deceive` tactic includes:
- **Decoy Environment**: Connected Honeynet, Integrated Honeynet, Standalone Honeynet
- **Decoy Object**: Decoy File, Decoy Network Resource, Decoy Persona, Decoy Public Release, Decoy Session Token, Decoy User Credential

Use D3FEND honeynet types when documenting environment isolation in the operation plan:
- **Standalone Honeynet** — fully isolated; safest; least realistic to a sophisticated adversary.
- **Connected Honeynet** — bridged to production paths to appear reachable; moderate risk.
- **Integrated Honeynet** — decoys interleaved with production assets; most realistic; highest operational risk and tightest gating required.

## NIST CSF 2.0 alignment
| CSF 2.0 ID | Relevance to adversary engagement |
|---|---|
| GV.RM-01 | Risk management objectives established — anchors the strategic Prepare goal |
| ID.RA-01 | Vulnerabilities identified — informs which weaknesses to expose |
| ID.IM-02 | Security testing / improvement — engagement operations validate detections |
| DE.CM-01 | Networks monitored to find adverse events — Expose Activities feed monitoring |
| DE.AE-02 | Potentially adverse events analyzed — triage of decoy alerts |

## Legal & ethical references
- Engagement operations interact with live adversaries; obtain written legal review before deployment.
- Preserve evidence per the organization's incident-response and forensics procedures (chain of custody).
- Coordinate with law enforcement engagement policy where applicable.
- Document rules of engagement and gating criteria before any Activity is deployed.
