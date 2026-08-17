# Standards and Framework Mapping

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| DE.CM-01 | Networks and network services are monitored to find potentially adverse events | Honeytokens and canarytokens are monitored decoy assets; their interaction events are the adverse-event signal this control requires. |

## MITRE ATT&CK

| ID | Name | Rationale |
|----|------|-----------|
| T1556 | Modify Authentication Process | A triggered honey credential is high-fidelity evidence of adversary attempts to harvest, replay, or otherwise abuse authentication material; the decoy provides the detection tripwire. |

## MITRE D3FEND (defensive counter-mapping)

| ID | Name | Rationale |
|----|------|-----------|
| D3-DF | Decoy File | Canary documents (Word/PDF), fake configs, and decoy archives are decoy files placed in monitored locations. |
| D3-DUC | Decoy User Credential | Honey credentials (AWS keys, AD service accounts, kubeconfig, Slack tokens) are decoy credentials integrated with a monitored decoy asset. |
| D3-DO | Decoy Object | Umbrella technique covering honeytokens/canarytokens as monitored decoy artifacts. |

## OWASP / Industry References

- Thinkst Canarytokens — open-source canarytoken engine and hosted service (https://canarytokens.org).
- Picus Security: "Defending Against Credential Access Attacks: Harnessing MITRE D3FEND Decoy Objects."
- The Canarytokens approach aligns with the deception layer recommended in zero-trust and defense-in-depth architectures.
