# Cloud Deception — Standards & Reference

## Detection foundations (audit logging is mandatory)
Cloud deception only works if a decoy touch is logged. Confirm these before deploying.

### AWS
- **CloudTrail** — management events plus **data events** (S3 object-level, Lambda invoke, etc.) for any storage/secret decoys. Multi-region trail recommended.
- **EventBridge** — pattern-match CloudTrail events on `userIdentity.userName`, `eventSource`, or `requestParameters.bucketName` and target SNS/Lambda.
- **GuardDuty** — correlates anomalous credential/API behavior; useful to enrich a decoy hit.
- Note: even *denied* API calls by a deny-all decoy principal are recorded in CloudTrail as `AccessDenied`, so the alert fires regardless of granted permission.

### Azure / Microsoft
- **Azure Activity log** + **Microsoft Entra ID audit and sign-in logs** streamed to a Log Analytics / Microsoft Sentinel workspace.
- **Microsoft Sentinel HoneyTokens** — built-in watchlist template; decoy identifiers added to the watchlist drive analytics rules that alert on use.
- **Microsoft Defender for Cloud** and **Entra ID Protection** — surface anomalous access to decoy identities.
- Enable diagnostic settings on decoy Storage accounts and Key Vaults to capture data-plane reads.

### GCP
- **Cloud Audit Logs** — Admin Activity logs are always on; enable **Data Access** logs for the services hosting decoys (Cloud Storage, Secret Manager, IAM).
- **Log-based metrics + Cloud Monitoring alerting policies** — trigger on audit entries where `protoPayload.authenticationInfo.principalEmail` is the decoy service account or the resource is the honey bucket.
- **Pub/Sub** sink to forward to a SIEM.

## MITRE D3FEND — Deceive tactic mappings
| D3FEND technique | Cloud decoy realization |
|---|---|
| Decoy User Credential | Canary IAM access key / decoy app secret / decoy SA key |
| Decoy Network Resource | Honey S3 / GCS / Azure Storage bucket |
| Decoy Object | Decoy secret in Secrets Manager / Key Vault / Secret Manager |
| Decoy Persona | Permission-less decoy IAM user / service principal / service account |
| Decoy Session Token | Planted temporary credential / SAS token |

## MITRE ATT&CK techniques detected
| Technique | Detected by decoy |
|---|---|
| T1078 / T1078.004 Valid Accounts (Cloud) | Canary key / decoy principal use |
| T1552 / T1552.001 Unsecured Credentials | Decoy secret read; planted credential use |
| T1580 Cloud Infrastructure Discovery | Enumeration touching decoy principals/resources |
| T1619 Cloud Storage Object Discovery | List on honey bucket |
| T1530 Data from Cloud Storage Object | GetObject on honey bucket |

## NIST CSF 2.0 alignment
| CSF 2.0 ID | Relevance |
|---|---|
| DE.CM-01 | Networks/environments monitored to find adverse events |
| DE.CM-06 | External service provider (cloud) activity monitored |
| DE.AE-02 | Potentially adverse events analyzed — decoy alert triage |
| ID.RA-01 | Vulnerabilities/exposures identified — informs decoy placement |
| RS.MA-01 | Incident management — decoy hit invokes the IR playbook |

## Tooling references
- Canarytokens (AWS API key token): https://canarytokens.org
- Thinkst Canary: https://canary.tools
- SpaceSiren (self-hosted AWS honey tokens, serverless): open-source
- Microsoft Sentinel HoneyTokens watchlist: Microsoft Learn — "Deploy decoys/honeytokens with Sentinel"
- AWS CloudTrail data events: AWS docs — "Logging data events"
- GCP Cloud Audit Logs: Google Cloud docs — "Cloud Audit Logs overview"

## Operating principles
- **Deny-all decoys only.** Decoy principals must carry an explicit deny-all policy (AWS) or no role bindings (GCP) / no privileged roles (Azure). The control's value is the alert, never access.
- **Keep an internal decoy inventory** separate from attacker-visible metadata so audits and clean-ups never delete a tripwire by accident, and real assets are never mistaken for decoys.
- **Validate end-to-end** (red-team each decoy) and record observed alert latency. Untested decoys are assumed non-functional.
- **Mark deception alerts high-fidelity** so they bypass routine noise filtering and go straight to an IR playbook.
