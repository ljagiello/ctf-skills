# Cloud Deception Deployment Record

> Worked example. Keep this record internal and separate from any attacker-visible metadata.

**Account / project:** acme-prod (AWS 111111111111) · **Owner:** [Cloud security lead] · **Last validated:** 2026-05-20

## 1. Decoy inventory & detection wiring
| Decoy | Cloud | Type | Plausible placement | Detection: source → rule → sink → playbook | Deny-all? | Target latency |
|---|---|---|---|---|---|---|
| svc-backup-prod (key) | AWS | Canary access key | CI variables, repo `.env`, internal wiki | CloudTrail → `decoy-key-used` → `sns:soc-deception-alerts` → IR-CLOUD-07 | Yes | < 5 min |
| acme-prod-db-backups-2026 | AWS | Honey S3 bucket | Discoverable via S3 list | CloudTrail data events → `decoy-bucket-access` → SNS → IR-CLOUD-07 | n/a | < 5 min |
| prod/db/master-password | AWS | Decoy secret | Secrets Manager | CloudTrail `GetSecretValue` → `decoy-secret-read` → SNS → IR-CLOUD-07 | n/a | < 5 min |
| h* sentinel honeytoken acct | Azure | Decoy service principal | Entra app registration | Sentinel HoneyTokens watchlist → analytics rule → SOC → IR-CLOUD-07 | Yes (no roles) | < 10 min |
| svc-billing-export | GCP | Decoy service account key | Build config | Cloud Audit Logs → log-based metric → Monitoring alert → IR-CLOUD-07 | Yes (no bindings) | < 10 min |

## 2. Least-privilege proof
- AWS decoy users: explicit `Deny *` inline policy attached (`deny-all`); verified with `aws iam get-user-policy`.
- Azure decoy SP: zero role assignments; verified in Entra.
- GCP decoy SA: zero IAM policy bindings; verified with `gcloud iam service-accounts get-iam-policy`.

## 3. Validation results (red-team each decoy)
| Decoy | Tested | By | Observed latency | Pass/Fail |
|---|---|---|---|---|
| svc-backup-prod | 2026-05-20 | Red team | 90 s | PASS |
| acme-prod-db-backups-2026 | 2026-05-20 | Red team | 2 min | PASS |
| prod/db/master-password | 2026-05-20 | Red team | 75 s | PASS |
| Azure honeytoken SP | 2026-05-20 | Red team | 6 min | PASS |
| svc-billing-export | 2026-05-20 | Red team | 4 min | PASS |

## 4. Maintenance plan
- **Rotation cadence:** Refresh names/secrets/pocket-litter quarterly so decoys age with prod.
- **Review owner:** [Cloud security lead], quarterly.
- **Inventory rule:** No decoy is deleted during clean-ups/audits without confirming against this record.
