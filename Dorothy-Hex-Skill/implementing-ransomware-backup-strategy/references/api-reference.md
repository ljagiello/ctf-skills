# API Reference: Ransomware Backup Strategy Audit

## Libraries Used

| Library | Purpose |
|---------|---------|
| `boto3` | AWS SDK for S3, AWS Backup, and IAM auditing |
| `json` | Parse backup policies and compliance data |
| `subprocess` | Run local backup verification commands |
| `datetime` | Calculate backup age and RPO/RTO compliance |

## Installation

```bash
pip install boto3
```

## Authentication

```python
import boto3
import os

session = boto3.Session(
    aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
    region_name=os.environ.get("AWS_REGION", "us-east-1"),
)

s3 = session.client("s3")
backup = session.client("backup")
iam = session.client("iam")
```

## AWS S3 Backup Audit

### Check Bucket Versioning (Ransomware Recovery)
```python
def audit_s3_versioning():
    findings = []
    buckets = s3.list_buckets()["Buckets"]
    for bucket in buckets:
        name = bucket["Name"]
        versioning = s3.get_bucket_versioning(Bucket=name)
        status = versioning.get("Status", "Disabled")
        mfa_delete = versioning.get("MFADelete", "Disabled")

        if status != "Enabled":
            findings.append({
                "bucket": name,
                "issue": "Versioning not enabled",
                "severity": "high",
                "remediation": "Enable versioning for ransomware recovery",
            })
        if mfa_delete != "Enabled":
            findings.append({
                "bucket": name,
                "issue": "MFA Delete not enabled",
                "severity": "medium",
                "remediation": "Enable MFA Delete to prevent bulk deletion",
            })
    return findings
```

### Check Object Lock (Immutable Backups)
```python
def check_object_lock(bucket_name):
    try:
        config = s3.get_object_lock_configuration(Bucket=bucket_name)
        lock = config["ObjectLockConfiguration"]
        rule = lock.get("Rule", {}).get("DefaultRetention", {})
        return {
            "bucket": bucket_name,
            "object_lock_enabled": lock.get("ObjectLockEnabled") == "Enabled",
            "retention_mode": rule.get("Mode", "NONE"),
            "retention_days": rule.get("Days", 0),
        }
    except s3.exceptions.ClientError:
        return {"bucket": bucket_name, "object_lock_enabled": False}
```

### Check Cross-Region Replication
```python
def check_cross_region_replication(bucket_name):
    try:
        repl = s3.get_bucket_replication(Bucket=bucket_name)
        rules = repl["ReplicationConfiguration"]["Rules"]
        return {
            "bucket": bucket_name,
            "replication_enabled": True,
            "destinations": [
                r["Destination"]["Bucket"] for r in rules if r["Status"] == "Enabled"
            ],
        }
    except s3.exceptions.ClientError:
        return {"bucket": bucket_name, "replication_enabled": False}
```

## AWS Backup Service

### List Backup Plans
```python
def list_backup_plans():
    plans = backup.list_backup_plans()["BackupPlansList"]
    result = []
    for plan in plans:
        detail = backup.get_backup_plan(BackupPlanId=plan["BackupPlanId"])
        rules = detail["BackupPlan"]["Rules"]
        result.append({
            "name": plan["BackupPlanName"],
            "id": plan["BackupPlanId"],
            "rules": [
                {
                    "name": r["RuleName"],
                    "schedule": r.get("ScheduleExpression"),
                    "lifecycle_delete_days": r.get("Lifecycle", {}).get("DeleteAfterDays"),
                    "lifecycle_cold_days": r.get("Lifecycle", {}).get("MoveToColdStorageAfterDays"),
                    "target_vault": r["TargetBackupVaultName"],
                }
                for r in rules
            ],
        })
    return result
```

### Audit Backup Vault Access Policy
```python
def audit_vault_access(vault_name):
    try:
        policy = backup.get_backup_vault_access_policy(BackupVaultName=vault_name)
        policy_doc = json.loads(policy["Policy"])
        # Check for overly permissive policies
        findings = []
        for stmt in policy_doc.get("Statement", []):
            if stmt.get("Effect") == "Allow" and stmt.get("Principal") == "*":
                findings.append({
                    "vault": vault_name,
                    "issue": "Vault policy allows public access",
                    "severity": "critical",
                })
        return findings
    except backup.exceptions.ClientError:
        return [{"vault": vault_name, "issue": "No access policy set", "severity": "medium"}]
```

### List Recovery Points (Check Backup Freshness)
```python
from datetime import datetime, timezone

def check_backup_freshness(vault_name, max_age_hours=24):
    recovery_points = backup.list_recovery_points_by_backup_vault(
        BackupVaultName=vault_name, MaxResults=100
    )["RecoveryPoints"]

    stale = []
    for rp in recovery_points:
        age = datetime.now(timezone.utc) - rp["CreationDate"]
        if age.total_seconds() > max_age_hours * 3600:
            stale.append({
                "resource": rp["ResourceArn"],
                "last_backup": rp["CreationDate"].isoformat(),
                "age_hours": round(age.total_seconds() / 3600),
                "status": rp["Status"],
            })
    return stale
```

## 3-2-1 Backup Rule Audit

```python
def audit_321_rule(bucket_name):
    """Verify the 3-2-1 backup rule: 3 copies, 2 media types, 1 offsite."""
    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
    replication = check_cross_region_replication(bucket_name)
    object_lock = check_object_lock(bucket_name)

    score = {
        "three_copies": versioning.get("Status") == "Enabled",
        "two_media": replication["replication_enabled"],
        "one_offsite": replication["replication_enabled"],
        "immutable": object_lock["object_lock_enabled"],
    }
    score["compliant"] = all([score["three_copies"], score["two_media"], score["one_offsite"]])
    return score
```

## Output Format

```json
{
  "audit_date": "2025-01-15",
  "backup_strategy": {
    "total_buckets": 15,
    "versioning_enabled": 12,
    "object_lock_enabled": 5,
    "cross_region_replication": 8,
    "three_two_one_compliant": 4
  },
  "backup_plans": 3,
  "recovery_points_stale": 2,
  "findings": [
    {
      "resource": "critical-data-bucket",
      "issue": "No Object Lock — vulnerable to ransomware deletion",
      "severity": "high",
      "remediation": "Enable S3 Object Lock in COMPLIANCE mode"
    }
  ]
}
```
