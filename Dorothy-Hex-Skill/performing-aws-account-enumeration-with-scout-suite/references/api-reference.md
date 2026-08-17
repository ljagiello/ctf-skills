# API Reference: AWS Account Enumeration with Scout Suite

## Libraries Used

| Library | Purpose |
|---------|---------|
| `subprocess` | Execute Scout Suite CLI scans |
| `json` | Parse Scout Suite JSON report output |
| `boto3` | AWS SDK for supplementary API calls |
| `os` | Read AWS credentials from environment |

## Installation

```bash
pip install scoutsuite boto3

# Or from source
git clone https://github.com/nccgroup/ScoutSuite
cd ScoutSuite
pip install -r requirements.txt
python scout.py --help
```

## Authentication

Scout Suite uses standard AWS credential chain:

```python
import os

# Option 1: Environment variables
os.environ["AWS_ACCESS_KEY_ID"] = "AKIA..."
os.environ["AWS_SECRET_ACCESS_KEY"] = "..."
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

# Option 2: AWS CLI profile
# scout aws --profile my-profile

# Option 3: IAM Role (EC2 instance profile / ECS task role)
# Automatically detected by boto3
```

## CLI Reference

### Full AWS Account Scan
```bash
scout aws --report-dir ./scout-report
```

### Scan Specific Services
```bash
scout aws --services iam s3 ec2 rds lambda --report-dir ./scout-report
```

### Scan Specific Regions
```bash
scout aws --regions us-east-1 us-west-2 eu-west-1 --report-dir ./scout-report
```

### Use Named Profile
```bash
scout aws --profile production-readonly --report-dir ./scout-report
```

### Key CLI Flags

| Flag | Description |
|------|-------------|
| `--provider` | Cloud provider: `aws`, `azure`, `gcp` |
| `--profile` | AWS CLI named profile |
| `--regions` | Specific AWS regions to scan |
| `--services` | Specific services to audit |
| `--report-dir` | Output directory for HTML report |
| `--no-browser` | Don't open report in browser |
| `--max-workers` | Number of parallel API threads |
| `--result-format` | Output format: `json`, `csv` |
| `--exceptions` | Path to exceptions file (known acceptable findings) |
| `--ruleset` | Custom ruleset file for scoring |

## Python Integration

### Run Scout Suite and Parse Results
```python
import subprocess
import json
from pathlib import Path

def run_scout(services=None, regions=None, profile=None, report_dir="/tmp/scout"):
    cmd = ["scout", "aws", "--report-dir", report_dir, "--no-browser"]
    if services:
        cmd.extend(["--services"] + services)
    if regions:
        cmd.extend(["--regions"] + regions)
    if profile:
        cmd.extend(["--profile", profile])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    if result.returncode != 0:
        raise RuntimeError(f"Scout Suite failed: {result.stderr}")

    # Parse the JSON results
    report_path = Path(report_dir) / "scoutsuite-results" / "scoutsuite_results.json"
    if report_path.exists():
        with open(report_path) as f:
            return json.load(f)
    return None
```

### Extract High-Risk Findings
```python
def extract_findings(report, min_severity="warning"):
    severity_order = {"danger": 3, "warning": 2, "info": 1}
    min_level = severity_order.get(min_severity, 1)
    findings = []

    for service_name, service_data in report.get("services", {}).items():
        for rule_name, rule_data in service_data.get("findings", {}).items():
            level = severity_order.get(rule_data.get("level", "info"), 0)
            if level >= min_level:
                findings.append({
                    "service": service_name,
                    "rule": rule_name,
                    "severity": rule_data.get("level"),
                    "description": rule_data.get("description"),
                    "flagged_items": rule_data.get("flagged_items", 0),
                    "checked_items": rule_data.get("checked_items", 0),
                })
    return sorted(findings, key=lambda x: severity_order.get(x["severity"], 0), reverse=True)
```

## Common Findings Categories

| Service | Common Findings |
|---------|----------------|
| IAM | Root account MFA, access key rotation, overly permissive policies |
| S3 | Public buckets, missing encryption, no versioning |
| EC2 | Security groups with 0.0.0.0/0, unencrypted EBS, public IPs |
| RDS | Public access, no encryption at rest, no multi-AZ |
| Lambda | Overly permissive roles, environment variable secrets |
| CloudTrail | Logging disabled, no log file validation |
| VPC | Default VPC in use, missing flow logs |

## Output Format

```json
{
  "provider_code": "aws",
  "account_id": "123456789012",
  "last_run": {
    "time": "2025-01-15T10:30:00Z",
    "ruleset_name": "default",
    "run_parameters": {"services": ["iam", "s3", "ec2"]}
  },
  "services": {
    "iam": {
      "findings": {
        "iam-root-account-no-mfa": {
          "level": "danger",
          "description": "Root account does not have MFA enabled",
          "flagged_items": 1,
          "checked_items": 1
        }
      }
    },
    "s3": {
      "findings": {
        "s3-bucket-no-default-encryption": {
          "level": "warning",
          "description": "S3 bucket does not have default encryption",
          "flagged_items": 3,
          "checked_items": 15
        }
      }
    }
  }
}
```
