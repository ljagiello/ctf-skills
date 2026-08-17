# API Reference: SOC 2 Type II Audit Preparation

## AICPA Trust Services Criteria (2017, updated 2022)

### Five Trust Services Categories

| Category | Required | Focus Area |
|----------|----------|------------|
| Security (CC1-CC9) | Mandatory | Common criteria for all SOC 2 audits |
| Availability (A1) | Optional | System uptime, DR, capacity planning |
| Processing Integrity (PI1) | Optional | Data processing accuracy and completeness |
| Confidentiality (C1) | Optional | Confidential information protection |
| Privacy (P1-P8) | Optional | Personal information lifecycle |

### Common Criteria Detail

| ID | Name | Key Controls |
|----|------|-------------|
| CC1 | Control Environment | Ethics, board oversight, org structure, competence, accountability |
| CC2 | Communication and Information | Internal/external communications, system boundaries |
| CC3 | Risk Assessment | Risk identification, fraud risk, change impact analysis |
| CC4 | Monitoring Activities | Control evaluations, deficiency identification |
| CC5 | Control Activities | Policy implementation, technology controls |
| CC6 | Logical and Physical Access | Auth, access provisioning, encryption, MFA |
| CC7 | System Operations | Monitoring, anomaly detection, incident response, vuln management |
| CC8 | Change Management | Change authorization, testing, approval, documentation |
| CC9 | Risk Mitigation | Vendor management, business continuity, disaster recovery |

## AWS Evidence Collection APIs

### IAM (CC6 - Access Controls)

```python
import boto3

iam = boto3.client("iam")

# List all users
users = iam.list_users()

# Check MFA devices per user
mfa = iam.list_mfa_devices(UserName="username")

# Get password policy
policy = iam.get_account_password_policy()

# Generate credential report
iam.generate_credential_report()
report = iam.get_credential_report()

# List access keys and their last used dates
keys = iam.list_access_keys(UserName="username")
last_used = iam.get_access_key_last_used(AccessKeyId="AKIA...")

# List attached policies
policies = iam.list_attached_user_policies(UserName="username")
```

### CloudTrail (CC7 - System Operations)

```python
ct = boto3.client("cloudtrail")

# Describe all trails
trails = ct.describe_trails()

# Get trail logging status
status = ct.get_trail_status(Name="trail-arn")

# Lookup recent events
events = ct.lookup_events(
    LookupAttributes=[
        {"AttributeKey": "EventName", "AttributeValue": "ConsoleLogin"}
    ],
    StartTime=datetime(2025, 4, 1),
    EndTime=datetime(2026, 3, 31),
)
```

### S3 (CC6 - Data Protection)

```python
s3 = boto3.client("s3")

# List all buckets
buckets = s3.list_buckets()

# Check public access block
pab = s3.get_public_access_block(Bucket="bucket-name")

# Check encryption
enc = s3.get_bucket_encryption(Bucket="bucket-name")

# Check versioning
ver = s3.get_bucket_versioning(Bucket="bucket-name")

# Check logging
log = s3.get_bucket_logging(Bucket="bucket-name")
```

### GuardDuty (CC7 - Anomaly Detection)

```python
gd = boto3.client("guardduty")

# List detectors
detectors = gd.list_detectors()

# Get findings (high severity)
findings = gd.list_findings(
    DetectorId="detector-id",
    FindingCriteria={"Criterion": {"severity": {"Gte": 7}}}
)

# Get finding details
details = gd.get_findings(
    DetectorId="detector-id",
    FindingIds=findings["FindingIds"]
)
```

## GitHub Evidence Collection APIs

### Pull Request Evidence (CC8 - Change Management)

```python
import requests

headers = {
    "Authorization": "token ghp_xxx",
    "Accept": "application/vnd.github.v3+json",
}

# List merged PRs
prs = requests.get(
    "https://api.github.com/repos/org/repo/pulls",
    params={"state": "closed", "base": "main", "per_page": 100},
    headers=headers,
)

# Get PR reviews
reviews = requests.get(
    "https://api.github.com/repos/org/repo/pulls/123/reviews",
    headers=headers,
)

# Get branch protection rules
protection = requests.get(
    "https://api.github.com/repos/org/repo/branches/main/protection",
    headers=headers,
)
```

## Okta Evidence Collection APIs (CC6 - Identity)

```python
headers = {
    "Authorization": "SSWS okta-api-token",
    "Accept": "application/json",
}

# List all users
users = requests.get("https://org.okta.com/api/v1/users", headers=headers)

# Get user MFA factors
factors = requests.get(
    "https://org.okta.com/api/v1/users/userId/factors",
    headers=headers,
)

# List authentication policies
policies = requests.get(
    "https://org.okta.com/api/v1/policies?type=ACCESS_POLICY",
    headers=headers,
)

# Get system log events
logs = requests.get(
    "https://org.okta.com/api/v1/logs",
    params={"since": "2025-04-01T00:00:00Z"},
    headers=headers,
)
```

## Compliance Automation Platforms

### Vanta API (GraphQL)

```python
headers = {"Authorization": "Bearer vanta-token"}

query = """
{
  controls {
    id
    name
    status
    lastTestedAt
    evidence { id name collectedAt }
  }
}
"""
resp = requests.post(
    "https://api.vanta.com/graphql",
    json={"query": query},
    headers=headers,
)
```

### Drata API (REST)

```python
headers = {"Authorization": "Bearer drata-token"}

# List controls
controls = requests.get("https://public-api.drata.com/controls", headers=headers)

# Get control evidence
evidence = requests.get(
    "https://public-api.drata.com/controls/{controlId}/evidence",
    headers=headers,
)

# List monitors
monitors = requests.get("https://public-api.drata.com/monitors", headers=headers)
```

## SOC 2 Type I vs Type II

| Aspect | Type I | Type II |
|--------|--------|---------|
| Scope | Point in time | Period of time (3-12 months) |
| Assessment | Controls designed properly | Controls operated effectively |
| Evidence | Current state docs | Historical evidence over period |
| Duration | 1-2 months prep | 3-12 month observation window |
| Cost | $20,000 - $50,000 | $30,000 - $100,000+ |

## Evidence Collection Frequency

| Evidence Type | Frequency | Example |
|--------------|-----------|---------|
| Automated scans | Daily/Continuous | IAM MFA status, S3 public access |
| Access reviews | Quarterly | User access certification |
| Vulnerability scans | Weekly/Monthly | Nessus, Qualys reports |
| Penetration tests | Annual | Third-party pentest report |
| Policy reviews | Annual | Security policy updates |
| Training records | Annual | Security awareness completion |
| Incident reports | Per-incident | IR documentation |
| Board minutes | Quarterly | Security committee meeting notes |

### References

- AICPA Trust Services Criteria: https://us.aicpa.org/interestareas/frc/assuranceadvisoryservices/trustservicescriteria
- SOC 2 Guide: https://soc2.fyi/
- Vanta SOC 2: https://www.vanta.com/collection/soc-2
- Drata Trust Services Criteria: https://drata.com/blog/trust-services-criteria
- Secureframe SOC 2 Checklist: https://secureframe.com/blog/soc-2-compliance-checklist
- SANS SOC 2 Trust Categories: https://www.sans.org/blog/soc-2-trust-services-categories
- Splunk SOC 2 Compliance: https://www.splunk.com/en_us/blog/learn/soc-2-compliance-checklist.html
