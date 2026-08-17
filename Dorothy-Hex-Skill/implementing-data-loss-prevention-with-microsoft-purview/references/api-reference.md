# API Reference: Microsoft Purview DLP Management Agent

## Overview

Automates Microsoft Purview DLP monitoring and compliance reporting through the Microsoft Graph Security API. Retrieves DLP alerts, sensitivity label configurations, and generates policy health assessments and compliance reports. Requires Azure AD app registration with Security.Read.All and InformationProtectionPolicy.Read.All permissions.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP requests to Microsoft Graph API |

## CLI Usage

```bash
# Retrieve DLP alerts from last 7 days
python agent.py --tenant-id <tenant-id> --client-id <client-id> \
  --client-secret <secret> --action alerts --days 7

# Filter high-severity alerts
python agent.py --tenant-id <tenant-id> --client-id <client-id> \
  --client-secret <secret> --action alerts --severity high --days 30

# List sensitivity labels
python agent.py --tenant-id <tenant-id> --client-id <client-id> \
  --client-secret <secret> --action labels

# Check DLP policy health
python agent.py --tenant-id <tenant-id> --client-id <client-id> \
  --client-secret <secret> --action health --days 14

# Generate full compliance report
python agent.py --tenant-id <tenant-id> --client-id <client-id> \
  --client-secret <secret> --action report --days 30 --output-dir ./reports
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--tenant-id` | Yes | Azure AD tenant ID for the Microsoft 365 organization |
| `--client-id` | Yes | Azure AD app registration client (application) ID |
| `--client-secret` | Yes | Azure AD app registration client secret |
| `--action` | Yes | Action to perform: `alerts`, `labels`, `health`, or `report` |
| `--days` | No | Number of days to look back for alerts (default: 7) |
| `--severity` | No | Filter alerts by severity: high, medium, low, informational |
| `--output-dir` | No | Directory for output files (default: current directory) |
| `--output` | No | Specific output file path (overrides default naming) |

## Azure AD App Registration Requirements

The app registration requires the following Microsoft Graph API permissions (Application type):

| Permission | Type | Purpose |
|-----------|------|---------|
| `Security.Read.All` | Application | Read DLP alerts from security/alerts_v2 |
| `InformationProtectionPolicy.Read.All` | Application | Read sensitivity labels and DLP policies |
| `User.Read.All` | Application | Resolve user principal names in alert data |

## Key Classes

### `PurviewAuthClient`
Handles OAuth2 client credentials flow authentication with automatic token caching and renewal.

**Methods:**
- `get_token()` - Obtains or returns cached access token. Refreshes 5 minutes before expiry.
- `headers()` - Returns authorization headers dictionary for Graph API requests.

## Key Functions

### `get_dlp_alerts(auth_client, days_back, severity, top)`
Retrieves DLP alerts from Microsoft Graph Security API (`/security/alerts_v2`). Filters by service source `microsoftDataLossPrevention`, date range, and optional severity. Returns list of alert objects.

### `get_sensitivity_labels(auth_client)`
Retrieves all sensitivity labels configured in the tenant from the beta endpoint (`/security/informationProtection/sensitivityLabels`). Returns list of label objects with ID, name, protection settings, and hierarchy.

### `generate_alert_summary(alerts)`
Computes summary statistics from alert list: severity breakdown, status breakdown, top 10 triggered policies, and top 10 affected users.

### `generate_label_report(labels)`
Transforms raw label data into a sorted report with configuration details including protection status, parent relationships, and content format support.

### `check_policy_health(alerts, threshold_high, threshold_override_pct)`
Analyzes alert patterns to identify policy health issues:
- `HIGH_ALERT_VOLUME`: More than threshold high-severity alerts
- `NOISY_POLICY`: Single policy generating 100+ alerts
- `UNRESOLVED_ALERT_BACKLOG`: 50+ alerts in "new" status
- `HEALTHY`: No anomalies detected

### `export_alerts_csv(alerts, output_path)`
Exports alerts to CSV format with columns: id, title, severity, status, createdDateTime, user, description, category. Suitable for compliance reporting and spreadsheet analysis.

### `generate_compliance_report(auth_client, days_back, output_dir)`
Generates comprehensive DLP compliance report combining alert summary, policy health assessment, sensitivity label configuration, and detailed alert data. Outputs JSON report and CSV export.

## Output Files

| Action | Default Output | Format |
|--------|---------------|--------|
| `alerts` | `dlp_alerts.json` | JSON with summary and alert details |
| `labels` | `sensitivity_labels.json` | JSON array of label configurations |
| `health` | `dlp_health.json` | JSON array of health findings |
| `report` | `dlp_compliance_report.json` + `dlp_alerts_export.csv` | JSON report + CSV export |

## Health Finding Types

| Finding | Severity | Trigger |
|---------|----------|---------|
| `HIGH_ALERT_VOLUME` | WARNING | More than 10 high-severity alerts in analysis period |
| `NOISY_POLICY` | INFO | Single policy generating 100+ alerts |
| `UNRESOLVED_ALERT_BACKLOG` | WARNING | 50+ alerts in "new" status |
| `HEALTHY` | INFO | All health checks passed |
