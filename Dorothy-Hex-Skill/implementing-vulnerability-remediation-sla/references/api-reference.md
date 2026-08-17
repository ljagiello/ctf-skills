# API Reference: Vulnerability Remediation SLA Tracking

## Libraries Used

| Library | Purpose |
|---------|---------|
| `requests` | Fetch vulnerability data from scanner APIs |
| `json` | Parse vulnerability and asset data |
| `datetime` | Calculate SLA deadlines, time-to-remediation |
| `csv` | Export SLA compliance reports |

## Installation

```bash
pip install requests
```

## SLA Tiers

| Severity | CVSS Range | SLA Deadline | Description |
|----------|------------|-------------|-------------|
| Critical | 9.0 - 10.0 | 24 hours | Actively exploited or trivially exploitable |
| High | 7.0 - 8.9 | 72 hours | Remote code execution, privilege escalation |
| Medium | 4.0 - 6.9 | 30 days | Requires user interaction or local access |
| Low | 0.1 - 3.9 | 90 days | Informational, minimal impact |

## Core Operations

### Define SLA Configuration
```python
from datetime import datetime, timedelta

SLA_TIERS = {
    "critical": timedelta(hours=24),
    "high": timedelta(hours=72),
    "medium": timedelta(days=30),
    "low": timedelta(days=90),
}

def get_sla_deadline(severity, discovery_date):
    tier = severity.lower()
    sla_window = SLA_TIERS.get(tier, timedelta(days=90))
    return discovery_date + sla_window
```

### Calculate SLA Status for a Vulnerability
```python
def calculate_sla_status(vuln):
    discovery = datetime.fromisoformat(vuln["discovery_date"])
    deadline = get_sla_deadline(vuln["severity"], discovery)
    now = datetime.now()

    if vuln.get("remediated_date"):
        remediated = datetime.fromisoformat(vuln["remediated_date"])
        return {
            "cve": vuln["cve"],
            "status": "remediated",
            "met_sla": remediated <= deadline,
            "time_to_remediate_hours": (remediated - discovery).total_seconds() / 3600,
        }

    overdue = now > deadline
    hours_remaining = (deadline - now).total_seconds() / 3600 if not overdue else 0
    hours_overdue = (now - deadline).total_seconds() / 3600 if overdue else 0

    return {
        "cve": vuln["cve"],
        "status": "overdue" if overdue else "open",
        "severity": vuln["severity"],
        "deadline": deadline.isoformat(),
        "hours_remaining": round(hours_remaining, 1),
        "hours_overdue": round(hours_overdue, 1),
    }
```

### Fetch Vulnerabilities from Tenable
```python
import requests
import os

TENABLE_URL = "https://cloud.tenable.com"
headers = {
    "X-ApiKeys": f"accessKey={os.environ['TENABLE_ACCESS_KEY']};secretKey={os.environ['TENABLE_SECRET_KEY']}",
}

def get_open_vulnerabilities():
    resp = requests.get(
        f"{TENABLE_URL}/workbenches/vulnerabilities",
        headers=headers,
        params={"date_range": 90, "filter.0.filter": "severity", "filter.0.value": "4,3"},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json().get("vulnerabilities", [])
```

### Generate SLA Compliance Report
```python
def generate_sla_report(vulnerabilities):
    report = {
        "total": len(vulnerabilities),
        "by_status": {"open": 0, "overdue": 0, "remediated": 0},
        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "sla_compliance_rate": 0.0,
        "overdue_vulns": [],
        "mean_time_to_remediate": {},
    }

    remediated_times = {"critical": [], "high": [], "medium": [], "low": []}

    for vuln in vulnerabilities:
        status = calculate_sla_status(vuln)
        report["by_status"][status["status"]] += 1
        report["by_severity"][vuln["severity"].lower()] += 1

        if status["status"] == "overdue":
            report["overdue_vulns"].append(status)
        if status["status"] == "remediated":
            sev = vuln["severity"].lower()
            remediated_times[sev].append(status["time_to_remediate_hours"])

    total_with_deadline = report["by_status"]["remediated"] + report["by_status"]["overdue"]
    if total_with_deadline > 0:
        met_sla = sum(1 for v in vulnerabilities
                      if calculate_sla_status(v).get("met_sla", False))
        report["sla_compliance_rate"] = round(met_sla / total_with_deadline * 100, 1)

    for sev, times in remediated_times.items():
        if times:
            report["mean_time_to_remediate"][sev] = round(sum(times) / len(times), 1)

    return report
```

## Output Format

```json
{
  "report_date": "2025-01-15",
  "total": 245,
  "by_status": {"open": 180, "overdue": 23, "remediated": 42},
  "by_severity": {"critical": 5, "high": 28, "medium": 112, "low": 100},
  "sla_compliance_rate": 87.5,
  "mean_time_to_remediate": {
    "critical": 18.5,
    "high": 52.3,
    "medium": 480.0,
    "low": 1200.0
  },
  "overdue_vulns": [
    {
      "cve": "CVE-2024-21887",
      "severity": "critical",
      "hours_overdue": 48.5,
      "deadline": "2025-01-13T10:00:00"
    }
  ]
}
```
