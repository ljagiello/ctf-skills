# API Reference: Rapid7 InsightVM Vulnerability Scanning

## Libraries Used

| Library | Purpose |
|---------|---------|
| `requests` | HTTP client for InsightVM REST API v3 |
| `json` | Parse scan results and vulnerability data |
| `base64` | Encode Basic Auth credentials |
| `os` | Read `INSIGHTVM_URL`, `INSIGHTVM_USER`, `INSIGHTVM_PASS` |

## Installation

```bash
pip install requests
```

## Authentication

InsightVM API v3 uses HTTP Basic Authentication:

```python
import requests
import os
from requests.auth import HTTPBasicAuth

INSIGHTVM_URL = os.environ.get("INSIGHTVM_URL", "https://insightvm.example.com:3780")
auth = HTTPBasicAuth(
    os.environ["INSIGHTVM_USER"],
    os.environ["INSIGHTVM_PASS"],
)
```

## REST API v3 Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/3/sites` | List all scan sites |
| GET | `/api/3/sites/{id}` | Get site details |
| POST | `/api/3/sites` | Create a new site |
| GET | `/api/3/sites/{id}/assets` | List assets in a site |
| POST | `/api/3/sites/{id}/scans` | Launch a scan on a site |
| GET | `/api/3/scans` | List all scans |
| GET | `/api/3/scans/{id}` | Get scan status and details |
| GET | `/api/3/assets` | List all assets |
| GET | `/api/3/assets/{id}` | Get asset details |
| GET | `/api/3/assets/{id}/vulnerabilities` | Get vulnerabilities for asset |
| GET | `/api/3/vulnerabilities` | List all known vulnerabilities |
| GET | `/api/3/vulnerabilities/{id}` | Get vulnerability details |
| GET | `/api/3/vulnerability_checks` | List vulnerability checks |
| GET | `/api/3/scan_engines` | List scan engines |
| GET | `/api/3/reports` | List generated reports |
| POST | `/api/3/reports` | Create a report configuration |
| POST | `/api/3/reports/{id}/generate` | Generate a report |
| GET | `/api/3/tags` | List all tags |
| GET | `/api/3/policies` | List compliance policies |

## Core Operations

### List Sites
```python
resp = requests.get(
    f"{INSIGHTVM_URL}/api/3/sites",
    auth=auth,
    params={"page": 0, "size": 100},
    timeout=30,
    verify=True,
)
for site in resp.json().get("resources", []):
    print(f"Site: {site['name']} (ID: {site['id']}) — {site.get('description', '')}")
```

### Launch a Scan
```python
resp = requests.post(
    f"{INSIGHTVM_URL}/api/3/sites/{site_id}/scans",
    auth=auth,
    json={"engineId": engine_id},
    timeout=30,
    verify=True,
)
scan_id = resp.json()["id"]
```

### Poll Scan Status
```python
import time

while True:
    resp = requests.get(
        f"{INSIGHTVM_URL}/api/3/scans/{scan_id}",
        auth=auth,
        timeout=30,
        verify=True,
    )
    status = resp.json()["status"]
    if status in ("finished", "stopped", "error"):
        break
    time.sleep(30)
```

### Get Asset Vulnerabilities
```python
resp = requests.get(
    f"{INSIGHTVM_URL}/api/3/assets/{asset_id}/vulnerabilities",
    auth=auth,
    params={"page": 0, "size": 500},
    timeout=60,
    verify=True,
)
vulns = resp.json().get("resources", [])
for v in vulns:
    print(f"  {v['id']} — CVSS: {v.get('cvssV3Score', 'N/A')} — {v.get('status')}")
```

### Get Vulnerability Details
```python
resp = requests.get(
    f"{INSIGHTVM_URL}/api/3/vulnerabilities/{vuln_id}",
    auth=auth,
    timeout=30,
    verify=True,
)
vuln = resp.json()
# Fields: title, description, cvss, severity, publishedDate, references, exploits
```

### Generate a Report
```python
report_config = {
    "name": "Monthly Vuln Report",
    "format": "pdf",
    "scope": {"sites": [site_id]},
    "template": "audit-report",
}
resp = requests.post(
    f"{INSIGHTVM_URL}/api/3/reports",
    auth=auth,
    json=report_config,
    timeout=30,
    verify=True,
)
report_id = resp.json()["id"]

# Generate the report
requests.post(
    f"{INSIGHTVM_URL}/api/3/reports/{report_id}/generate",
    auth=auth,
    timeout=30,
    verify=True,
)
```

## Pagination

All list endpoints support cursor-based pagination:

```python
def paginate(endpoint, auth, params=None):
    params = params or {}
    params.setdefault("size", 500)
    page = 0
    while True:
        params["page"] = page
        resp = requests.get(endpoint, auth=auth, params=params, timeout=60, verify=True)
        data = resp.json()
        yield from data.get("resources", [])
        if page >= data.get("page", {}).get("totalPages", 1) - 1:
            break
        page += 1
```

## Output Format

```json
{
  "id": 12345,
  "status": "finished",
  "vulnerabilities": {
    "critical": 3,
    "severe": 12,
    "moderate": 45,
    "total": 60
  },
  "assets": 128,
  "startTime": "2025-01-15T08:00:00Z",
  "endTime": "2025-01-15T09:45:00Z",
  "engineName": "Local Scan Engine"
}
```
