# API Reference: Patch Management Workflow Automation

## Libraries Used

| Library | Purpose |
|---------|---------|
| `requests` | HTTP client for Tenable.io, Qualys, and WSUS APIs |
| `json` | Parse scan and patch compliance data |
| `csv` | Export remediation plans to CSV |
| `subprocess` | Execute PowerShell WSUS commands |
| `os` | Read API credentials from environment |

## Installation

```bash
pip install requests
```

## Tenable.io API

### Authentication
```python
import requests
import os

TENABLE_URL = "https://cloud.tenable.com"
tenable_headers = {
    "X-ApiKeys": f"accessKey={os.environ['TENABLE_ACCESS_KEY']};secretKey={os.environ['TENABLE_SECRET_KEY']}",
    "Content-Type": "application/json",
}
```

### Key Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/scans` | List vulnerability scans |
| GET | `/scans/{id}` | Get scan results |
| POST | `/scans` | Create a new scan |
| POST | `/scans/{id}/launch` | Launch a scan |
| GET | `/workbenches/vulnerabilities` | List vulnerabilities |
| GET | `/workbenches/assets` | List assets |

### Get Scan Results with Missing Patches
```python
def get_tenable_missing_patches(scan_id):
    resp = requests.get(
        f"{TENABLE_URL}/scans/{scan_id}",
        headers=tenable_headers,
        timeout=60,
    )
    resp.raise_for_status()
    vulns = resp.json().get("vulnerabilities", [])
    patches_needed = [
        v for v in vulns
        if v.get("plugin_family") == "Windows : Microsoft Bulletins"
        or "patch" in v.get("plugin_name", "").lower()
    ]
    return sorted(patches_needed, key=lambda v: v.get("severity", 0), reverse=True)
```

## Qualys API

### Authentication
```python
QUALYS_URL = os.environ.get("QUALYS_URL", "https://qualysapi.qualys.com")
qualys_auth = (os.environ["QUALYS_USER"], os.environ["QUALYS_PASS"])
qualys_headers = {"X-Requested-With": "Python"}
```

### Key Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/2.0/fo/scan/` | List scans |
| POST | `/api/2.0/fo/scan/` | Launch a scan |
| GET | `/api/2.0/fo/asset/host/` | List host assets |
| POST | `/api/2.0/fo/knowledge_base/vuln/` | Query vulnerability KB |
| GET | `/api/2.0/fo/report/` | List reports |

### Get Missing Patches by Host
```python
def get_qualys_patches(scan_ref):
    resp = requests.get(
        f"{QUALYS_URL}/api/2.0/fo/scan/",
        params={"action": "fetch", "scan_ref": scan_ref, "output_format": "json"},
        auth=qualys_auth,
        headers=qualys_headers,
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()
```

## WSUS (Windows Server Update Services) via PowerShell

### Check Patch Compliance
```python
def check_wsus_compliance(server=None):
    cmd = ["powershell", "-Command"]
    ps_script = """
    Get-WsusUpdate -Approval Approved -Status FailedOrNeeded |
    Select-Object Title, Classification, KnowledgebaseArticles, ArrivalDate |
    ConvertTo-Json
    """
    if server:
        ps_script = f"Invoke-Command -ComputerName {server} -ScriptBlock {{{ps_script}}}"
    cmd.append(ps_script)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return json.loads(result.stdout) if result.stdout else []
```

### List Installed Updates
```python
def list_installed_patches():
    cmd = [
        "powershell", "-Command",
        "Get-HotFix | Select-Object HotFixID, Description, InstalledOn | ConvertTo-Json"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return json.loads(result.stdout) if result.stdout else []
```

## Patch Prioritization

```python
def prioritize_patches(vulnerabilities, kev_cves=None):
    """Prioritize patches using CVSS + KEV + age."""
    kev_set = set(kev_cves or [])
    for vuln in vulnerabilities:
        score = vuln.get("cvss_score", 0)
        if vuln.get("cve") in kev_set:
            score += 3  # KEV bonus
        if vuln.get("exploit_available"):
            score += 2
        vuln["priority_score"] = min(score, 10)
    return sorted(vulnerabilities, key=lambda v: v["priority_score"], reverse=True)
```

## Output Format

```json
{
  "scan_date": "2025-01-15T10:30:00Z",
  "total_hosts": 250,
  "patches_required": 145,
  "critical_patches": 12,
  "kev_matches": 5,
  "compliance_rate": 78.5,
  "remediation_plan": [
    {
      "kb": "KB5034441",
      "title": "Windows Security Update",
      "severity": "critical",
      "affected_hosts": 45,
      "cve": "CVE-2024-21345",
      "kev_listed": true
    }
  ]
}
```
