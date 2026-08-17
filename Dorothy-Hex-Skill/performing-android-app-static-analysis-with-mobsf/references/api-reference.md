# API Reference: MobSF Android Static Analysis

## Libraries Used

| Library | Purpose |
|---------|---------|
| `requests` | HTTP client for MobSF REST API v1 |
| `json` | Parse scan reports and finding data |
| `os` | Read `MOBSF_URL` and `MOBSF_API_KEY` environment variables |

## Installation

```bash
pip install requests

# MobSF server (Docker)
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf
```

## Authentication

MobSF uses API key authentication. The default key is shown on the MobSF dashboard:

```python
import requests
import os

MOBSF_URL = os.environ.get("MOBSF_URL", "http://localhost:8000")
MOBSF_KEY = os.environ["MOBSF_API_KEY"]
headers = {"Authorization": MOBSF_KEY}
```

## REST API v1 Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/upload` | Upload APK, IPA, ZIP, or APPX for analysis |
| POST | `/api/v1/scan` | Trigger static analysis on uploaded file |
| GET | `/api/v1/report_json` | Get full JSON analysis report |
| POST | `/api/v1/download_pdf` | Download PDF report |
| GET | `/api/v1/scans` | List recent scans |
| POST | `/api/v1/delete_scan` | Delete a scan and its data |
| POST | `/api/v1/search` | Search scans by hash or filename |
| POST | `/api/v1/compare` | Compare two app scans |
| GET | `/api/v1/scorecard` | Get app security scorecard |
| GET | `/api/v1/scan_logs` | View live scan logs |

## Core Operations

### Upload an APK
```python
def upload_apk(file_path):
    with open(file_path, "rb") as f:
        resp = requests.post(
            f"{MOBSF_URL}/api/v1/upload",
            files={"file": (os.path.basename(file_path), f, "application/octet-stream")},
            headers=headers,
            timeout=120,
        )
    resp.raise_for_status()
    result = resp.json()
    return result["hash"], result["scan_type"], result["file_name"]
    # hash: SHA-256 of the uploaded file
    # scan_type: "apk", "ipa", "zip", "appx"
```

### Trigger Static Analysis
```python
def start_scan(file_hash, scan_type, file_name):
    resp = requests.post(
        f"{MOBSF_URL}/api/v1/scan",
        data={
            "hash": file_hash,
            "scan_type": scan_type,
            "file_name": file_name,
        },
        headers=headers,
        timeout=600,  # Scans can take several minutes
    )
    resp.raise_for_status()
    return resp.json()
```

### Retrieve JSON Report
```python
def get_report(file_hash):
    resp = requests.post(
        f"{MOBSF_URL}/api/v1/report_json",
        data={"hash": file_hash},
        headers=headers,
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()
```

### Extract Key Findings
```python
def extract_findings(report):
    findings = {
        "security_score": report.get("security_score", "N/A"),
        "app_name": report.get("app_name"),
        "package_name": report.get("package_name"),
        "target_sdk": report.get("target_sdk"),
        "min_sdk": report.get("min_sdk"),
        "permissions": {
            "dangerous": [],
            "normal": [],
        },
        "manifest_issues": [],
        "code_issues": [],
        "binary_issues": [],
    }

    # Dangerous permissions
    for perm, details in report.get("permissions", {}).items():
        status = details.get("status", "normal")
        if status == "dangerous":
            findings["permissions"]["dangerous"].append(perm)
        else:
            findings["permissions"]["normal"].append(perm)

    # Manifest analysis
    for issue in report.get("manifest_analysis", []):
        if issue.get("severity") in ("high", "warning"):
            findings["manifest_issues"].append({
                "title": issue["title"],
                "severity": issue["severity"],
                "description": issue["description"],
            })

    # Code analysis
    for issue_key, issue_data in report.get("code_analysis", {}).items():
        findings["code_issues"].append({
            "rule": issue_key,
            "severity": issue_data.get("level"),
            "description": issue_data.get("description"),
            "files": issue_data.get("path", [])[:5],
        })

    return findings
```

### Download PDF Report
```python
def download_pdf(file_hash, output_path):
    resp = requests.post(
        f"{MOBSF_URL}/api/v1/download_pdf",
        data={"hash": file_hash},
        headers=headers,
        timeout=120,
    )
    resp.raise_for_status()
    with open(output_path, "wb") as f:
        f.write(resp.content)
```

### Compare Two Applications
```python
resp = requests.post(
    f"{MOBSF_URL}/api/v1/compare",
    data={"hash1": hash_v1, "hash2": hash_v2},
    headers=headers,
    timeout=120,
)
comparison = resp.json()
# Shows permission changes, new vulnerabilities, code changes
```

## Output Format

```json
{
  "file_name": "app-debug.apk",
  "app_name": "TestApp",
  "package_name": "com.example.testapp",
  "security_score": 42,
  "target_sdk": "33",
  "min_sdk": "24",
  "permissions": {
    "android.permission.INTERNET": {"status": "normal", "description": "..."},
    "android.permission.READ_CONTACTS": {"status": "dangerous", "description": "..."}
  },
  "manifest_analysis": [
    {"title": "Application is debuggable", "severity": "high", "description": "..."}
  ],
  "code_analysis": {
    "android_insecure_random": {
      "level": "high",
      "description": "Insecure Random Number Generator",
      "path": ["com/example/CryptoUtils.java"]
    }
  },
  "binary_analysis": [
    {"title": "NX bit not set", "severity": "high"}
  ]
}
```
