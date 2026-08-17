# API Reference: CAPE Sandbox Automated Malware Analysis

## Libraries Used

| Library | Purpose |
|---------|---------|
| `requests` | HTTP client for CAPE REST API v2 |
| `json` | Parse analysis reports and task metadata |
| `os` | Read `CAPE_URL` and `CAPE_API_KEY` environment variables |
| `time` | Poll task status until analysis completes |

## Installation

```bash
pip install requests
```

## Authentication

```python
import requests
import os

CAPE_URL = os.environ.get("CAPE_URL", "http://cape.example.com:8000")
CAPE_KEY = os.environ.get("CAPE_API_KEY", "")
headers = {"Authorization": f"Token {CAPE_KEY}"} if CAPE_KEY else {}
```

## REST API v2 Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/apiv2/tasks/create/file/` | Submit a file for analysis |
| POST | `/apiv2/tasks/create/url/` | Submit a URL for analysis |
| GET | `/apiv2/tasks/list/` | List all analysis tasks |
| GET | `/apiv2/tasks/view/{id}/` | Get task status and metadata |
| GET | `/apiv2/tasks/report/{id}/` | Get full analysis report |
| GET | `/apiv2/tasks/report/{id}/lite/` | Get lightweight report |
| DELETE | `/apiv2/tasks/delete/{id}/` | Delete a task and its data |
| GET | `/apiv2/tasks/screenshots/{id}/` | Get analysis screenshots |
| GET | `/apiv2/tasks/procmemory/{id}/` | Get process memory dumps |
| GET | `/apiv2/files/view/sha256/{hash}/` | Look up file by SHA-256 |
| GET | `/apiv2/files/get/{sha256}/` | Download the sample binary |
| GET | `/apiv2/pcap/get/{id}/` | Download PCAP network capture |
| GET | `/apiv2/machines/list/` | List analysis VMs |
| GET | `/apiv2/cuckoo/status/` | Server status and version |

## Core Operations

### Submit a File for Analysis
```python
def submit_file(file_path, timeout_mins=5, machine=None):
    files = {"file": open(file_path, "rb")}
    data = {
        "timeout": timeout_mins * 60,
        "enforce_timeout": True,
        "options": "procmemdump=yes,import_reconstruction=yes",
    }
    if machine:
        data["machine"] = machine

    resp = requests.post(
        f"{CAPE_URL}/apiv2/tasks/create/file/",
        files=files,
        data=data,
        headers=headers,
        timeout=60,
    )
    resp.raise_for_status()
    result = resp.json()
    return result["data"]["task_ids"][0]
```

### Submit a URL for Analysis
```python
def submit_url(url, timeout_mins=3):
    resp = requests.post(
        f"{CAPE_URL}/apiv2/tasks/create/url/",
        data={
            "url": url,
            "timeout": timeout_mins * 60,
            "options": "procmemdump=yes",
        },
        headers=headers,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["data"]["task_ids"][0]
```

### Poll Task Until Complete
```python
import time

def wait_for_task(task_id, poll_interval=30, max_wait=600):
    elapsed = 0
    while elapsed < max_wait:
        resp = requests.get(
            f"{CAPE_URL}/apiv2/tasks/view/{task_id}/",
            headers=headers,
            timeout=30,
        )
        status = resp.json()["data"]["status"]
        if status == "reported":
            return True
        if status in ("failed_analysis", "failed_processing"):
            raise RuntimeError(f"Task {task_id} failed: {status}")
        time.sleep(poll_interval)
        elapsed += poll_interval
    raise TimeoutError(f"Task {task_id} did not complete within {max_wait}s")
```

### Retrieve Analysis Report
```python
def get_report(task_id, lite=False):
    endpoint = "lite" if lite else ""
    resp = requests.get(
        f"{CAPE_URL}/apiv2/tasks/report/{task_id}/{endpoint}",
        headers=headers,
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()
```

### Extract Key Findings from Report
```python
def extract_findings(report):
    info = report.get("info", {})
    findings = {
        "score": info.get("score", 0),
        "duration": info.get("duration", 0),
        "signatures": [],
        "network_iocs": {"domains": [], "ips": [], "urls": []},
        "dropped_files": [],
        "yara_matches": [],
    }

    # Behavioral signatures
    for sig in report.get("signatures", []):
        findings["signatures"].append({
            "name": sig["name"],
            "severity": sig["severity"],
            "description": sig["description"],
        })

    # Network IOCs
    network = report.get("network", {})
    findings["network_iocs"]["domains"] = [
        d["domain"] for d in network.get("domains", [])
    ]
    findings["network_iocs"]["ips"] = [
        h["ip"] for h in network.get("hosts", [])
    ]

    # YARA matches
    for target_yara in report.get("target", {}).get("file", {}).get("yara", []):
        findings["yara_matches"].append(target_yara["name"])

    return findings
```

### Download Network PCAP
```python
def download_pcap(task_id, output_path):
    resp = requests.get(
        f"{CAPE_URL}/apiv2/pcap/get/{task_id}/",
        headers=headers,
        timeout=60,
    )
    resp.raise_for_status()
    with open(output_path, "wb") as f:
        f.write(resp.content)
```

## Output Format

```json
{
  "info": {
    "id": 42,
    "score": 8.5,
    "duration": 120,
    "machine": {"name": "win10-01", "label": "win10-01"},
    "started": "2025-01-15T10:30:00",
    "ended": "2025-01-15T10:32:00"
  },
  "signatures": [
    {"name": "ransomware_bcdedit", "severity": 5, "description": "Modifies boot configuration"},
    {"name": "creates_exe", "severity": 3, "description": "Creates executable files on disk"}
  ],
  "network": {
    "hosts": [{"ip": "198.51.100.42", "country": "US"}],
    "domains": [{"domain": "c2.evil.example.com", "ip": "198.51.100.42"}]
  },
  "target": {
    "file": {
      "name": "sample.exe",
      "size": 245760,
      "sha256": "a1b2c3d4e5f6..."
    }
  }
}
```
