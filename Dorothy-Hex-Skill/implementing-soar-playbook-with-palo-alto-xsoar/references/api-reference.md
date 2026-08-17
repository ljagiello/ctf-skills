# API Reference: Palo Alto Cortex XSOAR SOAR Playbook

## Libraries Used

| Library | Purpose |
|---------|---------|
| `requests` | HTTP client for XSOAR REST API |
| `json` | Parse incident and playbook payloads |
| `os` | Read `XSOAR_URL` and `XSOAR_API_KEY` environment variables |

## Installation

```bash
pip install requests
```

## Authentication

```python
import requests
import os

XSOAR_URL = os.environ["XSOAR_URL"]  # e.g., "https://xsoar.example.com"
headers = {
    "Authorization": os.environ["XSOAR_API_KEY"],
    "Content-Type": "application/json",
    "Accept": "application/json",
}
```

## REST API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/incident` | Create a new incident |
| POST | `/incident/search` | Search incidents |
| GET | `/incident/{id}` | Get incident details |
| POST | `/incident/close` | Close an incident |
| POST | `/playbook/search` | Search playbooks |
| GET | `/playbook/{id}` | Get playbook details |
| POST | `/entry/execute/{playbook}` | Run a playbook on an incident |
| POST | `/automation/search` | Search automation scripts |
| POST | `/automation/execute` | Execute an automation command |
| GET | `/settings/integration/search` | List integrations |
| POST | `/indicators/search` | Search indicators (IOCs) |
| POST | `/indicators` | Create indicators |
| GET | `/health` | System health check |
| GET | `/user` | Get current user info |

## Core Operations

### Create an Incident
```python
incident = {
    "name": "Phishing Alert - Suspicious Email",
    "type": "Phishing",
    "severity": 3,  # 0=Unknown, 1=Low, 2=Medium, 3=High, 4=Critical
    "labels": [
        {"type": "Email/from", "value": "attacker@evil.com"},
        {"type": "Email/subject", "value": "Urgent: Verify Account"},
    ],
    "customFields": {
        "sourceemail": "attacker@evil.com",
        "reportedby": "soc-analyst-1",
    },
}
resp = requests.post(
    f"{XSOAR_URL}/incident",
    headers=headers,
    json=incident,
    timeout=30,
)
incident_id = resp.json()["id"]
```

### Search Incidents
```python
search = {
    "filter": {
        "query": "type:Phishing AND severity:>=3",
        "period": {"fromValue": "7 days ago"},
    },
    "page": 0,
    "size": 50,
}
resp = requests.post(
    f"{XSOAR_URL}/incident/search",
    headers=headers,
    json=search,
    timeout=30,
)
incidents = resp.json().get("data", [])
```

### Execute a Playbook on an Incident
```python
resp = requests.post(
    f"{XSOAR_URL}/entry/execute/{playbook_name}",
    headers=headers,
    json={"investigationId": incident_id},
    timeout=30,
)
```

### Search Playbooks
```python
resp = requests.post(
    f"{XSOAR_URL}/playbook/search",
    headers=headers,
    json={
        "query": "name:*phishing*",
        "page": 0,
        "size": 20,
    },
    timeout=30,
)
playbooks = resp.json().get("playbooks", [])
for pb in playbooks:
    print(f"{pb['name']} — tasks: {len(pb.get('tasks', {}))}")
```

### Run an Automation Command
```python
resp = requests.post(
    f"{XSOAR_URL}/automation/execute",
    headers=headers,
    json={
        "script": "!ip ip=8.8.8.8",
        "investigationId": incident_id,
    },
    timeout=60,
)
```

### Search Indicators (IOCs)
```python
resp = requests.post(
    f"{XSOAR_URL}/indicators/search",
    headers=headers,
    json={
        "query": "type:IP AND verdict:malicious",
        "size": 100,
    },
    timeout=30,
)
indicators = resp.json().get("iocObjects", [])
```

### Check Integration Health
```python
resp = requests.get(
    f"{XSOAR_URL}/settings/integration/search",
    headers=headers,
    timeout=30,
)
integrations = resp.json().get("instances", [])
for inst in integrations:
    status = "healthy" if inst.get("enabled") else "disabled"
    print(f"{inst['name']} — brand: {inst['brand']} — {status}")
```

## Output Format

```json
{
  "id": "12345",
  "name": "Phishing Alert - Suspicious Email",
  "type": "Phishing",
  "severity": 3,
  "status": 1,
  "created": "2025-01-15T10:30:00Z",
  "phase": "Triage",
  "playbooks": ["Phishing Investigation - Generic v2"],
  "labels": [
    {"type": "Email/from", "value": "attacker@evil.com"}
  ]
}
```
