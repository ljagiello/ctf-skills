# API Reference: Proofpoint Email Security Gateway

## Libraries Used

| Library | Purpose |
|---------|---------|
| `requests` | HTTP client for Proofpoint TAP API v2 |
| `json` | Parse threat and message event data |
| `os` | Read `PROOFPOINT_SP` and `PROOFPOINT_SECRET` credentials |
| `datetime` | Build ISO-8601 time range queries |

## Installation

```bash
pip install requests
```

## Authentication

Proofpoint TAP API uses HTTP Basic Auth with service principal and secret:

```python
import requests
import os
from requests.auth import HTTPBasicAuth

PROOFPOINT_URL = "https://tap-api-v2.proofpoint.com"
auth = HTTPBasicAuth(
    os.environ["PROOFPOINT_SP"],       # Service Principal
    os.environ["PROOFPOINT_SECRET"],   # Secret
)
```

## TAP API v2 Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v2/siem/messages/blocked` | Messages blocked by Proofpoint |
| GET | `/v2/siem/messages/delivered` | Messages delivered (with threats) |
| GET | `/v2/siem/clicks/blocked` | Blocked URL clicks |
| GET | `/v2/siem/clicks/permitted` | Permitted URL clicks (with threats) |
| GET | `/v2/siem/all` | All events (messages + clicks) |
| GET | `/v2/siem/issues` | Campaign and threat issues |
| GET | `/v2/people/vap` | Very Attacked People report |
| GET | `/v2/forensics` | Threat forensics detail |
| POST | `/v2/quarantine/release` | Release message from quarantine |
| POST | `/v2/quarantine/delete` | Delete message from quarantine |

## Core Operations

### Fetch Blocked Messages
```python
from datetime import datetime, timedelta

def get_blocked_messages(hours_back=1):
    since = (datetime.utcnow() - timedelta(hours=hours_back)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    resp = requests.get(
        f"{PROOFPOINT_URL}/v2/siem/messages/blocked",
        auth=auth,
        params={
            "sinceTime": since,
            "format": "json",
        },
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json().get("messagesBlocked", [])
```

### Fetch Permitted Clicks with Threats
```python
def get_permitted_clicks(hours_back=24):
    since = (datetime.utcnow() - timedelta(hours=hours_back)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    resp = requests.get(
        f"{PROOFPOINT_URL}/v2/siem/clicks/permitted",
        auth=auth,
        params={"sinceTime": since, "format": "json"},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json().get("clicksPermitted", [])
```

### Get All SIEM Events
```python
def get_all_events(hours_back=1):
    since = (datetime.utcnow() - timedelta(hours=hours_back)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    resp = requests.get(
        f"{PROOFPOINT_URL}/v2/siem/all",
        auth=auth,
        params={"sinceTime": since, "format": "json"},
        timeout=120,
    )
    resp.raise_for_status()
    data = resp.json()
    return {
        "messages_blocked": data.get("messagesBlocked", []),
        "messages_delivered": data.get("messagesDelivered", []),
        "clicks_blocked": data.get("clicksBlocked", []),
        "clicks_permitted": data.get("clicksPermitted", []),
    }
```

### Get Very Attacked People (VAP)
```python
def get_vap_report(days=30):
    resp = requests.get(
        f"{PROOFPOINT_URL}/v2/people/vap",
        auth=auth,
        params={"window": days, "size": 100},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json().get("users", [])
```

### Extract Threat IOCs
```python
def extract_iocs(events):
    iocs = {"urls": set(), "senders": set(), "subjects": set(), "sha256": set()}
    for msg in events.get("messages_blocked", []) + events.get("messages_delivered", []):
        iocs["senders"].add(msg.get("sender", ""))
        iocs["subjects"].add(msg.get("subject", ""))
        for threat in msg.get("threatsInfoMap", []):
            if threat.get("threatUrl"):
                iocs["urls"].add(threat["threatUrl"])
            if threat.get("sha256"):
                iocs["sha256"].add(threat["sha256"])
    return {k: list(v) for k, v in iocs.items()}
```

## Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `sinceTime` | ISO-8601 | Start time (required, max 1 hour back for `/all`) |
| `sinceSeconds` | int | Seconds before now (alternative to sinceTime) |
| `format` | string | Response format: `json` (default) or `syslog` |
| `threatType` | string | Filter: `url`, `attachment`, `messageText` |
| `threatStatus` | string | Filter: `active`, `cleared`, `falsePositive` |

## Output Format

```json
{
  "messagesBlocked": [
    {
      "GUID": "abc123-def456",
      "QID": "r1234567",
      "sender": "attacker@malicious.example.com",
      "recipient": ["user@company.com"],
      "subject": "Invoice #12345 Attached",
      "messageTime": "2025-01-15T10:30:00Z",
      "threatsInfoMap": [
        {
          "threat": "https://evil.example.com/payload",
          "threatType": "url",
          "threatStatus": "active",
          "classification": "phish",
          "sha256": "a1b2c3d4e5f6..."
        }
      ],
      "malwareScore": 100,
      "phishScore": 95,
      "spamScore": 0
    }
  ]
}
```
