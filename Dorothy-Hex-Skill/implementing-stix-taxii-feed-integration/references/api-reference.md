# API Reference: STIX/TAXII Threat Intelligence Feed Integration

## Libraries Used

| Library | Purpose |
|---------|---------|
| `taxii2-client` | TAXII 2.0/2.1 client for fetching CTI collections |
| `stix2` | Parse and create STIX 2.1 objects (indicators, malware, etc.) |
| `requests` | HTTP fallback for custom TAXII endpoints |
| `json` | Serialize and filter STIX bundles |

## Installation

```bash
pip install taxii2-client stix2 requests
```

## Authentication

### TAXII Server with HTTP Basic Auth
```python
from taxii2client.v21 import Server, Collection
import os

TAXII_URL = os.environ["TAXII_URL"]  # e.g., "https://cti-taxii.mitre.org/taxii2/"
server = Server(
    TAXII_URL,
    user=os.environ.get("TAXII_USER"),
    password=os.environ.get("TAXII_PASS"),
)
```

### TAXII Server with API Key
```python
from taxii2client.v21 import Server as Server21

server = Server21(
    url=TAXII_URL,
    headers={"Authorization": f"Bearer {os.environ['TAXII_TOKEN']}"},
)
```

## TAXII 2.1 Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /taxii2/` | Server discovery — returns API roots |
| `GET /{api-root}/` | API root information |
| `GET /{api-root}/collections/` | List available collections |
| `GET /{api-root}/collections/{id}/` | Get collection details |
| `GET /{api-root}/collections/{id}/objects/` | Get STIX objects from collection |
| `GET /{api-root}/collections/{id}/manifest/` | Object manifest (metadata only) |
| `POST /{api-root}/collections/{id}/objects/` | Add objects to a collection |
| `GET /{api-root}/status/{id}/` | Check status of a POST operation |

## Core Operations

### Discover Collections
```python
for api_root in server.api_roots:
    print(f"API Root: {api_root.title}")
    for collection in api_root.collections:
        print(f"  Collection: {collection.title} ({collection.id})")
        print(f"    Can read: {collection.can_read}, Can write: {collection.can_write}")
```

### Fetch STIX Objects from a Collection
```python
from taxii2client.v21 import Collection

collection = Collection(
    f"{TAXII_URL}collections/{collection_id}/",
    user=os.environ.get("TAXII_USER"),
    password=os.environ.get("TAXII_PASS"),
)

# Get all objects
stix_bundle = collection.get_objects()

# Filter by STIX type
indicators = collection.get_objects(type=["indicator"])

# Filter by time range
from datetime import datetime
recent = collection.get_objects(
    added_after=datetime(2025, 1, 1).strftime("%Y-%m-%dT%H:%M:%SZ")
)
```

### Parse STIX Objects
```python
import stix2

bundle = stix2.parse(stix_bundle, allow_custom=True)
for obj in bundle.objects:
    if obj.type == "indicator":
        print(f"Indicator: {obj.name}")
        print(f"  Pattern: {obj.pattern}")
        print(f"  Valid: {obj.valid_from} — {getattr(obj, 'valid_until', 'N/A')}")
    elif obj.type == "malware":
        print(f"Malware: {obj.name} — {obj.malware_types}")
    elif obj.type == "attack-pattern":
        print(f"TTP: {obj.name}")
```

### Extract IOCs from STIX Indicators
```python
import re

def extract_iocs(stix_objects):
    iocs = {"ipv4": [], "domain": [], "url": [], "sha256": [], "md5": []}
    for obj in stix_objects:
        if obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        # IPv4
        for ip in re.findall(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern):
            iocs["ipv4"].append(ip)
        # Domain
        for domain in re.findall(r"domain-name:value\s*=\s*'([^']+)'", pattern):
            iocs["domain"].append(domain)
        # SHA-256
        for sha in re.findall(r"file:hashes\.'SHA-256'\s*=\s*'([^']+)'", pattern):
            iocs["sha256"].append(sha)
    return iocs
```

### Create and Push STIX Objects
```python
indicator = stix2.Indicator(
    name="Malicious IP",
    pattern="[ipv4-addr:value = '198.51.100.42']",
    pattern_type="stix",
    valid_from=datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
    labels=["malicious-activity"],
)
bundle = stix2.Bundle(objects=[indicator])

collection.add_objects(bundle.serialize())
```

## Public TAXII Feeds

| Provider | URL | Content |
|----------|-----|---------|
| MITRE ATT&CK | `https://cti-taxii.mitre.org/taxii2/` | ATT&CK Enterprise, Mobile, ICS |
| AlienVault OTX | OTX API + STIX export | Community threat intel |
| Anomali STAXX | STAXX TAXII endpoint | Curated threat feeds |

## Output Format

```json
{
  "type": "bundle",
  "id": "bundle--a1b2c3d4",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--e5f6a7b8",
      "created": "2025-01-15T10:30:00Z",
      "name": "Malicious C2 IP",
      "pattern": "[ipv4-addr:value = '198.51.100.42']",
      "pattern_type": "stix",
      "valid_from": "2025-01-15T10:30:00Z",
      "labels": ["malicious-activity"]
    }
  ]
}
```
