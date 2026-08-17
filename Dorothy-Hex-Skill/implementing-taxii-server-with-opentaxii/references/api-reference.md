# API Reference: OpenTAXII Server

## Libraries Used

| Library | Purpose |
|---------|---------|
| `opentaxii` | TAXII 1.x and 2.x server implementation |
| `taxii2-client` | TAXII 2.1 client for testing and integration |
| `stix2` | Create and parse STIX 2.1 objects |
| `requests` | HTTP client for direct API testing |

## Installation

```bash
# Server
pip install opentaxii

# Client and testing
pip install taxii2-client stix2 requests
```

## Server Configuration

### opentaxii.yml
```yaml
---
persistence_api:
  class: opentaxii.persistence.sqldb.SQLDatabaseAPI
  parameters:
    db_connection: sqlite:////tmp/opentaxii.db
    create_tables: true

auth_api:
  class: opentaxii.auth.sqldb.SQLDatabaseAuth
  parameters:
    db_connection: sqlite:////tmp/opentaxii.db
    create_tables: true
    secret: "change-this-secret-in-production"

taxii1:
  save_raw_inbox_messages: false

logging:
  opentaxii: info
  root: info
```

### Start the Server
```bash
# Set config path
export OPENTAXII_CONFIG=/path/to/opentaxii.yml

# Run the server
opentaxii-run-dev --host 0.0.0.0 --port 9000

# Production (with gunicorn)
gunicorn opentaxii.http:app --bind 0.0.0.0:9000
```

## TAXII 2.1 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/taxii2/` | Server discovery |
| GET | `/{api-root}/` | API root information |
| GET | `/{api-root}/collections/` | List collections |
| GET | `/{api-root}/collections/{id}/` | Get collection details |
| GET | `/{api-root}/collections/{id}/objects/` | Get STIX objects |
| POST | `/{api-root}/collections/{id}/objects/` | Add STIX objects |
| GET | `/{api-root}/collections/{id}/manifest/` | Object manifest |
| GET | `/{api-root}/status/{id}/` | Async operation status |

## Server Administration

### Create Collections via CLI
```bash
opentaxii-create-services -c services.yml
opentaxii-create-collections -c collections.yml
opentaxii-create-account --username admin --password admin123
```

### collections.yml
```yaml
---
- name: "threat-indicators"
  id: "collection-001"
  description: "Threat intelligence indicators"
  type: "DATA_FEED"
  accept_all_content: true
  can_read: true
  can_write: true

- name: "malware-samples"
  id: "collection-002"
  description: "Malware sample hashes and metadata"
  type: "DATA_SET"
  can_read: true
  can_write: false
```

## Client Operations

### Discover Server and Collections
```python
from taxii2client.v21 import Server
import os

server = Server(
    os.environ.get("OPENTAXII_URL", "http://localhost:9000/taxii2/"),
    user=os.environ.get("TAXII_USER", "admin"),
    password=os.environ.get("TAXII_PASS", "admin123"),
)

for api_root in server.api_roots:
    print(f"API Root: {api_root.title}")
    for coll in api_root.collections:
        print(f"  {coll.title} (ID: {coll.id})")
        print(f"  Read: {coll.can_read} | Write: {coll.can_write}")
```

### Push STIX Objects to a Collection
```python
import stix2
from taxii2client.v21 import Collection

collection = Collection(
    f"http://localhost:9000/collections/collection-001/",
    user="admin",
    password="admin123",
)

indicator = stix2.Indicator(
    name="Malicious C2 Domain",
    pattern="[domain-name:value = 'evil.example.com']",
    pattern_type="stix",
    valid_from="2025-01-15T00:00:00Z",
    labels=["malicious-activity"],
)

bundle = stix2.Bundle(objects=[indicator])
collection.add_objects(bundle.serialize())
```

### Fetch Objects from a Collection
```python
objects = collection.get_objects()
for obj in objects.get("objects", []):
    print(f"  {obj['type']}: {obj.get('name', obj['id'])}")
```

## Health Check

```python
import requests

resp = requests.get(
    "http://localhost:9000/taxii2/",
    auth=("admin", "admin123"),
    timeout=10,
)
if resp.status_code == 200:
    discovery = resp.json()
    print(f"Server title: {discovery.get('title')}")
    print(f"API roots: {discovery.get('api_roots', [])}")
```

## Output Format

```json
{
  "title": "OpenTAXII TAXII 2.1 Server",
  "description": "Threat intelligence sharing server",
  "api_roots": ["http://localhost:9000/api/"],
  "collections": [
    {
      "id": "collection-001",
      "title": "threat-indicators",
      "can_read": true,
      "can_write": true,
      "media_types": ["application/stix+json;version=2.1"]
    }
  ]
}
```
