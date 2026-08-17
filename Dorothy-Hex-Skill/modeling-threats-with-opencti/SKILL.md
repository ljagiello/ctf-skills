---
name: modeling-threats-with-opencti
description: Model threat actors, intrusion sets, campaigns, and TTPs as a STIX 2.1 knowledge graph in OpenCTI (Filigran) using the pycti Python client, connectors, and import workers for structured cyber threat intelligence.
domain: cybersecurity
subdomain: threat-intelligence
tags:
- opencti
- threat-intelligence
- stix2
- pycti
- knowledge-graph
- threat-modeling
- mitre-attack
- cti
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.RA-03
mitre_attack:
- T1589
---
# Modeling Threats with OpenCTI

## Overview

OpenCTI (Open Cyber Threat Intelligence) is an open-source threat-intelligence platform developed by **Filigran** that lets analysts store, organize, visualize, and share structured cyber threat intelligence as a knowledge graph. Every object — Threat Actors, Intrusion Sets, Campaigns, Attack Patterns, Malware, Indicators, Observables, Vulnerabilities — is modeled on the **STIX 2.1** standard, and the relationships between them (`uses`, `attributed-to`, `targets`, `indicates`) form a graph that reveals how adversaries operate end to end.

Architecturally, OpenCTI is built from a GraphQL API backed by Elasticsearch/OpenSearch and a graph database, a Redis stream, RabbitMQ message broker, **import/export workers**, and **connectors**. Connectors retrieve information from external sources (MITRE ATT&CK, MISP, AlienVault OTX, CISA, abuse.ch, etc.), convert it into STIX 2.1 bundles, and submit those bundles to the platform; workers then ingest the bundles into the graph. The official Python client, **pycti** (`OpenCTIApiClient`), is the programmatic interface analysts use to create entities, build relationships, and push STIX bundles.

This skill follows the official OpenCTI documentation (docs.opencti.io) and the `OpenCTI-Platform/client-python` (pycti) repository. It maps to MITRE ATT&CK **T1589 (Gather Victim Identity Information)** as part of the broader CTI analysis lifecycle — OpenCTI is where reconnaissance and adversary tradecraft observed across reporting is consolidated, deduplicated, and modeled so detection and response teams can act on it. The threat context is the volume and fragmentation of modern CTI: hundreds of vendor reports, IOC feeds, and ATT&CK updates that are useless until correlated into a single, queryable adversary picture.

## When to Use

- Building a centralized, STIX-native knowledge base of threat actors, campaigns, and TTPs
- Correlating IOCs and reports from multiple feeds into a single adversary graph
- Mapping observed activity to MITRE ATT&CK techniques for coverage and gap analysis
- Producing structured intelligence (STIX bundles) for downstream detection engineering
- Tracking attribution: which intrusion sets are attributed to which threat actors and campaigns
- Automating CTI ingestion via connectors and the pycti API

## Prerequisites

- Docker and Docker Compose (OpenCTI is deployed as a container stack)
- Python 3.8+ for the pycti client:
  ```bash
  pip install pycti stix2
  ```
- An OpenCTI instance and an API token (Profile > API access in the UI)
- Familiarity with the STIX 2.1 data model (SDOs, SROs, observables)
- RabbitMQ, Redis, and Elasticsearch/OpenSearch reachable by the platform (handled by the reference compose)

## Objectives

- Deploy an OpenCTI platform with workers via Docker Compose
- Authenticate to the GraphQL API with pycti using an API token
- Create core STIX domain objects: Threat Actor, Intrusion Set, Campaign, Attack Pattern, Malware
- Build relationships (`uses`, `attributed-to`, `targets`) to form the adversary graph
- Enable connectors (MITRE ATT&CK, MISP) to auto-ingest intelligence
- Submit STIX 2.1 bundles via `send_stix2_bundle`
- Query the graph and export an actor's full TTP profile

## MITRE ATT&CK Mapping

| ID | Name | Relevance |
|----|------|-----------|
| T1589 | Gather Victim Identity Information | OpenCTI consolidates reconnaissance and victim/target intelligence observed across reporting into a structured, queryable knowledge graph that supports analysis of adversary targeting. |

## Workflow

### Step 1: Deploy the OpenCTI platform
Use the official Docker Compose stack. Generate the required tokens/UUIDs and start the platform, workers, and dependencies.
```bash
git clone https://github.com/OpenCTI-Platform/docker.git opencti-docker
cd opencti-docker

# Generate required secrets (UUID v4 for tokens, base64 for app secret)
cat > .env <<EOF
OPENCTI_ADMIN_EMAIL=admin@opencti.local
OPENCTI_ADMIN_PASSWORD=$(openssl rand -hex 16)
OPENCTI_ADMIN_TOKEN=$(cat /proc/sys/kernel/random/uuid)
OPENCTI_BASE_URL=http://localhost:8080
MINIO_ROOT_USER=$(cat /proc/sys/kernel/random/uuid)
MINIO_ROOT_PASSWORD=$(cat /proc/sys/kernel/random/uuid)
RABBITMQ_DEFAULT_USER=guest
RABBITMQ_DEFAULT_PASS=guest
ELASTIC_MEMORY_SIZE=4G
CONNECTOR_HISTORY_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_EXPORT_FILE_STIX_ID=$(cat /proc/sys/kernel/random/uuid)
EOF

# Increase vm.max_map_count for Elasticsearch, then start the stack
sudo sysctl -w vm.max_map_count=1048575
docker compose up -d
```
Access the UI at http://localhost:8080 and log in with the admin credentials from `.env`.

### Step 2: Authenticate with pycti
Create an `OpenCTIApiClient` instance using your platform URL and API token.
```python
from pycti import OpenCTIApiClient

opencti = OpenCTIApiClient(
    "http://localhost:8080",
    "YOUR_API_TOKEN",  # from Profile > API access, or OPENCTI_ADMIN_TOKEN
)
```

### Step 3: Create core STIX domain objects
Create a Threat Actor, an Intrusion Set, a Campaign, and an Attack Pattern. pycti `create()` calls act as upserts when `update=True`.
```python
# Threat Actor (group)
actor = opencti.threat_actor_group.create(
    name="APT-EXAMPLE",
    description="Financially motivated intrusion group tracked in this case.",
    threat_actor_types=["crime-syndicate"],
)

# Intrusion Set
intrusion_set = opencti.intrusion_set.create(
    name="EXAMPLE-SET",
    description="Cluster of activity sharing infrastructure and TTPs.",
)

# Campaign
campaign = opencti.campaign.create(
    name="Operation Example 2026",
    description="Spearphishing campaign targeting the finance sector.",
)

# Attack Pattern linked to MITRE ATT&CK (x_mitre_id maps to the technique)
technique = opencti.attack_pattern.create(
    name="Spearphishing Attachment",
    x_mitre_id="T1566.001",
)
```

### Step 4: Build relationships to form the graph
Connect the objects with STIX relationships so the graph reflects how the adversary operates.
```python
# Intrusion set attributed to the threat actor
opencti.stix_core_relationship.create(
    fromId=intrusion_set["id"],
    toId=actor["id"],
    relationship_type="attributed-to",
)

# Campaign attributed to the intrusion set
opencti.stix_core_relationship.create(
    fromId=campaign["id"],
    toId=intrusion_set["id"],
    relationship_type="attributed-to",
)

# Intrusion set uses the technique
opencti.stix_core_relationship.create(
    fromId=intrusion_set["id"],
    toId=technique["id"],
    relationship_type="uses",
)
```

### Step 5: Add indicators and observables
Create an indicator with a STIX pattern and tie it to the intrusion set via an `indicates` relationship.
```python
from dateutil.parser import parse

date = parse("2026-06-01").strftime("%Y-%m-%dT%H:%M:%SZ")

indicator = opencti.indicator.create(
    name="C2 domain for Operation Example",
    pattern_type="stix",
    pattern="[domain-name:value = 'malicious-c2.example']",
    x_opencti_main_observable_type="Domain-Name",
    valid_from=date,
)

opencti.stix_core_relationship.create(
    fromId=indicator["id"],
    toId=intrusion_set["id"],
    relationship_type="indicates",
)
```

### Step 6: Submit a STIX 2.1 bundle directly
For bulk ingestion, build a STIX bundle and submit it with `send_stix2_bundle` — the recommended bulk-ingest path.
```python
import json

with open("threat_report_bundle.json") as f:
    bundle = json.load(f)

opencti.stix2.import_bundle_from_json(
    json.dumps(bundle),
    update=True,
)
```

### Step 7: Enable connectors for automated ingestion
Add connectors to the compose stack so external intelligence (MITRE ATT&CK, MISP) is ingested continuously. Each connector needs its own token.
```yaml
# Append to docker-compose.yml under services:
  connector-mitre:
    image: opencti/connector-mitre:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${CONNECTOR_MITRE_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_MITRE_ID}
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - CONNECTOR_NAME=MITRE ATT&CK
      - CONNECTOR_SCOPE=tool,report,malware,identity,attack-pattern,intrusion-set,campaign
      - MITRE_INTERVAL=7   # days
    restart: always
```
```bash
docker compose up -d connector-mitre
```

### Step 8: Query the graph and export an actor profile
Read back the adversary's full picture for reporting and detection engineering.
```python
# Resolve all techniques an intrusion set uses
iset = opencti.intrusion_set.read(filters={
    "mode": "and",
    "filters": [{"key": "name", "values": ["EXAMPLE-SET"]}],
    "filterGroups": [],
})

rels = opencti.stix_core_relationship.list(
    fromId=iset["id"],
    relationship_type="uses",
)
for r in rels:
    print(r["to"]["name"], r["to"].get("x_mitre_id"))
```

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| OpenCTI Platform | STIX 2.1 threat-intel knowledge graph | https://github.com/OpenCTI-Platform/opencti |
| OpenCTI Docker | Reference compose stack | https://github.com/OpenCTI-Platform/docker |
| pycti | Official Python client for the GraphQL API | https://github.com/OpenCTI-Platform/client-python |
| OpenCTI Connectors | Importers (MITRE, MISP, OTX, CISA, abuse.ch) | https://github.com/OpenCTI-Platform/connectors |
| OpenCTI docs | Official documentation | https://docs.opencti.io/latest/ |
| STIX 2.1 spec | Underlying data model | https://oasis-open.github.io/cti-documentation/ |

## STIX Object Cheat Sheet (pycti entities)

| pycti entity | STIX type | Use |
|--------------|-----------|-----|
| `threat_actor_group` | threat-actor | Named adversary group |
| `intrusion_set` | intrusion-set | Clustered activity / tracked set |
| `campaign` | campaign | Time-bounded operation |
| `attack_pattern` | attack-pattern | MITRE ATT&CK technique |
| `malware` | malware | Tooling/implant |
| `indicator` | indicator | Detection pattern (STIX/Sigma/YARA) |
| `vulnerability` | vulnerability | CVE |
| `stix_core_relationship` | relationship | `uses`, `attributed-to`, `targets`, `indicates` |

## Validation Criteria

- [ ] OpenCTI platform and workers deployed and reachable at the base URL
- [ ] pycti authenticates with a valid API token
- [ ] Threat Actor, Intrusion Set, Campaign, and Attack Pattern objects created
- [ ] Relationships (`attributed-to`, `uses`, `indicates`) built between objects
- [ ] At least one indicator created and linked to an intrusion set
- [ ] A STIX 2.1 bundle ingested via `import_bundle_from_json`
- [ ] MITRE ATT&CK connector enabled and importing techniques
- [ ] Intrusion-set TTP profile queryable and exportable
