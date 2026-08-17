# API Reference — OpenCTI / pycti

## Client initialization

```python
from pycti import OpenCTIApiClient
opencti = OpenCTIApiClient("http://localhost:8080", "API_TOKEN")
```

| Constructor arg | Purpose |
|-----------------|---------|
| url | Base URL of the OpenCTI platform |
| token | API token (Profile > API access) |
| ssl_verify | Verify TLS (default False for self-hosted dev) |
| log_level | `info`, `debug`, etc. |

## Core entity creators (upsert with `update=True`)

| Method | STIX type | Key arguments |
|--------|-----------|---------------|
| `opencti.threat_actor_group.create(...)` | threat-actor | name, description, threat_actor_types |
| `opencti.intrusion_set.create(...)` | intrusion-set | name, description, first_seen, last_seen |
| `opencti.campaign.create(...)` | campaign | name, description, objective |
| `opencti.attack_pattern.create(...)` | attack-pattern | name, x_mitre_id |
| `opencti.malware.create(...)` | malware | name, is_family, malware_types |
| `opencti.indicator.create(...)` | indicator | name, pattern, pattern_type, x_opencti_main_observable_type, valid_from |
| `opencti.vulnerability.create(...)` | vulnerability | name (CVE id), description |
| `opencti.identity.create(...)` | identity | name, type (organization/individual/sector) |

## Relationships

```python
opencti.stix_core_relationship.create(
    fromId=..., toId=..., relationship_type="uses")
```

| relationship_type | Meaning |
|-------------------|---------|
| uses | Actor/set/campaign uses a technique, tool, or malware |
| attributed-to | Campaign -> intrusion-set -> threat-actor |
| targets | Adversary targets an identity/sector/location |
| indicates | Indicator indicates a malware/intrusion-set/campaign |
| based-on | Indicator based-on an observable |

## Reading / listing

| Method | Purpose |
|--------|---------|
| `opencti.intrusion_set.read(filters=...)` | Read a single object by filter |
| `opencti.stix_core_relationship.list(fromId=..., relationship_type=...)` | List relationships from an object |
| `opencti.stix_domain_object.list(types=[...])` | List SDOs by type |

## Bundle ingestion

| Method | Purpose |
|--------|---------|
| `opencti.stix2.import_bundle_from_json(json_str, update=True)` | Import a STIX 2.1 bundle (JSON string) |
| `opencti.stix2.import_bundle_from_file(path, update=True)` | Import a bundle from a file |
| `connector_helper.send_stix2_bundle(bundle)` | Connector path to send a bundle to workers |

## Connector environment variables (compose)

| Variable | Purpose |
|----------|---------|
| OPENCTI_URL | Platform URL reachable by the connector |
| OPENCTI_TOKEN | Connector-specific API token |
| CONNECTOR_ID | UUID v4 unique per connector |
| CONNECTOR_TYPE | EXTERNAL_IMPORT / INTERNAL_ENRICHMENT / STREAM |
| CONNECTOR_SCOPE | STIX types the connector handles |
| CONNECTOR_NAME | Display name |

## Deployment quick reference

| Command | Purpose |
|---------|---------|
| `docker compose up -d` | Start platform, workers, dependencies |
| `sysctl -w vm.max_map_count=1048575` | Required for Elasticsearch |
| `cat /proc/sys/kernel/random/uuid` | Generate UUID v4 tokens |
