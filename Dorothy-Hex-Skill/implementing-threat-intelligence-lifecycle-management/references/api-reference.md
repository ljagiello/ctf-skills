# API Reference: Threat Intelligence Lifecycle Management

## Libraries Used

| Library | Purpose |
|---------|---------|
| `pymisp` | MISP threat intelligence platform API client |
| `stix2` | Create, parse, and manipulate STIX 2.1 objects |
| `requests` | HTTP client for external TI feed APIs |
| `json` | Parse and serialize intelligence data |

## Installation

```bash
pip install pymisp stix2 requests
```

## Authentication

### MISP Connection
```python
from pymisp import PyMISP
import os

MISP_URL = os.environ["MISP_URL"]
MISP_KEY = os.environ["MISP_API_KEY"]
MISP_VERIFYCERT = os.environ.get("MISP_VERIFY", "True") == "True"

misp = PyMISP(MISP_URL, MISP_KEY, ssl=MISP_VERIFYCERT)
```

## MISP API Operations

### Search for Events
```python
def search_events(tags=None, date_from=None, published=True):
    results = misp.search(
        controller="events",
        tags=tags,
        date_from=date_from,
        published=published,
        limit=100,
    )
    return results
```

### Create a Threat Intelligence Event
```python
from pymisp import MISPEvent, MISPAttribute

def create_ti_event(info, threat_level=2, analysis=1):
    event = MISPEvent()
    event.info = info
    event.threat_level_id = threat_level  # 1=High, 2=Medium, 3=Low, 4=Undefined
    event.analysis = analysis  # 0=Initial, 1=Ongoing, 2=Completed
    event.distribution = 1  # 1=This community
    created = misp.add_event(event)
    return created
```

### Add Indicators to an Event
```python
def add_indicators(event_id, indicators):
    for ioc in indicators:
        attr = MISPAttribute()
        attr.type = ioc["type"]  # "ip-dst", "domain", "sha256", "url"
        attr.value = ioc["value"]
        attr.category = ioc.get("category", "Network activity")
        attr.to_ids = ioc.get("to_ids", True)
        attr.comment = ioc.get("comment", "")
        misp.add_attribute(event_id, attr)
```

### Search for Specific IOCs
```python
def search_ioc(ioc_type, value):
    results = misp.search(
        controller="attributes",
        type_attribute=ioc_type,
        value=value,
    )
    return results
```

### Tag Management
```python
# Add TLP marking
misp.tag(event_id, "tlp:amber")

# Add threat actor tag
misp.tag(event_id, "mitre-attack-pattern:T1566.001")

# Add custom taxonomy
misp.tag(event_id, "adversary:APT29")
```

## STIX 2.1 Intelligence Objects

### Create STIX Indicator
```python
import stix2

indicator = stix2.Indicator(
    name="Cobalt Strike C2 Domain",
    pattern="[domain-name:value = 'c2.evil.example.com']",
    pattern_type="stix",
    valid_from="2025-01-15T00:00:00Z",
    labels=["malicious-activity"],
    confidence=85,
    external_references=[
        stix2.ExternalReference(
            source_name="Internal IR",
            description="Observed during incident IR-2025-001",
        )
    ],
)
```

### Create STIX Threat Actor
```python
threat_actor = stix2.ThreatActor(
    name="APT29",
    aliases=["Cozy Bear", "The Dukes"],
    threat_actor_types=["nation-state"],
    roles=["agent"],
    sophistication="expert",
    resource_level="government",
    primary_motivation="espionage",
)
```

### Create Relationships and Bundle
```python
relationship = stix2.Relationship(
    relationship_type="indicates",
    source_ref=indicator.id,
    target_ref=threat_actor.id,
    confidence=80,
)

bundle = stix2.Bundle(objects=[indicator, threat_actor, relationship])
```

### Convert MISP Event to STIX
```python
def misp_to_stix(event):
    stix_objects = []
    for attr in event.get("Attribute", []):
        if attr["type"] == "ip-dst":
            stix_objects.append(stix2.Indicator(
                name=f"Malicious IP: {attr['value']}",
                pattern=f"[ipv4-addr:value = '{attr['value']}']",
                pattern_type="stix",
                valid_from=attr["timestamp"],
            ))
        elif attr["type"] == "domain":
            stix_objects.append(stix2.Indicator(
                name=f"Malicious Domain: {attr['value']}",
                pattern=f"[domain-name:value = '{attr['value']}']",
                pattern_type="stix",
                valid_from=attr["timestamp"],
            ))
    return stix2.Bundle(objects=stix_objects)
```

## Intelligence Lifecycle Phases

| Phase | MISP Action | STIX Object |
|-------|-------------|-------------|
| Collection | `misp.add_event()` | Bundle |
| Processing | `misp.add_attribute()` | Indicator, ObservedData |
| Analysis | `misp.tag()`, correlations | Relationship, ThreatActor |
| Dissemination | `misp.publish()`, TAXII push | Collection (TAXII) |
| Feedback | `misp.add_sighting()` | Sighting |

## Output Format

```json
{
  "lifecycle_phase": "analysis",
  "events_processed": 42,
  "indicators_created": 156,
  "stix_objects": {
    "indicators": 120,
    "threat_actors": 5,
    "malware": 8,
    "relationships": 95,
    "attack_patterns": 23
  },
  "tlp_distribution": {
    "tlp:white": 30,
    "tlp:green": 45,
    "tlp:amber": 65,
    "tlp:red": 16
  }
}
```
