---
name: operationalizing-misp-threat-feeds
description: Run MISP, curate feeds, and auto-generate detections for Wazuh, Sigma, and Suricata.
domain: cybersecurity
subdomain: threat-intelligence
tags:
- threat-intelligence
- misp
- pymisp
- threat-feeds
- ioc
- suricata
- sigma
- detection-engineering
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.RA-02
mitre_attack:
- T1589
---
# Operationalizing MISP Threat Feeds

> **Note:** This skill covers a defensive threat-intelligence platform. Handle ingested intelligence according to its Traffic Light Protocol (TLP) marking and your sharing agreements. Treat ingested IOCs as potentially sensitive.

## Overview

MISP (Malware Information Sharing Platform) is the de-facto open-source threat-intelligence platform for storing, correlating, and sharing structured indicators (IOCs), events, galaxies (threat-actor/technique knowledge), and objects. Running a MISP instance is only the first step; the value comes from *operationalizing* it — curating high-quality feeds, suppressing false positives with warninglists, and pushing the resulting IOCs into detection tooling so intelligence actually drives blocking and alerting.

A feed in MISP is a remote source (another MISP, a CSV/freetext list, or a structured collection) that you **enable** and optionally **cache**. Caching pulls the feed's IOCs into the instance's Redis-backed cache so values can be correlated and looked up in real time (e.g., a SIEM asking "have you seen this domain?") without importing every event. Curation matters: enabling every public feed produces noise and false positives, so you select reputable feeds (CIRCL OSINT, abuse.ch, Feodo Tracker, etc.), apply **warninglists** (known-good ranges like RFC1918, Alexa/Tranco top sites, public DNS resolvers) to flag non-actionable indicators, and use taxonomies/tags (TLP, confidence) to scope what gets exported.

The detection-engineering payoff comes from MISP's export formats and PyMISP. MISP can render matching attributes directly as **Suricata** and **Snort** rules via the REST API, and PyMISP lets you script extraction of fresh IOCs to generate **Sigma** rules and **Wazuh** CDB lists / rules on a schedule. This skill walks the full lifecycle: feed enablement and caching, warninglist-based FP reduction, PyMISP-driven search, and automated generation of Suricata, Sigma, and Wazuh detections.

## When to Use

- Standing up or maturing a MISP instance into a feed that drives detection, not just a repository.
- Curating and caching public/commercial threat feeds with quality controls.
- Reducing IOC false positives with warninglists before they reach the SIEM/IDS.
- Automating generation of Suricata/Sigma/Wazuh detections from MISP attributes.
- Integrating MISP with a SOC so DNS/IP/hash lookups can be enriched against current intel.

## Prerequisites

- A running MISP instance (the maintained container images are the fastest path):
  ```bash
  git clone https://github.com/MISP/misp-docker.git
  cd misp-docker && cp template.env .env
  docker compose up -d
  # Web UI on https://localhost; default admin: admin@admin.test / admin
  ```
- A MISP **Auth Key** (UI: Administration -> List Auth Keys -> Add).
- PyMISP:
  ```bash
  pip install pymisp
  ```
- Target detection tooling reachable: Suricata, a Sigma toolchain (`pip install sigma-cli`), and/or Wazuh manager.

## Objectives

- Enable and cache curated threat feeds in MISP.
- Apply warninglists to suppress known-good / non-actionable indicators.
- Authenticate and query MISP with PyMISP to pull fresh, scoped IOCs.
- Export matching attributes as Suricata/Snort rules via the REST API.
- Generate Sigma rules and Wazuh CDB lists from MISP attributes on a schedule.
- Validate that generated detections load and fire in the target tooling.

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Relevance |
|--------------|----------------|-----------|
| T1589 | Gather Victim Identity Information | Feeds capture adversary reconnaissance indicators; operationalizing them detects/contextualizes such activity. |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 domain/URL IOCs from feeds become Suricata/Sigma detections for malicious HTTP(S). |
| T1071.004 | Application Layer Protocol: DNS | Malicious-domain IOCs feed DNS-based detection (Wazuh/Suricata). |
| T1105 | Ingress Tool Transfer | File-hash IOCs from feeds detect known malicious payload delivery. |

## Workflow

### 1. Add and enable a feed
Register a reputable source and turn it on.
```python
# add_feed.py (PyMISP) — register the CIRCL OSINT feed
from pymisp import PyMISP, MISPFeed
misp = PyMISP("https://localhost", "YOUR_AUTH_KEY", ssl=False)
feed = MISPFeed()
feed.name = "CIRCL OSINT Feed"
feed.provider = "CIRCL"
feed.url = "https://www.circl.lu/doc/misp/feed-osint"
feed.source_format = "misp"
feed.input_source = "network"
feed.enabled = True
print(misp.add_feed(feed, pythonify=True))
```

### 2. Cache enabled feeds for real-time correlation
Caching loads feed IOCs into Redis so lookups are instant.
```python
# Cache all enabled feeds (equivalent to "Enable caching" in the UI)
print(misp.cache_all_feeds())
# Or fetch a single feed's events into the instance by feed id:
print(misp.fetch_feed(1))
```

### 3. Enable warninglists to reduce false positives
Turn on known-good lists so non-actionable indicators are flagged.
```python
# Enable the common false-positive warninglists
for wl in misp.warninglists(pythonify=True):
    if wl.name in ("List of RFC 1918 CIDR blocks",
                   "Top 1000 website from Cisco Umbrella",
                   "List of known public DNS resolvers"):
        misp.toggle_warninglist(warninglist_id=wl.id, force_enable=True)
```

### 4. Authenticate and search for fresh IOCs
Pull recently published, TLP-scoped, to-IDS attributes only.
```python
from pymisp import PyMISP
misp = PyMISP("https://localhost", "YOUR_AUTH_KEY", ssl=False)
# Only export attributes flagged to_ids=1, published, last 7 days, IP/domain/url/hash
attrs = misp.search(
    controller="attributes",
    type_attribute=["ip-dst", "domain", "url", "md5", "sha256"],
    to_ids=True, published=True, last="7d",
    enforce_warninglist=True,   # drop warninglisted (known-good) values
    pythonify=True,
)
print(f"{len(attrs)} actionable IOCs")
```

### 5. Export Suricata/Snort rules via the REST API
MISP renders matching attributes directly as IDS rules.
```bash
# Suricata rules for all to_ids network IOCs (NIDS export)
curl -s -k -H "Authorization: YOUR_AUTH_KEY" -H "Accept: application/json" \
  "https://localhost/attributes/restSearch/returnFormat:suricata/to_ids:1/type:domain%7Cip-dst%7Curl" \
  -o misp_suricata.rules

# Snort equivalent
curl -s -k -H "Authorization: YOUR_AUTH_KEY" -H "Accept: application/json" \
  "https://localhost/attributes/restSearch/returnFormat:snort/to_ids:1" -o misp_snort.rules
```

### 6. Deploy the Suricata rules
Load and reload.
```bash
cp misp_suricata.rules /etc/suricata/rules/
suricata -T -c /etc/suricata/suricata.yaml   # validate config + rules
suricatasc -c reload-rules                    # hot reload
```

### 7. Generate Wazuh CDB lists from IOCs
Convert MISP domains/IPs into a Wazuh CDB lookup list referenced by a rule.
```python
# Build a Wazuh CDB list (key:value per line) from the searched attributes
with open("misp_iocs.cdb", "w") as fh:
    for a in attrs:
        if a.type in ("domain", "ip-dst"):
            fh.write(f"{a.value}:\n")
# On the Wazuh manager: place under /var/ossec/etc/lists/, reference in ossec.conf:
#   <list>etc/lists/misp_iocs</list>
# then compile and restart:
#   /var/ossec/bin/wazuh-control restart
```

### 8. Generate Sigma rules from MISP intelligence
Emit a Sigma rule matching the exported domains.
```python
import yaml
domains = [a.value for a in attrs if a.type == "domain"]
sigma = {
    "title": "MISP feed malicious domain contact",
    "status": "experimental",
    "logsource": {"category": "dns"},
    "detection": {"selection": {"query|contains": domains}, "condition": "selection"},
    "level": "high",
    "tags": ["attack.command_and_control", "attack.t1071.004"],
}
with open("misp_domains.yml", "w") as fh:
    yaml.safe_dump(sigma, fh, sort_keys=False)
```

### 9. Convert and deploy Sigma to your SIEM backend
Use `sigma-cli` to compile to the target backend (Splunk, Elastic, etc.).
```bash
sigma convert -t splunk -p splunk_windows misp_domains.yml > misp_domains.spl
sigma convert -t elasticsearch misp_domains.yml > misp_domains.eql
```

### 10. Schedule the pipeline and run the bundled helper
`agent.py` searches MISP and writes Suricata/Sigma/Wazuh artifacts in one pass; schedule it via cron.
```bash
python scripts/agent.py --url https://localhost --key YOUR_AUTH_KEY \
  --last 7d --outdir ./detections --insecure
# crontab: 0 * * * * /usr/bin/python /path/scripts/agent.py ... >> /var/log/misp_pipeline.log 2>&1
```

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| MISP | Threat-intelligence platform | https://www.misp-project.org/ |
| misp-docker | Maintained container deployment | https://github.com/MISP/misp-docker |
| PyMISP | Python client for the MISP REST API | https://github.com/MISP/PyMISP |
| MISP warninglists | Known-good lists for FP reduction | https://github.com/MISP/misp-warninglists |
| MISP automation docs | REST API + export formats | https://www.circl.lu/doc/misp/automation/ |
| sigma-cli | Sigma rule conversion | https://github.com/SigmaHQ/sigma-cli |
| Wazuh CDB lists | IOC lookup lists for Wazuh | https://documentation.wazuh.com/ |

## Validation Criteria

- [ ] MISP instance reachable and an Auth Key created.
- [ ] At least one reputable feed enabled and cached.
- [ ] Relevant warninglists enabled and `enforce_warninglist` applied to searches.
- [ ] PyMISP search returns scoped, to_ids, non-warninglisted IOCs.
- [ ] Suricata/Snort rules exported via REST and validated with `suricata -T`.
- [ ] Wazuh CDB list generated and loaded by the manager.
- [ ] Sigma rule generated and converted to the SIEM backend.
- [ ] Generated detections confirmed to load (and fire on a test IOC).
- [ ] Pipeline scheduled and logging successfully.
