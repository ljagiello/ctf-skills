# MISP / PyMISP API Reference

## PyMISP client

Install: `pip install pymisp`

```python
from pymisp import PyMISP
misp = PyMISP("https://misp.example", "AUTH_KEY", ssl=True)
```

### Feed management
| Method | Description |
|--------|-------------|
| `misp.feeds(pythonify=True)` | List configured feeds. |
| `misp.add_feed(MISPFeed, pythonify=True)` | Register a new feed. |
| `misp.enable_feed(feed_id)` / `misp.disable_feed(feed_id)` | Toggle a feed. |
| `misp.fetch_feed(feed_id)` | Pull a feed's events into the instance. |
| `misp.cache_feeds(scope)` / `misp.cache_all_feeds()` | Cache feed IOCs into Redis for correlation. |

### Searching attributes/events
| Call | Description |
|------|-------------|
| `misp.search(controller="attributes", ...)` | Search attributes (IOCs). |
| `type_attribute=[...]` | Filter by attribute type (`ip-dst`, `domain`, `url`, `md5`, `sha256`). |
| `to_ids=True` | Only IDS-flagged (actionable) attributes. |
| `published=True` | Only attributes in published events. |
| `last="7d"` | Published within a time window. |
| `enforce_warninglist=True` | Drop values matching enabled warninglists. |
| `tags=["tlp:white"]` | Filter by tag/taxonomy. |

### Warninglists
| Method | Description |
|--------|-------------|
| `misp.warninglists(pythonify=True)` | List warninglists. |
| `misp.toggle_warninglist(warninglist_id=ID, force_enable=True)` | Enable a warninglist. |

## REST restSearch return formats

Endpoint: `POST/GET https://<misp>/attributes/restSearch/` with header `Authorization: <AUTH_KEY>`.

Path-style modifiers: `returnFormat:<fmt>/to_ids:1/type:<a%7Cb%7Cc>/last:7d/published:1`

| returnFormat | Output |
|--------------|--------|
| `json` | Native JSON. |
| `suricata` | Suricata IDS rules. |
| `snort` | Snort IDS rules. |
| `csv` | CSV of attributes. |
| `text` | Plain value list (one per line). |
| `stix2` | STIX 2.1 bundle. |

Example:
```bash
curl -s -k -H "Authorization: AUTH_KEY" -H "Accept: application/json" \
  "https://misp/attributes/restSearch/returnFormat:suricata/to_ids:1/type:domain%7Cip-dst" \
  -o misp.rules
```

## Downstream deployment

| Tool | Command |
|------|---------|
| Suricata validate | `suricata -T -c /etc/suricata/suricata.yaml` |
| Suricata reload | `suricatasc -c reload-rules` |
| Wazuh restart | `/var/ossec/bin/wazuh-control restart` |
| Sigma convert | `sigma convert -t splunk -p splunk_windows rule.yml` |
