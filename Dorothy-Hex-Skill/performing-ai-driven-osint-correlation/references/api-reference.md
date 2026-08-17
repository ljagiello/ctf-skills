# API Reference: Performing AI-Driven OSINT Correlation

## CLI Usage

```bash
# Correlate Sherlock + theHarvester results
python agent.py --target "targetdomain.com" \
  --sherlock sherlock-results.csv \
  --harvester harvester-results.json \
  -o correlation_report.json

# Full multi-source correlation
python agent.py --target "john.doe" \
  --sherlock sherlock.csv \
  --harvester harvester.json \
  --spiderfoot spiderfoot.json \
  --breach breach-results.json \
  -o report.json \
  --markdown intelligence-profile.md

# Normalize only (no correlation)
python agent.py --sherlock sherlock.csv --harvester harvester.json \
  --normalize-only -o normalized.json

# Load pre-normalized generic findings
python agent.py --generic normalized_findings.json -o report.json
```

## Supported Data Sources

| Source | Flag | Input Format | Data Extracted |
|--------|------|-------------|----------------|
| Sherlock | `--sherlock` | CSV or text | Usernames, social profile URLs, platforms |
| theHarvester | `--harvester` | JSON | Emails, hostnames, IP addresses |
| SpiderFoot | `--spiderfoot` | JSON | Mixed OSINT findings (200+ module types) |
| Breach/HIBP | `--breach` | JSON | Breach names, dates, data classes |
| Generic | `--generic` | JSON array | Any pre-normalized findings |

## Input File Formats

### Sherlock CSV Format

```csv
username,name,url_user,exists,http_status
johndoe,GitHub,https://github.com/johndoe,Claimed,200
johndoe,Twitter,https://twitter.com/johndoe,Claimed,200
```

### theHarvester JSON Format

```json
{
  "emails": ["john@targetdomain.com", "admin@targetdomain.com"],
  "hosts": ["mail.targetdomain.com", "vpn.targetdomain.com"],
  "ips": ["203.0.113.10", "203.0.113.11"]
}
```

### SpiderFoot JSON Format

```json
[
  {"type": "EMAILADDR", "data": "john@targetdomain.com", "module": "sfp_hunter"},
  {"type": "IP_ADDRESS", "data": "203.0.113.10", "module": "sfp_dnsresolve"},
  {"type": "SOCIAL_MEDIA", "data": "https://github.com/johndoe", "module": "sfp_github"}
]
```

### Breach/HIBP JSON Format

```json
[
  {
    "Name": "ExampleBreach",
    "BreachDate": "2023-06-15",
    "DataClasses": ["Email addresses", "Passwords", "Usernames"]
  }
]
```

## Correlation Confidence Scoring

| Factor | Weight | Description |
|--------|--------|-------------|
| Exact email match | 0.95 | Same email found across multiple sources |
| Breach email match | 0.90 | Email found in breach database |
| Exact username match | 0.85 | Same username across multiple platforms |
| Same IP infrastructure | 0.70 | Shared IP address or hosting |
| Domain match | 0.60 | Shared domain registration or hosting |
| Similar username | 0.45 | Partial username overlap with shared metadata |
| Temporal co-registration | 0.40 | Accounts created within similar timeframe |

Cross-source corroboration increases confidence: +0.15 per additional source, capped at 0.95.

## Report Output Schema

```json
{
  "meta": {
    "target": "targetdomain.com",
    "generated_at": "2026-03-19T12:00:00+00:00",
    "sources_used": ["sherlock", "theHarvester", "spiderfoot", "breach_database"],
    "total_findings": 247,
    "total_entities": 12
  },
  "identifiers": {
    "usernames": ["johndoe", "jdoe"],
    "emails": ["john@targetdomain.com"],
    "domains": ["targetdomain.com"],
    "ip_addresses": ["203.0.113.10"],
    "urls": ["https://github.com/johndoe"]
  },
  "entities": [
    {
      "identifier": "johndoe",
      "identifier_type": "user",
      "confidence": 0.92,
      "sources": ["sherlock", "theHarvester", "breach_database"],
      "source_count": 3,
      "linked_accounts": [
        {"source": "sherlock", "platform": "GitHub", "url": "https://github.com/johndoe"}
      ],
      "flags": ["Exposed in 2 breach(es)"],
      "risk_level": "high"
    }
  ],
  "risk_summary": {
    "high_risk": 2,
    "medium_risk": 5,
    "low_risk": 5
  }
}
```

## Markdown Report Output

The `--markdown` flag generates an intelligence profile in Markdown containing:
- Target metadata and source summary
- Risk summary table
- Entity profiles with linked accounts, confidence scores, and risk flags

## OSINT Tool Commands (Data Collection)

```bash
# Sherlock: enumerate username across platforms
sherlock "targetuser" --output sherlock.csv --csv

# theHarvester: harvest emails and subdomains
theHarvester -d targetdomain.com -b all -f harvester.json

# SpiderFoot: passive scan via REST API
curl -s http://localhost:5001/api/scan/start \
  -d "scanname=recon&scantarget=targetdomain.com&usecase=passive"

# HIBP: check email breach exposure
curl -s -H "hibp-api-key: ${HIBP_KEY}" -H "User-Agent: OSINT-Agent" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/target@example.com" \
  -o breach.json
```

## References

- Sherlock Project: https://github.com/sherlock-project/sherlock
- theHarvester: https://github.com/laramies/theHarvester
- SpiderFoot: https://github.com/smicallef/spiderfoot
- HIBP API: https://haveibeenpwned.com/API/v3
- Maltego: https://www.maltego.com/
- LOLBAS for graph visualization: https://lolbas-project.github.io/
