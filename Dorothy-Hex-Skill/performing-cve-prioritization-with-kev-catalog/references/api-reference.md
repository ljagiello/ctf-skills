# API Reference: CISA KEV Catalog CVE Prioritization

## Libraries Used

| Library | Purpose |
|---------|---------|
| `requests` | Fetch KEV catalog JSON from CISA |
| `json` | Parse vulnerability entries and match against scan data |
| `csv` | Read vulnerability scanner CSV exports |
| `datetime` | Calculate remediation deadlines and SLA compliance |

## Installation

```bash
pip install requests
```

## Data Sources

### CISA KEV JSON Feed
```
URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
Format: JSON
Authentication: None (public)
Update frequency: Updated as new exploited CVEs are added (typically several times per week)
```

### CISA KEV CSV Feed
```
URL: https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv
Format: CSV
```

### GitHub Mirror
```
URL: https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json
```

## Core Operations

### Fetch the KEV Catalog
```python
import requests
from datetime import datetime

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_kev_catalog():
    resp = requests.get(KEV_URL, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return {
        "title": data["title"],
        "catalog_version": data["catalogVersion"],
        "date_released": data["dateReleased"],
        "count": data["count"],
        "vulnerabilities": data["vulnerabilities"],
    }
```

### KEV Entry Schema

| Field | Type | Description |
|-------|------|-------------|
| `cveID` | string | CVE identifier (e.g., "CVE-2024-12345") |
| `vendorProject` | string | Affected vendor (e.g., "Microsoft") |
| `product` | string | Affected product (e.g., "Windows") |
| `vulnerabilityName` | string | Human-readable vulnerability description |
| `dateAdded` | string | Date added to KEV (YYYY-MM-DD) |
| `shortDescription` | string | Brief vulnerability description |
| `requiredAction` | string | CISA-recommended remediation action |
| `dueDate` | string | Remediation deadline for federal agencies (YYYY-MM-DD) |
| `knownRansomwareCampaignUse` | string | "Known" or "Unknown" ransomware association |
| `notes` | string | Additional context |

### Match Scan Results Against KEV
```python
def match_scan_to_kev(scan_cves, kev_catalog):
    """Cross-reference vulnerability scan CVEs against the KEV catalog."""
    kev_lookup = {v["cveID"]: v for v in kev_catalog["vulnerabilities"]}
    matched = []
    unmatched = []

    for cve_id in scan_cves:
        if cve_id in kev_lookup:
            entry = kev_lookup[cve_id]
            matched.append({
                "cve": cve_id,
                "vendor": entry["vendorProject"],
                "product": entry["product"],
                "due_date": entry["dueDate"],
                "ransomware": entry["knownRansomwareCampaignUse"],
                "action": entry["requiredAction"],
                "overdue": datetime.strptime(entry["dueDate"], "%Y-%m-%d") < datetime.now(),
            })
        else:
            unmatched.append(cve_id)

    return {"kev_matches": matched, "non_kev": unmatched}
```

### Prioritize by Risk
```python
def prioritize_kev_findings(kev_matches):
    """Sort KEV matches by priority: overdue > ransomware > due date."""
    def priority_key(entry):
        score = 0
        if entry["overdue"]:
            score += 1000
        if entry["ransomware"] == "Known":
            score += 500
        # Earlier due dates get higher priority
        days_until = (datetime.strptime(entry["due_date"], "%Y-%m-%d") - datetime.now()).days
        score -= days_until
        return -score

    return sorted(kev_matches, key=priority_key)
```

### Generate Remediation Report
```python
def generate_report(scan_results, kev_catalog):
    matches = match_scan_to_kev(scan_results, kev_catalog)

    overdue = [m for m in matches["kev_matches"] if m["overdue"]]
    ransomware = [m for m in matches["kev_matches"] if m["ransomware"] == "Known"]

    return {
        "total_vulns_scanned": len(scan_results),
        "kev_matches": len(matches["kev_matches"]),
        "overdue_count": len(overdue),
        "ransomware_associated": len(ransomware),
        "critical_actions": prioritize_kev_findings(matches["kev_matches"])[:10],
        "non_kev_vulns": len(matches["non_kev"]),
    }
```

### Monitor KEV Catalog Updates
```python
def check_for_new_entries(last_known_count):
    """Check if new vulnerabilities have been added to KEV."""
    catalog = fetch_kev_catalog()
    current_count = catalog["count"]
    if current_count > last_known_count:
        new_entries = catalog["vulnerabilities"][last_known_count:]
        return {
            "new_entries": len(new_entries),
            "latest": new_entries,
            "total": current_count,
        }
    return {"new_entries": 0, "total": current_count}
```

## Output Format

```json
{
  "catalog_version": "2025.01.15",
  "total_kev_entries": 1150,
  "scan_matches": 12,
  "overdue": 3,
  "ransomware_associated": 5,
  "critical_actions": [
    {
      "cve": "CVE-2024-21887",
      "vendor": "Ivanti",
      "product": "Connect Secure",
      "due_date": "2024-01-31",
      "ransomware": "Known",
      "overdue": true,
      "action": "Apply mitigations per vendor instructions or discontinue use."
    }
  ]
}
```
