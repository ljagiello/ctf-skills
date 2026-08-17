# API Reference: SBOM Supply Chain Vulnerability Analysis

## NVD API 2.0 - Vulnerability Lookup

### Base URL
```
https://services.nvd.nist.gov/rest/json/cves/2.0
```

### Authentication
```
Header: apiKey: <your-api-key>
Get free key: https://nvd.nist.gov/developers/request-an-api-key
```

### Rate Limits
| Condition | Limit |
|-----------|-------|
| Without API key | 5 requests per 30 seconds |
| With API key | 50 requests per 30 seconds |

### Search by CPE Name
```bash
GET /rest/json/cves/2.0?cpeName=cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*
```

```python
import requests

resp = requests.get(
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
    params={"cpeName": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"},
    headers={"apiKey": "YOUR_KEY"},
    timeout=30
)
data = resp.json()
for vuln in data.get("vulnerabilities", []):
    cve = vuln["cve"]
    print(f"{cve['id']}: {cve['metrics']}")
```

### Search by Keyword
```bash
GET /rest/json/cves/2.0?keywordSearch=lodash+prototype+pollution
```

### Search by CVE ID
```bash
GET /rest/json/cves/2.0?cveId=CVE-2021-44228
```

### Response Structure
```json
{
  "resultsPerPage": 50,
  "startIndex": 0,
  "totalResults": 3,
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2021-44228",
        "published": "2021-12-10T10:15:00.000",
        "descriptions": [{"lang": "en", "value": "Apache Log4j2 ..."}],
        "metrics": {
          "cvssMetricV31": [{
            "cvssData": {
              "version": "3.1",
              "baseScore": 10.0,
              "baseSeverity": "CRITICAL"
            }
          }]
        },
        "references": [{"url": "https://..."}]
      }
    }
  ]
}
```

## CycloneDX JSON Format (v1.5)

### Minimal Structure
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "metadata": {
    "timestamp": "2026-03-19T00:00:00Z",
    "tools": [{"name": "syft", "version": "1.0.0"}]
  },
  "components": [],
  "dependencies": []
}
```

### Component Object
```json
{
  "type": "library",
  "name": "express",
  "version": "4.18.2",
  "purl": "pkg:npm/express@4.18.2",
  "cpe": "cpe:2.3:a:expressjs:express:4.18.2:*:*:*:*:node.js:*:*",
  "licenses": [{"license": {"id": "MIT"}}],
  "supplier": {"name": "OpenJS Foundation"}
}
```

### Dependency Graph
```json
{
  "dependencies": [
    {
      "ref": "pkg:npm/express@4.18.2",
      "dependsOn": [
        "pkg:npm/body-parser@1.20.1",
        "pkg:npm/cookie@0.5.0"
      ]
    }
  ]
}
```

## SPDX JSON Format (v2.3)

### Minimal Structure
```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-application",
  "packages": [],
  "relationships": []
}
```

### Package Object
```json
{
  "SPDXID": "SPDXRef-Package-npm-express",
  "name": "express",
  "versionInfo": "4.18.2",
  "downloadLocation": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
  "licenseConcluded": "MIT",
  "licenseDeclared": "MIT",
  "externalRefs": [
    {"referenceType": "purl", "referenceLocator": "pkg:npm/express@4.18.2"},
    {"referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:expressjs:express:4.18.2:*:*:*:*:*:*:*"}
  ]
}
```

### Relationship Types
```json
{
  "spdxElementId": "SPDXRef-Package-npm-express",
  "relatedSpdxElement": "SPDXRef-Package-npm-body-parser",
  "relationshipType": "DEPENDS_ON"
}
```

## syft - SBOM Generation

### Installation
```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

### Generate CycloneDX SBOM
```bash
syft <source> -o cyclonedx-json > sbom.json

# Sources: container image, directory, file archive
syft alpine:latest -o cyclonedx-json
syft dir:/app -o cyclonedx-json
syft file:archive.tar.gz -o spdx-json
```

### Output Formats
| Format | Flag |
|--------|------|
| CycloneDX JSON | `-o cyclonedx-json` |
| CycloneDX XML | `-o cyclonedx-xml` |
| SPDX JSON | `-o spdx-json` |
| SPDX Tag-Value | `-o spdx-tag-value` |
| Syft JSON | `-o json` (default) |
| Table | `-o table` |

## grype - Vulnerability Scanning

### Installation
```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

### Scan SBOM for Vulnerabilities
```bash
# Scan CycloneDX SBOM
grype sbom:sbom-cyclonedx.json

# JSON output
grype sbom:sbom.json -o json > grype-results.json

# Filter by severity
grype sbom:sbom.json --only-fixed --fail-on critical

# Table output with severity filter
grype sbom:sbom.json -o table --only-fixed
```

### Grype Vulnerability Sources
- NVD (National Vulnerability Database)
- GitHub Security Advisories (GHSA)
- Alpine SecDB
- Red Hat Enterprise Linux
- Debian Security Tracker
- Ubuntu CVE Tracker
- Amazon Linux ALAS
- Oracle Linux ELSA
- Wolfi SecDB

## Python Libraries

### nvdlib - NVD API Wrapper
```python
import nvdlib

# Search CVEs by CPE
results = nvdlib.searchCVE(cpeName="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
for cve in results:
    print(f"{cve.id}: CVSS {cve.score[1]}")

# Search CVEs by keyword
results = nvdlib.searchCVE(keywordSearch="lodash prototype pollution")
```

### networkx - Dependency Graph
```python
import networkx as nx

G = nx.DiGraph()
G.add_edge("app", "framework")
G.add_edge("framework", "vulnerable-lib")

# Find all paths to a vulnerable component
paths = nx.all_simple_paths(G, "app", "vulnerable-lib")

# Betweenness centrality (bottleneck identification)
centrality = nx.betweenness_centrality(G)

# Longest dependency chain (DAG only)
longest = nx.dag_longest_path(G)
```

## CLI Usage Examples

```bash
# Full SBOM analysis with NVD correlation
python agent.py analyze sbom-cyclonedx.json --api-key YOUR_KEY -o report.json

# Offline analysis (skip NVD queries)
python agent.py analyze sbom.json --skip-nvd -o report.json

# Compare two SBOMs
python agent.py diff old-sbom.json new-sbom.json

# Parse and list components only
python agent.py parse sbom.json -o components.json

# Check license compliance
python agent.py licenses sbom.json
```
