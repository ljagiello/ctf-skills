# Reference: Attack Surface Management

## Exposure Scoring Algorithm

### Weighted Formula

The exposure score uses a weighted composite of five factors, each normalized to 0-100:

```
Exposure Score = (Port_Score * 0.25) + (Vuln_Score * 0.30) + (Tech_Score * 0.15)
               + (Exposure_Score * 0.15) + (Data_Score * 0.15)
```

### Component Scoring

**Open Ports (25% weight)**
- Each port has a risk weight from PORT_RISK_WEIGHTS (1.0-9.5)
- Management ports (SSH, RDP, Telnet): 8.0-9.5
- Database ports (MySQL, MongoDB, Redis): 9.0-9.5
- Web ports (HTTP, HTTPS): 2.5-3.0
- Formula: `min(100, (avg_weight * 10) * log2(count + 1))`

**Vulnerabilities (30% weight)**
- Weighted by CVSS score bands: Critical=10, High=7, Medium=4, Low=2
- Diminishing returns via logarithmic scaling
- Formula: `min(100, total_weight * log2(count + 1))`

**Technology Risk (15% weight)**
- Known high-risk technologies scored 2.0-8.0
- Struts (8.0), phpMyAdmin (8.0), WebLogic (7.0), Jenkins (7.0)
- Unknown technologies get baseline score of 10.0

**Exposure Level (15% weight)**
- Base score 50 for internet-facing
- HTTP-only: +15 | CDN protected: -20
- Auth required (401/403): -25
- Admin/login panel detected: +20

**Data Sensitivity (15% weight)**
- Exposed database ports: +20 each
- File sharing ports (FTP, SMB): +15 each
- Sensitive service indicators: +15 each

### Risk Levels

| Score Range | Risk Level |
|-------------|------------|
| 80-100 | CRITICAL |
| 60-79 | HIGH |
| 40-59 | MEDIUM |
| 20-39 | LOW |
| 0-19 | INFORMATIONAL |

## OWASP Attack Surface Analysis

### Entry Points to Catalog

Per OWASP Attack Surface Analysis Cheat Sheet:
- Network-accessible ports and services
- Web application endpoints and parameters
- Authentication mechanisms
- File upload functions
- Administrative interfaces
- API endpoints
- Form fields and query parameters

### Relative Attack Surface Quotient (RSQ)

Microsoft's RSQ methodology counts:
1. **Channels**: TCP/UDP ports, RPC endpoints, named pipes
2. **Methods**: HTTP verbs, RPC methods, API functions
3. **Data Items**: Files, registry keys, database records

RSQ = sum of (damage_potential / effort) for each attack vector

## Shodan Search Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `hostname:` | Search by hostname | `hostname:example.com` |
| `org:` | Search by organization | `org:"Example Corp"` |
| `net:` | Search by CIDR | `net:93.184.216.0/24` |
| `port:` | Filter by port | `port:3389` |
| `product:` | Filter by product | `product:nginx` |
| `os:` | Filter by OS | `os:"Windows Server 2019"` |
| `ssl.cert.subject.cn:` | SSL cert CN | `ssl.cert.subject.cn:example.com` |
| `vuln:` | Search by CVE | `vuln:CVE-2021-44228` |
| `country:` | Filter by country | `country:US` |
| `has_vuln:true` | Has known vulns | `hostname:example.com has_vuln:true` |

## Censys Search Syntax

| Query | Description |
|-------|-------------|
| `services.port: 443` | Hosts with port 443 open |
| `services.tls.certificates.leaf.subject.common_name: example.com` | SSL cert match |
| `services.http.response.html_title: "Admin"` | Page title match |
| `services.software.product: "Apache"` | Software product |
| `location.country: "United States"` | Geographic filter |
| `autonomous_system.asn: 13335` | ASN filter |

## ProjectDiscovery Tool Chain

### subfinder
Passive subdomain discovery using 50+ data sources:
- Certificate transparency (crt.sh, Certspotter)
- DNS datasets (DNSdumpster, SecurityTrails)
- Search engines (Google, Bing, Yahoo)
- Web archives (Wayback Machine, CommonCrawl)
- Shodan, Censys, VirusTotal APIs

```bash
subfinder -d example.com -all -recursive -o subs.txt
```

### httpx
HTTP toolkit for probing and fingerprinting:
- Status codes, content length, content type
- Technology detection (Wappalyzer)
- Favicon hash, JARM fingerprint
- CDN detection, CNAME resolution

```bash
cat subs.txt | httpx -sc -cl -ct -title -tech-detect -json -o httpx.json
```

### nuclei
Template-based vulnerability scanner:
- 10,000+ community templates
- Severity-based filtering
- Protocol support: HTTP, DNS, TCP, SSL, File
- Automatic template updates

```bash
cat live_hosts.txt | nuclei -severity critical,high -tags cve -o findings.txt
```

## Port Risk Classification

### Critical Exposure (Score 9.0+)
- 23 (Telnet): Unencrypted remote access
- 27017 (MongoDB): Often misconfigured without auth
- 6379 (Redis): Commonly exposed without auth
- 445 (SMB): Ransomware propagation vector

### High Exposure (Score 7.0-8.9)
- 22 (SSH): Brute force target
- 3389 (RDP): BlueKeep, credential attacks
- 3306/5432/1433 (Databases): Data exfiltration
- 21 (FTP): Anonymous access, credential theft
- 161 (SNMP): Community string exposure

### Medium Exposure (Score 4.0-6.9)
- 8080/8443 (Alt HTTP/S): Dev/staging environments
- 25 (SMTP): Open relay, spoofing
- 53 (DNS): Zone transfer, cache poisoning
- 8888 (Various): Development panels

### Low Exposure (Score 2.0-3.9)
- 80 (HTTP): Standard web
- 443 (HTTPS): Standard secure web

### References

- OWASP Attack Surface Analysis: https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html
- OWASP ASM Top 10: https://owasp.org/www-project-attack-surface-management-top-10/
- ProjectDiscovery ASM blog: https://blog.projectdiscovery.io/asm-platform-using-projectdiscovery-tools/
- Shodan API documentation: https://developer.shodan.io/api
- Censys API documentation: https://search.censys.io/api
- subfinder GitHub: https://github.com/projectdiscovery/subfinder
- nuclei GitHub: https://github.com/projectdiscovery/nuclei
