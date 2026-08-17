# API Reference: Brand Impersonation Monitoring

## Libraries Used

| Library | Purpose |
|---------|---------|
| `requests` | HTTP client for CT log, WHOIS, and DNS APIs |
| `dns.resolver` | DNS record lookups for impersonation detection |
| `json` | Parse API responses and certificate data |
| `re` | Pattern matching for brand name variations |
| `datetime` | Track certificate issuance timelines |

## Installation

```bash
pip install requests dnspython
```

## Certificate Transparency Log Monitoring

### Search CT Logs via crt.sh
```python
import requests

def search_ct_logs(domain):
    """Search Certificate Transparency logs for domain certificates."""
    resp = requests.get(
        "https://crt.sh/",
        params={"q": f"%.{domain}", "output": "json"},
        timeout=30,
    )
    resp.raise_for_status()
    certs = resp.json()
    return [
        {
            "id": c["id"],
            "common_name": c["common_name"],
            "issuer": c["issuer_name"],
            "not_before": c["not_before"],
            "not_after": c["not_after"],
        }
        for c in certs
    ]
```

### Detect Suspicious Look-alike Domains
```python
import re

def generate_typosquat_variants(domain):
    """Generate common typosquatting variants of a domain."""
    name, tld = domain.rsplit(".", 1)
    variants = set()

    # Character substitution (homoglyphs)
    homoglyphs = {"a": ["@", "4"], "e": ["3"], "i": ["1", "l"], "o": ["0"], "s": ["5", "$"]}
    for i, char in enumerate(name):
        for replacement in homoglyphs.get(char, []):
            variants.add(name[:i] + replacement + name[i+1:] + "." + tld)

    # Missing/extra characters
    for i in range(len(name)):
        variants.add(name[:i] + name[i+1:] + "." + tld)  # Omission
        variants.add(name[:i] + name[i] + name[i] + name[i+1:] + "." + tld)  # Repetition

    # Adjacent TLDs
    for alt_tld in ["com", "net", "org", "io", "co", "app", "dev"]:
        if alt_tld != tld:
            variants.add(name + "." + alt_tld)

    # Hyphen insertion
    for i in range(1, len(name)):
        variants.add(name[:i] + "-" + name[i:] + "." + tld)

    return variants
```

### Check Domain Registration
```python
def check_domain_whois(domain):
    """Check WHOIS data for a suspicious domain."""
    resp = requests.get(
        f"https://rdap.org/domain/{domain}",
        timeout=10,
    )
    if resp.status_code == 200:
        data = resp.json()
        return {
            "domain": domain,
            "registered": True,
            "registrar": data.get("entities", [{}])[0].get("vcardArray", [None, []])[1][0]
                if data.get("entities") else "Unknown",
            "events": data.get("events", []),
        }
    return {"domain": domain, "registered": False}
```

### DNS Record Check
```python
import dns.resolver

def check_dns_records(domain):
    """Check if a suspicious domain has active DNS records."""
    records = {}
    for rtype in ["A", "MX", "NS", "TXT"]:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            records[rtype] = []
    return {
        "domain": domain,
        "has_a_record": len(records.get("A", [])) > 0,
        "has_mx_record": len(records.get("MX", [])) > 0,
        "records": records,
    }
```

### Monitor for Brand Mentions
```python
def scan_for_impersonation(brand_domain, ct_results):
    """Identify certificates that may indicate impersonation."""
    suspicious = []
    for cert in ct_results:
        cn = cert["common_name"].lower()
        if brand_domain not in cn:
            continue
        # Flag if issued by free CA (common for phishing)
        if any(ca in cert["issuer"].lower() for ca in ["let's encrypt", "zerossl", "buypass"]):
            suspicious.append({
                **cert,
                "reason": "Brand name in cert from free CA",
                "risk": "high",
            })
    return suspicious
```

## Output Format

```json
{
  "brand": "example.com",
  "scan_date": "2025-01-15",
  "ct_certificates_found": 342,
  "suspicious_certificates": 5,
  "typosquat_domains_registered": 8,
  "findings": [
    {
      "domain": "examp1e.com",
      "type": "typosquat",
      "registered": true,
      "has_mx_record": true,
      "risk": "high",
      "detail": "Active mail server — possible phishing"
    }
  ]
}
```
