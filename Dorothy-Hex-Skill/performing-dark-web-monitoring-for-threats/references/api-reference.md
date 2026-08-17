# API Reference: Dark Web Threat Monitoring

## Libraries Used

| Library | Purpose |
|---------|---------|
| `requests` | HTTP client for Tor-proxied requests and clearnet APIs |
| `json` | Parse breach data and monitoring results |
| `re` | Pattern matching for credentials and brand mentions |
| `hashlib` | Hash credentials for safe lookup (k-anonymity) |
| `datetime` | Track monitoring timelines |

## Installation

```bash
pip install requests

# Tor service (required for .onion access)
# Ubuntu/Debian
sudo apt install tor
sudo systemctl start tor

# macOS
brew install tor && brew services start tor
```

## Authentication and Proxy Configuration

### Tor SOCKS5 Proxy Setup
```python
import requests
import os

TOR_PROXY = os.environ.get("TOR_PROXY", "socks5h://127.0.0.1:9050")
proxies = {"http": TOR_PROXY, "https": TOR_PROXY}

def tor_request(url, timeout=30):
    """Make an HTTP request through the Tor network."""
    resp = requests.get(url, proxies=proxies, timeout=timeout)
    return resp
```

### Verify Tor Connectivity
```python
def check_tor_connection():
    try:
        resp = requests.get(
            "https://check.torproject.org/api/ip",
            proxies=proxies,
            timeout=15,
        )
        data = resp.json()
        return {"tor_active": data.get("IsTor", False), "exit_ip": data.get("IP")}
    except requests.RequestException as e:
        return {"tor_active": False, "error": str(e)}
```

## Credential Breach Monitoring

### Have I Been Pwned API (k-Anonymity)
```python
import hashlib

HIBP_API = "https://api.pwnedpasswords.com/range/"

def check_password_breach(password):
    """Check if a password appears in known breaches using k-anonymity."""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    resp = requests.get(f"{HIBP_API}{prefix}", timeout=10)
    resp.raise_for_status()

    for line in resp.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return {"breached": True, "count": int(count)}
    return {"breached": False, "count": 0}
```

### Check Email in Breaches
```python
HIBP_ACCOUNT_API = "https://haveibeenpwned.com/api/v3/breachedaccount/"

def check_email_breaches(email, api_key):
    """Check if an email appears in known data breaches."""
    resp = requests.get(
        f"{HIBP_ACCOUNT_API}{email}",
        headers={
            "hibp-api-key": api_key,
            "user-agent": "SecurityAuditTool",
        },
        params={"truncateResponse": "false"},
        timeout=15,
    )
    if resp.status_code == 200:
        breaches = resp.json()
        return {
            "email": email,
            "breached": True,
            "breach_count": len(breaches),
            "breaches": [
                {
                    "name": b["Name"],
                    "date": b["BreachDate"],
                    "data_classes": b["DataClasses"],
                }
                for b in breaches
            ],
        }
    elif resp.status_code == 404:
        return {"email": email, "breached": False, "breach_count": 0}
    return {"email": email, "error": resp.status_code}
```

## Brand Mention Monitoring

### Search Paste Sites
```python
def search_paste_sites(brand_keywords, api_key=None):
    """Search paste monitoring services for brand mentions."""
    findings = []
    for keyword in brand_keywords:
        # IntelligenceX API (example)
        resp = requests.get(
            "https://2.intelx.io/intelligent/search",
            headers={"x-key": api_key} if api_key else {},
            params={
                "term": keyword,
                "buckets": "pastes",
                "maxresults": 20,
                "datefrom": "",
                "dateto": "",
                "sort": 2,  # Date descending
            },
            timeout=30,
        )
        if resp.status_code == 200:
            results = resp.json().get("records", [])
            for r in results:
                findings.append({
                    "keyword": keyword,
                    "source": r.get("systemid"),
                    "date": r.get("date"),
                    "bucket": r.get("bucket"),
                })
    return findings
```

## Domain Monitoring

### Monitor for Credential Dumps Mentioning Domain
```python
def monitor_domain_mentions(domain, sources):
    """Search for domain mentions across dark web sources."""
    findings = []
    email_pattern = re.compile(rf"[\w.+-]+@{re.escape(domain)}", re.IGNORECASE)

    for source in sources:
        try:
            resp = tor_request(source["url"], timeout=30)
            matches = email_pattern.findall(resp.text)
            if matches:
                findings.append({
                    "source": source["name"],
                    "emails_found": len(set(matches)),
                    "sample": list(set(matches))[:5],
                    "risk": "high",
                })
        except requests.RequestException:
            continue
    return findings
```

## Alerting

```python
def create_alert(finding, severity="high"):
    return {
        "alert_type": "dark_web_mention",
        "severity": severity,
        "source": finding.get("source"),
        "detail": finding,
        "timestamp": datetime.now().isoformat(),
        "action_required": "Investigate and rotate exposed credentials",
    }
```

## Output Format

```json
{
  "monitoring_date": "2025-01-15",
  "domain": "example.com",
  "tor_connected": true,
  "credential_breaches": {
    "emails_checked": 50,
    "breached_accounts": 8,
    "unique_breaches": 12
  },
  "paste_mentions": 3,
  "dark_web_findings": [
    {
      "source": "paste-site",
      "type": "credential_dump",
      "emails_found": 15,
      "risk": "high",
      "action": "Force password reset for affected accounts"
    }
  ]
}
```
