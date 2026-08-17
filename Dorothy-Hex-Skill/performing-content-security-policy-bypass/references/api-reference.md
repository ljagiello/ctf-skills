# API Reference: Content Security Policy (CSP) Bypass Testing

## Libraries Used

| Library | Purpose |
|---------|---------|
| `requests` | Fetch target page headers and HTML content |
| `re` | Parse CSP directives and detect bypass patterns |
| `json` | Structure findings and report output |
| `urllib.parse` | Parse and analyze allowed CSP source domains |

## Installation

```bash
pip install requests
```

## CSP Directive Reference

| Directive | Controls |
|-----------|----------|
| `default-src` | Fallback for all resource types |
| `script-src` | JavaScript execution sources |
| `style-src` | CSS stylesheet sources |
| `img-src` | Image sources |
| `connect-src` | XMLHttpRequest, fetch, WebSocket |
| `font-src` | Font file sources |
| `object-src` | Plugin sources (Flash, Java) |
| `frame-src` | iframe embedding sources |
| `base-uri` | Controls `<base>` tag URLs |
| `form-action` | Controls form submission targets |
| `frame-ancestors` | Controls who can embed this page |
| `report-uri` | CSP violation report endpoint |

## Core Operations

### Fetch and Parse CSP Header
```python
import requests
import re

def get_csp(url):
    resp = requests.get(url, timeout=10)
    csp = resp.headers.get("Content-Security-Policy", "")
    csp_ro = resp.headers.get("Content-Security-Policy-Report-Only", "")
    return {
        "url": url,
        "csp": csp,
        "csp_report_only": csp_ro,
        "has_csp": bool(csp),
        "directives": parse_csp(csp) if csp else {},
    }

def parse_csp(csp_string):
    directives = {}
    for directive in csp_string.split(";"):
        parts = directive.strip().split()
        if parts:
            name = parts[0].lower()
            values = parts[1:] if len(parts) > 1 else []
            directives[name] = values
    return directives
```

### Analyze CSP for Weaknesses
```python
BYPASS_PATTERNS = {
    "'unsafe-inline'": "Allows inline scripts — XSS bypass",
    "'unsafe-eval'": "Allows eval() — code injection bypass",
    "data:": "Allows data: URIs — can inject inline content",
    "blob:": "Allows blob: URIs — can create executable blobs",
    "*": "Wildcard source — no effective restriction",
    "http:": "Allows HTTP — mixed content / MITM bypass",
}

JSONP_ENDPOINTS = [
    "accounts.google.com", "ajax.googleapis.com",
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
    "*.githubusercontent.com", "raw.githubusercontent.com",
]

def analyze_csp(directives):
    findings = []

    # Check for missing critical directives
    if "default-src" not in directives and "script-src" not in directives:
        findings.append({
            "directive": "script-src",
            "issue": "No script-src or default-src — scripts unrestricted",
            "severity": "critical",
        })

    if "object-src" not in directives:
        findings.append({
            "directive": "object-src",
            "issue": "Missing object-src — plugin-based XSS possible",
            "severity": "high",
        })

    if "base-uri" not in directives:
        findings.append({
            "directive": "base-uri",
            "issue": "Missing base-uri — base tag injection possible",
            "severity": "medium",
        })

    # Check each directive for bypass patterns
    for directive, values in directives.items():
        for value in values:
            if value in BYPASS_PATTERNS:
                findings.append({
                    "directive": directive,
                    "value": value,
                    "issue": BYPASS_PATTERNS[value],
                    "severity": "high" if value in ("'unsafe-inline'", "'unsafe-eval'", "*") else "medium",
                })

            # Check for JSONP-hosting CDNs
            for jsonp_host in JSONP_ENDPOINTS:
                if jsonp_host in value or value.endswith(jsonp_host):
                    findings.append({
                        "directive": directive,
                        "value": value,
                        "issue": f"Allows {jsonp_host} — JSONP/script gadget bypass possible",
                        "severity": "high",
                    })

    return findings
```

### Check for Nonce/Hash Based CSP
```python
def check_nonce_hash(directives, html_content):
    script_src = directives.get("script-src", [])

    nonces = [v for v in script_src if v.startswith("'nonce-")]
    hashes = [v for v in script_src if v.startswith("'sha256-") or v.startswith("'sha384-")]

    findings = []
    if nonces:
        # Check if nonce is reused (static)
        nonce_value = nonces[0].strip("'").replace("nonce-", "")
        if len(nonce_value) < 16:
            findings.append({
                "issue": "Nonce is too short — may be predictable",
                "severity": "medium",
            })

    if not nonces and not hashes and "'strict-dynamic'" not in script_src:
        if "'unsafe-inline'" not in script_src:
            findings.append({
                "issue": "No nonce, hash, or strict-dynamic — consider adding",
                "severity": "info",
            })

    return {"nonces": len(nonces), "hashes": len(hashes), "findings": findings}
```

### Generate Bypass Payloads
```python
def suggest_bypasses(directives):
    """Suggest CSP bypass techniques based on the policy."""
    bypasses = []
    script_src = directives.get("script-src", directives.get("default-src", []))

    if "'unsafe-inline'" in script_src:
        bypasses.append({
            "technique": "Inline script injection",
            "payload": "<script>alert(document.domain)</script>",
        })

    if "'unsafe-eval'" in script_src:
        bypasses.append({
            "technique": "eval() injection",
            "payload": "<img src=x onerror=\"eval(atob('YWxlcnQoMSk='))\">",
        })

    if any("googleapis.com" in v for v in script_src):
        bypasses.append({
            "technique": "Google JSONP callback",
            "payload": "<script src='https://accounts.google.com/o/oauth2/revoke?callback=alert(1)'></script>",
        })

    if "data:" in script_src:
        bypasses.append({
            "technique": "Data URI script",
            "payload": "<script src='data:text/javascript,alert(1)'></script>",
        })

    return bypasses
```

## Output Format

```json
{
  "url": "https://example.com",
  "has_csp": true,
  "directives_count": 8,
  "findings": [
    {
      "directive": "script-src",
      "value": "'unsafe-inline'",
      "issue": "Allows inline scripts — XSS bypass",
      "severity": "high"
    }
  ],
  "bypass_techniques": 2,
  "overall_rating": "weak"
}
```
