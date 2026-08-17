# API Reference: PCI DSS Compliance Control Audit

## Libraries Used

| Library | Purpose |
|---------|---------|
| `requests` | API calls to scan engines and cloud services |
| `jinja2` | Generate compliance assessment reports |
| `json` | Parse control status and evidence data |
| `subprocess` | Run network segmentation and encryption checks |
| `csv` | Export compliance matrices |

## Installation

```bash
pip install requests jinja2
```

## PCI DSS v4.0 Requirements Map

| Requirement | Title | Automated Checks |
|-------------|-------|-----------------|
| 1 | Install and maintain network security controls | Firewall rules, segmentation testing |
| 2 | Apply secure configurations | Default credential scan, hardening baselines |
| 3 | Protect stored account data | Encryption at rest, key management |
| 4 | Protect cardholder data with strong cryptography during transmission | TLS version, cipher suites |
| 5 | Protect all systems against malware | AV status, EDR coverage |
| 6 | Develop and maintain secure systems | Vulnerability scans, SAST/DAST |
| 7 | Restrict access by business need to know | RBAC review, access logs |
| 8 | Identify users and authenticate access | MFA status, password policy |
| 9 | Restrict physical access to cardholder data | Physical access logs |
| 10 | Log and monitor all access | Log aggregation, SIEM alerts |
| 11 | Test security of systems regularly | Penetration tests, IDS/IPS |
| 12 | Support information security with policies | Policy review dates |

## Core Compliance Checks

### Requirement 2: Default Credentials Check
```python
import requests

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("root", "root"),
    ("admin", ""), ("user", "user"), ("test", "test"),
]

def check_default_credentials(target_url):
    findings = []
    for username, password in DEFAULT_CREDS:
        try:
            resp = requests.post(
                f"{target_url}/login",
                data={"username": username, "password": password},
                timeout=10,
                allow_redirects=False,
            )
            if resp.status_code in (200, 302):
                findings.append({
                    "target": target_url,
                    "username": username,
                    "requirement": "2.2.2",
                    "severity": "critical",
                })
        except requests.RequestException:
            pass
    return findings
```

### Requirement 4: TLS Configuration Check
```python
import ssl
import socket

def check_tls_config(hostname, port=443):
    findings = []
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            protocol = ssock.version()
            cipher = ssock.cipher()
            cert = ssock.getpeercert()

            # Check TLS version (must be 1.2+)
            if protocol in ("TLSv1", "TLSv1.1"):
                findings.append({
                    "check": "tls_version",
                    "requirement": "4.2.1",
                    "severity": "high",
                    "detail": f"Weak TLS version: {protocol}",
                })

            # Check cipher strength
            if cipher and cipher[2] < 128:
                findings.append({
                    "check": "cipher_strength",
                    "requirement": "4.2.1",
                    "severity": "high",
                    "detail": f"Weak cipher: {cipher[0]} ({cipher[2]} bits)",
                })

    return {"protocol": protocol, "cipher": cipher[0], "findings": findings}
```

### Requirement 8: MFA and Password Policy
```python
def check_password_policy(identity_provider_url, headers):
    resp = requests.get(
        f"{identity_provider_url}/api/v1/policies/password",
        headers=headers,
        timeout=30,
    )
    policy = resp.json()

    findings = []
    if policy.get("minLength", 0) < 12:
        findings.append({
            "check": "password_length",
            "requirement": "8.3.6",
            "severity": "medium",
            "detail": f"Min password length {policy['minLength']} < 12",
        })
    if not policy.get("requireUppercase"):
        findings.append({
            "check": "password_complexity",
            "requirement": "8.3.6",
            "severity": "low",
            "detail": "Uppercase not required",
        })
    return findings
```

### Requirement 10: Log Monitoring Check
```python
def check_logging_coverage(siem_url, siem_headers):
    """Verify all CDE systems forward logs to SIEM."""
    resp = requests.get(
        f"{siem_url}/api/sources",
        headers=siem_headers,
        timeout=30,
    )
    active_sources = resp.json().get("sources", [])
    return {
        "total_sources": len(active_sources),
        "requirement": "10.2",
        "active": [s for s in active_sources if s.get("status") == "active"],
        "inactive": [s for s in active_sources if s.get("status") != "active"],
    }
```

### Generate Compliance Report
```python
from jinja2 import Template

REPORT_TEMPLATE = """
# PCI DSS v4.0 Compliance Assessment

Generated: {{ timestamp }}
Scope: {{ scope }}

## Summary
- Total Controls: {{ total }}
- Compliant: {{ compliant }}
- Non-Compliant: {{ non_compliant }}
- Compliance Rate: {{ rate }}%

## Findings
{% for finding in findings %}
### {{ finding.requirement }} — {{ finding.check }}
- **Severity**: {{ finding.severity }}
- **Detail**: {{ finding.detail }}
{% endfor %}
"""

def generate_report(findings, scope, timestamp):
    compliant = sum(1 for f in findings if not f.get("findings"))
    template = Template(REPORT_TEMPLATE)
    return template.render(
        timestamp=timestamp,
        scope=scope,
        total=len(findings),
        compliant=compliant,
        non_compliant=len(findings) - compliant,
        rate=round(compliant / len(findings) * 100, 1),
        findings=[f for f in findings if f.get("findings")],
    )
```

## Output Format

```json
{
  "assessment_date": "2025-01-15",
  "pci_dss_version": "4.0",
  "scope": "Cardholder Data Environment",
  "total_requirements": 12,
  "compliant": 9,
  "non_compliant": 3,
  "findings": [
    {
      "requirement": "4.2.1",
      "check": "tls_version",
      "severity": "high",
      "detail": "Payment gateway using TLSv1.1",
      "remediation": "Upgrade to TLS 1.2 or higher"
    }
  ]
}
```
