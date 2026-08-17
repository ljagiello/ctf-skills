# API Reference: Vulnerability SLA Breach Alerting

## Libraries Used

| Library | Purpose |
|---------|---------|
| `requests` | Slack webhook and Jira API integration |
| `smtplib` | Send email alerts for SLA breaches |
| `json` | Parse vulnerability and SLA data |
| `datetime` | Calculate SLA deadlines and breach timing |
| `email.mime.text` | Compose HTML email notifications |

## Installation

```bash
pip install requests
```

## Alert Channels

### Slack Webhook Alert
```python
import requests
import os

SLACK_WEBHOOK = os.environ["SLACK_WEBHOOK_URL"]

def send_slack_alert(breaches):
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "SLA Breach Alert"}
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{len(breaches)} vulnerabilities have breached SLA*",
            }
        },
    ]
    for breach in breaches[:10]:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*{breach['cve']}* — {breach['severity'].upper()}\n"
                    f"Host: `{breach['host']}` | Overdue: {breach['hours_overdue']}h\n"
                    f"Owner: {breach.get('owner', 'Unassigned')}"
                ),
            }
        })

    resp = requests.post(
        SLACK_WEBHOOK,
        json={"blocks": blocks},
        timeout=10,
    )
    return resp.status_code == 200
```

### Email Alert (SMTP)
```python
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email_alert(breaches, recipients):
    smtp_host = os.environ["SMTP_HOST"]
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ["SMTP_USER"]
    smtp_pass = os.environ["SMTP_PASS"]

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"SLA Breach: {len(breaches)} vulnerabilities overdue"
    msg["From"] = smtp_user
    msg["To"] = ", ".join(recipients)

    html = "<h2>SLA Breach Report</h2><table border='1'>"
    html += "<tr><th>CVE</th><th>Severity</th><th>Host</th><th>Hours Overdue</th></tr>"
    for b in breaches:
        html += f"<tr><td>{b['cve']}</td><td>{b['severity']}</td>"
        html += f"<td>{b['host']}</td><td>{b['hours_overdue']}</td></tr>"
    html += "</table>"

    msg.attach(MIMEText(html, "html"))

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_user, recipients, msg.as_string())
```

### Jira Ticket Creation
```python
JIRA_URL = os.environ["JIRA_URL"]
JIRA_AUTH = (os.environ["JIRA_USER"], os.environ["JIRA_TOKEN"])

def create_jira_ticket(breach):
    ticket = {
        "fields": {
            "project": {"key": os.environ.get("JIRA_PROJECT", "VULN")},
            "summary": f"SLA Breach: {breach['cve']} on {breach['host']}",
            "description": (
                f"Vulnerability {breach['cve']} ({breach['severity']}) "
                f"has breached its remediation SLA.\n\n"
                f"Host: {breach['host']}\n"
                f"Hours overdue: {breach['hours_overdue']}\n"
                f"Discovery date: {breach['discovery_date']}\n"
                f"SLA deadline: {breach['deadline']}\n\n"
                f"Required action: Remediate immediately."
            ),
            "issuetype": {"name": "Bug"},
            "priority": {"name": "Highest" if breach["severity"] == "critical" else "High"},
            "labels": ["sla-breach", "security", breach["severity"]],
        }
    }
    resp = requests.post(
        f"{JIRA_URL}/rest/api/2/issue",
        auth=JIRA_AUTH,
        json=ticket,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["key"]
```

## SLA Breach Detection

```python
from datetime import datetime, timedelta

SLA_TIERS = {
    "critical": timedelta(hours=24),
    "high": timedelta(hours=72),
    "medium": timedelta(days=30),
    "low": timedelta(days=90),
}

def detect_breaches(vulnerabilities):
    breaches = []
    now = datetime.now()
    for vuln in vulnerabilities:
        if vuln.get("remediated"):
            continue
        discovery = datetime.fromisoformat(vuln["discovery_date"])
        sla = SLA_TIERS.get(vuln["severity"].lower(), timedelta(days=90))
        deadline = discovery + sla
        if now > deadline:
            breaches.append({
                **vuln,
                "deadline": deadline.isoformat(),
                "hours_overdue": round((now - deadline).total_seconds() / 3600, 1),
            })
    return sorted(breaches, key=lambda b: b["hours_overdue"], reverse=True)
```

## Orchestration

```python
def run_sla_breach_alerting(vulnerabilities):
    breaches = detect_breaches(vulnerabilities)
    if not breaches:
        return {"breaches": 0, "alerts_sent": False}

    # Send alerts through all channels
    send_slack_alert(breaches)
    send_email_alert(breaches, os.environ.get("ALERT_RECIPIENTS", "").split(","))

    # Create Jira tickets for critical/high breaches only
    for breach in breaches:
        if breach["severity"] in ("critical", "high"):
            create_jira_ticket(breach)

    return {"breaches": len(breaches), "alerts_sent": True}
```

## Output Format

```json
{
  "run_time": "2025-01-15T10:00:00Z",
  "breaches_detected": 5,
  "alerts": {
    "slack": true,
    "email": true,
    "jira_tickets_created": 3
  },
  "breaches": [
    {
      "cve": "CVE-2024-21887",
      "severity": "critical",
      "host": "web-prod-01",
      "hours_overdue": 48.5,
      "deadline": "2025-01-13T10:00:00",
      "owner": "platform-team"
    }
  ]
}
```
