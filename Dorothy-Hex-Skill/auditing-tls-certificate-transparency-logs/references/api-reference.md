# API Reference: CT Log Monitoring Agent

## Overview

Monitors Certificate Transparency logs via the crt.sh API to detect unauthorized certificate issuance, discover subdomains, detect typosquat phishing infrastructure, and alert security teams. Stores state in SQLite for baseline comparison across monitoring cycles.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP requests to crt.sh API and webhook delivery |
| cryptography | >=41.0 | Certificate parsing and validation (optional advanced features) |
| pyOpenSSL | >=23.0 | X.509 certificate chain inspection (optional advanced features) |

The core monitoring functionality requires only `requests`. The `cryptography` and `pyOpenSSL` packages are needed for direct certificate parsing beyond what the crt.sh JSON API provides.

## CLI Usage

```bash
# One-shot scan with report
python agent.py --domains example.com --db ct_monitor.db --report report.json

# Continuous monitoring with Slack alerts
python agent.py --domains example.com --continuous --interval 900 \
    --webhook https://hooks.slack.com/services/XXX/YYY/ZZZ

# Build baseline and auto-detect authorized CAs
python agent.py --domains example.com --auto-baseline --db ct_monitor.db

# Monitor multiple domains with email alerts
python agent.py --domains example.com bank.example.com \
    --continuous --interval 600 \
    --smtp-host smtp.gmail.com --smtp-port 587 \
    --smtp-user alerts@example.com --smtp-pass "app-password" \
    --email-to security@example.com soc@example.com

# Scan for typosquat phishing domains
python agent.py --domains example.com --typosquats --report typosquat_report.json

# Manually add an authorized CA
python agent.py --domains example.com --add-ca "DigiCert SHA2 Extended Validation Server CA" 1397
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--domains` | Yes | Space-separated list of domains to monitor |
| `--db` | No | SQLite database path (default: `ct_monitor.db`) |
| `--report` | No | Output JSON report to specified path |
| `--timeout` | No | HTTP request timeout in seconds (default: 30) |
| `--continuous` | No | Run continuous monitoring loop |
| `--interval` | No | Monitoring interval in seconds (default: 900) |
| `--resolve-dns` | No | Resolve discovered subdomains via DNS (default: true) |
| `--no-resolve-dns` | No | Disable DNS resolution of subdomains |
| `--typosquats` | No | Enable typosquat domain scanning (slow, rate-limited) |
| `--webhook` | No | Webhook URL for alert notifications (Slack, Teams) |
| `--auto-baseline` | No | Auto-populate authorized CAs from current certificates |
| `--add-ca` | No | Manually add authorized CA: name and crt.sh CA ID |
| `--smtp-host` | No | SMTP server hostname for email alerts |
| `--smtp-port` | No | SMTP port (default: 587) |
| `--smtp-user` | No | SMTP authentication username |
| `--smtp-pass` | No | SMTP authentication password |
| `--email-from` | No | Alert email sender address |
| `--email-to` | No | Alert email recipient address(es) |
| `-v, --verbose` | No | Enable debug logging |

## Key Functions

### `query_crtsh(domain, exclude_expired, timeout)`
Queries the crt.sh JSON API with wildcard domain patterns. Implements retry with exponential backoff on rate limiting (HTTP 429). Returns list of certificate records.

### `store_certificates(conn, certs, monitored_domain)`
Stores certificates in SQLite, deduplicating by crt.sh ID. Returns only newly discovered certificates for alerting.

### `discover_subdomains(conn, certs, parent_domain)`
Extracts unique subdomains from certificate SAN/name_value fields. Handles wildcard entries by recording the parent domain.

### `resolve_subdomain(subdomain, timeout)`
Performs DNS A/AAAA and CNAME resolution for a single subdomain with configurable timeout.

### `check_unauthorized_ca(conn, new_certs)`
Compares certificate issuers against the authorized CA list. Generates critical alerts for unknown CAs.

### `check_new_subdomain_alerts(conn, new_subdomains, parent_domain)`
Generates medium-severity alerts for previously unseen subdomains discovered in CT data.

### `check_wildcard_certs(conn, new_certs)`
Alerts on new wildcard certificate issuances which have broader security impact.

### `check_short_lived_certs(conn, new_certs, threshold_hours)`
Detects certificates with unusually short validity periods that may indicate automated phishing infrastructure.

### `check_expiring_certs(conn, domain, days_warning)`
Checks for certificates approaching expiration at configurable warning thresholds (30, 14, 7 days).

### `generate_typosquat_candidates(domain)`
Generates domain permutations using omission, transposition, keyboard-adjacent replacement, and bitsquatting techniques.

### `scan_typosquats(domain, timeout)`
Queries CT logs for certificates issued to typosquat variations of the monitored domain.

### `send_email_alert(alerts, smtp_host, ...)`
Delivers alert notifications via SMTP with both plaintext and HTML formatting.

### `send_webhook_alert(alerts, webhook_url, timeout)`
Posts alert notifications to a webhook endpoint (Slack, Teams, generic).

### `generate_report(conn, domain, output_path)`
Produces a comprehensive JSON report including certificate inventory, issuer breakdown, subdomain list, and recent alerts.

### `run_monitor_cycle(conn, domains, ...)`
Executes a complete monitoring cycle: query crt.sh, store certificates, discover subdomains, run alert checks, and deliver notifications.

## Database Schema

| Table | Purpose |
|-------|---------|
| `certificates` | All certificates seen in CT logs with issuer, validity, and SAN data |
| `subdomains` | Unique subdomains discovered from certificate name_value fields |
| `authorized_cas` | Whitelist of authorized Certificate Authorities for alert comparison |
| `alerts` | Generated alerts with type, severity, and acknowledgment status |

## Alert Types

| Alert Type | Severity | Trigger |
|------------|----------|---------|
| `unauthorized_ca` | Critical | Certificate issued by CA not in authorized list |
| `new_subdomain` | Medium | Previously unseen subdomain in CT data |
| `wildcard_certificate` | High | New wildcard certificate issuance |
| `short_lived_certificate` | High | Certificate validity under threshold (default 24h) |
| `certificate_expiring` | Medium/High | Certificate approaching expiration |
| `typosquat_detected` | High | CT certificate found for typosquat domain variation |
