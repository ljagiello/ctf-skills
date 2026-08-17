# Canarytokens API and Deployment Reference

## Self-hosting (canarytokens-docker)

| Step | Command |
|------|---------|
| Clone | `git clone https://github.com/thinkst/canarytokens-docker` |
| Config (switchboard) | `cp switchboard.env.dist switchboard.env` |
| Config (frontend) | `cp frontend.env.dist frontend.env` |
| Start (HTTP) | `docker compose up -d` |
| Start (Let's Encrypt) | `docker compose -f docker-compose-letsencrypt.yml up -d` |
| Status / logs | `docker compose ps` / `docker compose logs -f frontend` |

### Key environment variables

| Variable | File | Purpose |
|----------|------|---------|
| `CANARY_DOMAINS` | frontend.env | Comma-separated domains for general-purpose tokens |
| `CANARY_NXDOMAINS` | frontend.env | Domains reserved for PDF/DNS tokens |
| `CANARY_PUBLIC_IP` | frontend.env | Public IPv4 of the host |
| `CANARY_PUBLIC_DOMAIN` | switchboard.env | Domain serving the frontend |
| `CANARY_MAILGUN_DOMAIN_NAME` | switchboard.env | Mailgun domain for email alerts |
| `CANARY_MAILGUN_API_KEY` | switchboard.env | Mailgun API key |
| `CANARY_ALERT_EMAIL_FROM_ADDRESS` | switchboard.env | Alert sender address |
| `CANARY_ALERT_EMAIL_FROM_DISPLAY` | switchboard.env | Alert sender display name |
| `CANARY_ALERT_EMAIL_SUBJECT` | switchboard.env | Alert email subject |
| `CANARY_WG_PRIVATE_KEY_SEED` | switchboard.env | Base64 seed for WireGuard tokens (`dd bs=32 count=1 if=/dev/urandom | base64`) |

## Public / frontend HTTP API

### POST /generate
Create a token. Form fields:

| Field | Required | Description |
|-------|----------|-------------|
| `type` | yes | Token type string (see table below) |
| `email` | one of email/webhook | Alert email address |
| `webhook_url` | one of email/webhook | Webhook (Slack/Teams/generic) |
| `memo` | yes | Free-text reminder of where the token is planted |

Response (JSON) includes: `token`, `auth`, `hostname`, `url`, `url_components`; for `aws_keys` it adds `access_key_id` and `secret_access_key`.

### GET /download
Download the artifact for document/credential tokens.

| Param | Description |
|-------|-------------|
| `fmt` | Output format, e.g. `msword`, `aws_keys`, `adobe_pdf` |
| `token` | Token id from /generate |
| `auth` | Auth value from /generate |

### GET /history
View triggers for a token (params `token`, `auth`).

## Token type strings

| `type` | Token | Trigger |
|--------|-------|---------|
| `http` | Web-bug URL | HTTP GET on the URL |
| `dns` | DNS name | DNS resolution of the hostname |
| `aws_keys` | AWS API key | Use of the key against AWS |
| `msword` | MS Word doc | Document opened |
| `adobe_pdf` | PDF doc | Document opened |
| `slack_api` | Slack API token | Use against Slack API |
| `kubeconfig` | Kubernetes config | Use against kube API |
| `azure_id` | Azure login cert | Azure authentication |
| `qr_code` | QR code | Encoded URL requested |
| `web_image` | Image web-bug | Image loaded |
| `log4shell` | Log4j JNDI string | Vulnerable logger evaluates string |
| `cmd` | Sensitive command (Windows) | Command/process executed |
| `cloned_web` | Cloned website | JS detects clone load |
| `sql_server` | SQL Server | DB connection/trigger |

## Active Directory honey credential (PowerShell)

| Action | Command |
|--------|---------|
| Create decoy user | `New-ADUser -Name svc_backup_legacy -AccountPassword (ConvertTo-SecureString 'C0mpl3xDecoy!2026' -AsPlainText -Force) -Enabled $true` |
| Add SPN (Kerberoast bait) | `Set-ADUser svc_backup_legacy -ServicePrincipalNames @{Add="MSSQLSvc/decoy.example.com:1433"}` |
| Alerting | SIEM rule on Event ID 4768/4769/4625 for the decoy SAM account |
