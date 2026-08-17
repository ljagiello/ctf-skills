# Secret-Pattern Catalog

> Reference content for the `offensive-osint` skill. Originally §17 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 17. Secret-Pattern Catalog — 48 patterns (29 base + 19 modern)

The catalog runs against any text source: GitHub code, Postman workspaces, JS bodies, sourcesContent blobs, mobile-app strings, Wayback HTML, paste sites, Stack Exchange code blocks. **Order matters: most-specific patterns first** so generic catches don't pre-empt typed ones.

| # | Name | Regex | Severity | Category |
|---|---|---|---|---|
| 1 | AWS Access Key | `\b(AKIA\|ASIA)[0-9A-Z]{16}\b` | **CRITICAL** | aws |
| 2 | AWS Secret Key (typed) | `(?i)aws[_\-]?secret[_\-]?access[_\-]?key['"\s:=]+([A-Za-z0-9/+=]{40})` | **CRITICAL** | aws |
| 3 | AWS Secret (loose) | `(?i)aws(.{0,20})?(secret\|sk)["'=: ]+([0-9a-z/+=]{40})` | HIGH | aws |
| 4 | GCP Service Account JSON | `"type"\s*:\s*"service_account"` | **CRITICAL** | gcp |
| 5 | Google API Key | `\bAIza[0-9A-Za-z_\-]{35}\b` | HIGH | gcp |
| 6 | GitHub Classic PAT | `\bghp_[A-Za-z0-9]{36}\b` | **CRITICAL** | github |
| 7 | GitHub Fine-grained PAT | `\bgithub_pat_[A-Za-z0-9_]{82}\b` | **CRITICAL** | github |
| 8 | GitHub OAuth | `\bgho_[A-Za-z0-9]{36}\b` | HIGH | github |
| 9 | GitHub Server-to-Server | `\bgh[usr]_[A-Za-z0-9]{36,}\b` | HIGH | github |
| 10 | Stripe Live Key | `\bsk_live_[0-9A-Za-z]{24,}\b` | **CRITICAL** | stripe |
| 11 | Stripe Test Key | `\bsk_test_[0-9A-Za-z]{24,}\b` | LOW | stripe |
| 12 | Slack Token | `\bxox[abpors]-[0-9A-Za-z\-]{10,48}\b` | HIGH | slack |
| 13 | Slack Webhook | `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+` | MEDIUM | slack |
| 14 | SendGrid Key | `\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b` | HIGH | email_svc |
| 15 | Mailgun Key (v1) | `\bkey-[0-9a-zA-Z]{32}\b` | HIGH | email_svc |
| 16 | Mailgun Key (loose) | `\bkey-[0-9a-f]{32}\b` | HIGH | email_svc |
| 17 | Twilio API Key | `\bSK[0-9a-fA-F]{32}\b` | HIGH | twilio |
| 18 | Twilio Account SID | `\bAC[a-f0-9]{32}\b` | MEDIUM | twilio |
| 19 | Twilio Auth Token | `(?i)twilio(.{0,20})?(auth\|token)["'=: ]+([a-f0-9]{32})` | HIGH | twilio |
| 20 | Heroku API Key | `(?i)heroku(.{0,20})?api["'=: ]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})` | MEDIUM | paas |
| 21 | Firebase URL | `\bhttps?://[a-z0-9\-]+\.firebaseio\.com\b` | LOW | firebase |
| 22 | JWT (any) | `\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b` | MEDIUM | jwt |
| 23 | Bearer Token Assignment | `(?i)authorization["'=: ]+bearer\s+[A-Za-z0-9._\-]{20,}` | MEDIUM | bearer |
| 24 | Basic Auth in URL | `https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+` | MEDIUM | basic_auth |
| 25 | RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` | **CRITICAL** | private_key |
| 26 | EC Private Key | `-----BEGIN EC PRIVATE KEY-----` | **CRITICAL** | private_key |
| 27 | OpenSSH Private Key | `-----BEGIN OPENSSH PRIVATE KEY-----` | **CRITICAL** | private_key |
| 28 | Generic Private Key | `-----BEGIN (DSA \|PGP \|)PRIVATE KEY-----` | **CRITICAL** | private_key |
| 29 | Generic API Key | `(?i)(?:api[_\-]?key\|apikey\|api_secret\|access_token\|secret[_\-]?token)['"\s:=]+["']([A-Za-z0-9+/=_\-]{24,})["']` | MEDIUM | generic |
| 30 | Anthropic API Key | `\bsk-ant-(?:api03\|admin01)-[A-Za-z0-9_\-]{93,}\b` | **CRITICAL** | ai_api |
| 31 | OpenAI API Key (legacy) | `\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b` | **CRITICAL** | ai_api |
| 32 | OpenAI Project Key | `\bsk-proj-[A-Za-z0-9_\-]{40,}T3BlbkFJ[A-Za-z0-9_\-]{40,}\b` | **CRITICAL** | ai_api |
| 33 | OpenAI User Session | `\bsess-[A-Za-z0-9]{40}\b` | HIGH | ai_api |
| 34 | HuggingFace Token | `\bhf_[A-Za-z0-9]{30,}\b` | HIGH | ai_api |
| 35 | Cloudflare API Token | `\b[A-Za-z0-9_\-]{40}\b` (when paired with `(?i)cloudflare`/`X-Auth-Key` context) | HIGH | infra_api |
| 36 | Cloudflare Global API Key | `(?i)cf[_\-]?api[_\-]?key['"\s:=]+([a-f0-9]{37})` | **CRITICAL** | infra_api |
| 37 | DigitalOcean Token | `\bdop_v1_[a-f0-9]{64}\b` | HIGH | infra_api |
| 38 | npm Token (Modern) | `\bnpm_[A-Za-z0-9]{36}\b` | HIGH | package_registry |
| 39 | PyPI Token | `\bpypi-AgENdGV[A-Za-z0-9_\-]+\b` | HIGH | package_registry |
| 40 | Docker Hub PAT | `\bdckr_pat_[A-Za-z0-9_\-]{27,}\b` | HIGH | package_registry |
| 41 | Atlassian API Token | `\bATATT3xFfGF0[A-Za-z0-9_\-]{180,}\b` | HIGH | saas_api |
| 42 | New Relic License Key | `\b(?:NRAA\|NRAK\|NRBR)-[A-F0-9]{27}\b` | MEDIUM | observability |
| 43 | DataDog API Key (in DD_API_KEY context) | `(?i)dd[_\-]?api[_\-]?key['"\s:=]+([a-f0-9]{32})` | HIGH | observability |
| 44 | Sentry DSN | `https://[a-f0-9]+@o[0-9]+\.ingest\.sentry\.io/[0-9]+` | LOW | observability |
| 45 | ngrok Auth Token | `\b[12][A-Za-z0-9]{26}_[A-Za-z0-9]{32,}\b` (when `(?i)ngrok` context) | MEDIUM | tunneling |
| 46 | Linear API Key | `\blin_api_[A-Za-z0-9]{40}\b` | MEDIUM | saas_api |
| 47 | Discord Bot Token | `\b[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}\b` | HIGH | bot_token |
| 48 | Telegram Bot Token | `\b\d{8,10}:[A-Za-z0-9_\-]{35}\b` | HIGH | bot_token |

**False-positive notes:**
- Patterns 22 (JWT), 23 (Bearer), 29 (Generic) trigger on test/example data frequently. Always look at *context* — a JWT in a `README.md` example block ≠ a JWT in a production `.env` file.
- Pattern 16 (Mailgun loose) and pattern 11 (Stripe test) are noisy by design; severity is set low for that reason.
- Pattern 24 (Basic auth in URL) catches monitoring-tool URLs and CI-debug URLs as well as real creds — verify before alerting.
- For GitHub's Fine-grained PAT (pattern 7), the `82` length is by GitHub's spec — be skeptical of matches significantly longer or shorter.

---

