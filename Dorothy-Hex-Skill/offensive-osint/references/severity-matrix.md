# Severity Decision Matrix

> Reference content for the `offensive-osint` skill. Originally §40 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 40. Severity Decision Matrix — Worked Examples

When in doubt, anchor on these worked examples (drawn from real engagements):

| Finding | Severity | Why |
|---|---|---|
| `/.git/config` reachable on prod webapp | **CRITICAL** | Full source-code disclosure; secret history reconstructable. |
| `/.env` reachable on prod webapp | **CRITICAL** | Plaintext creds (DB, cloud, API). |
| Open Firebase RTDB returning data | **CRITICAL** | All app data readable; often writable. |
| Listable S3 bucket containing PII | **CRITICAL** | Direct data exfil. |
| Listable S3 bucket containing logs only | HIGH | Internal hostnames + paths in logs; pivot data. |
| Spring Boot `/actuator/env` exposed | **CRITICAL** | DB creds, JWT secrets, cloud keys in env. |
| Spring Boot `/actuator/heapdump` exposed | **CRITICAL** | Heap contains live secrets in string form. |
| Open Elasticsearch (`/_cat/indices` returns) | **CRITICAL** | Full data reads; often writable. |
| Open MongoDB (no auth) | **CRITICAL** | Full data + password-hash collection. |
| Open Redis (no AUTH) | **CRITICAL** | Write `authorized_keys` → SSH foothold. |
| Open Docker API (port 2375) | **CRITICAL** | Container/host takeover. |
| Public PMAK validated live with broad scope | **CRITICAL** | Full Postman account + all team workspaces. |
| Public AWS root access key validated live | **CRITICAL** | Full account compromise. |
| Live AWS IAM-user key found on GitHub | HIGH | Limited scope (depends on IAM policy); often elevatable. |
| Live GitHub PAT found in JS bundle | HIGH | Repo write access (depends on scope). |
| Live Slack token in pastebin | HIGH | Workspace data + history; sometimes channel post. |
| Sourcemap (`.js.map`) accessible on prod | HIGH | Frontend source disclosure. |
| Open GraphQL introspection on prod | HIGH | Full schema → mutations + business-logic discovery. |
| Subdomain takeover possible (Heroku / GitHub Pages / etc.) | HIGH | Takeover → phishing on trusted domain. |
| Reflected CORS with credentials on `/api/billing` | HIGH | CSRF-via-CORS for billing data. |
| Verb tampering: DELETE allowed on documented-GET-only endpoint | HIGH | Authz bypass; potentially destructive. |
| `phpinfo.php` reachable on prod | HIGH | Discloses paths, env vars, modules → vuln-version pivot. |
| Tomcat `/manager/html` reachable | HIGH | Often default creds; WAR upload = RCE. |
| Jenkins script console accessible | HIGH | Groovy script execution = RCE. |
| Missing HSTS on `/login` | HIGH (escalated from MED) | Login pages must enforce HSTS. |
| Missing HSTS on standard pages | MEDIUM | Hardening gap. |
| Missing CSP | MEDIUM | XSS impact mitigation gone. |
| Internal IP / K8s service DNS in JS | MEDIUM | Internal topology disclosure. |
| Apache `/server-status` reachable | MEDIUM | Live request visibility. |
| `android:debuggable=true` on prod app | **CRITICAL** | Production debug-build → full client compromise. |
| `android:allowBackup=true` (no whitelist) | MEDIUM | App data exfil via `adb backup`. |
| `android:usesCleartextTraffic=true` | MEDIUM | MITM-able on hostile networks. |
| Sensitive deep-link handler (`myapp://reset-password`) | HIGH | Other apps can trigger sensitive flows. |
| Exported Android component without permission | MEDIUM | IPC attack surface. |
| Slack webhook URL leaked | MEDIUM | Send to channel; can be used for social-eng. |
| Twilio Account SID leaked (no auth token) | MEDIUM | Half a credential pair; plus account enumeration. |
| Wildcard CORS on data-returning API | MEDIUM | Lower than reflected+creds but still exfil-able. |
| Missing `X-Frame-Options` | LOW | Clickjacking. |
| `.DS_Store` exposed | LOW | Directory listing of dev's machine. |
| Stripe **test** key leaked | LOW | No real money risk. |
| Firebase URL exposed (no open RTDB) | LOW | Project-ID disclosure only. |
| Cert pinning missing in mobile app | LOW | MITM possible on hostile networks. |
| Outdated WordPress install detected | LOW | Pending CVE confirmation. |
| Missing `Referrer-Policy` / `Permissions-Policy` | INFO | Hardening, not an exposure. |
| `/.well-known/security.txt` discovered | INFO | Useful contact info only. |
| Domain in breach with 0 named accounts | INFO | Contextual only. |
| Private bucket exists (HEAD 403) | INFO | Asset only, no finding. |
| Open kubelet on 10250 | **CRITICAL** | Pod exec without K8s API auth. |
| Open etcd on 2379 | **CRITICAL** | Cluster state + secrets. |
| K8s API on 6443 with anonymous-auth | HIGH | Cluster recon; sometimes pod exec. |
| K8s dashboard exposed without auth | HIGH | Cluster admin UI. |
| Helm Tiller (Helm 2) on 44134 | HIGH | Cluster-admin scope. |
| Citrix Netscaler with KEV CVE | **CRITICAL** | Patch immediately; actively exploited. |
| F5 BIG-IP TMUI accessible | HIGH | TMUI = admin panel; CVE-2022-1388 if unpatched = CRIT. |
| Pulse Secure with CVE-2024-21887 | **CRITICAL** | KEV; chained command injection. |
| FortiGate with CVE-2024-21762 | **CRITICAL** | KEV; auth bypass + RCE. |
| PaloAlto GlobalProtect with CVE-2024-3400 | **CRITICAL** | KEV; pre-auth RCE. |
| VMware vCenter with CVE-2021-21972 | **CRITICAL** | KEV; pre-auth RCE. |
| VMware ESXi exposed without VPN | HIGH | Multiple CVEs (ESXiArgs ransomware vector). |
| MS Exchange with ProxyShell/Logon/NotShell unpatched | **CRITICAL** | KEV chain; RCE + mailbox dump. |
| AWS Lambda Function URL accessible anonymously | HIGH | Direct invocation; check IAM auth posture. |
| Public Cloud Run / Cloud Function unauthenticated | HIGH | Same. |
| Public Docker registry (anonymous catalog) | MEDIUM | Image enum + secret hunt in layers. |
| GitHub Actions secrets echoed in workflow logs | HIGH | Secret-in-log = full secret disclosure. |
| GitHub Actions `pull_request_target` checkout of fork code | HIGH | Class of bug; secrets accessible to attacker PRs. |
| GitLab self-hosted with CVE-2021-22205 | **CRITICAL** | KEV; ExifTool RCE. |
| Jenkins with `pull_request_target`-equivalent misconfig | HIGH | Build secrets accessible to PRs. |
| Public Notion page with internal SOPs | MEDIUM | Operational intel; sometimes credentials. |
| Public Trello board with credentials in cards | HIGH | Often plaintext API keys. |
| Public Confluence space with onboarding docs | MEDIUM | Seed creds + tech-stack reveal. |
| Public Miro board with architecture diagrams | LOW | Internal-host disclosure. |
| DMARC policy `p=none` on production sending domain | MEDIUM | Spoof feasible (escalated from LOW for risk surface). |
| SPF `~all` (softfail) without strict DMARC | MEDIUM | Spoofs land in spam, but land. |
| MX server allows open relay (test with 250 OK to RCPT TO foreign domain) | HIGH | Spam + spoof feasibility. |
| Live Anthropic / OpenAI API key with broad scope | **CRITICAL** | Quota cost + potential PII in past responses. |
| Live npm token with `publish` scope | **CRITICAL** | Supply-chain compromise of all maintained packages. |
| Live PyPI / Docker Hub / GHCR token with publish scope | **CRITICAL** | Supply-chain compromise. |
| Atlassian token with admin scope | HIGH | Workspace-wide read; sometimes write. |
| Subdomain takeover candidate confirmed | HIGH | Trusted-domain phishing surface. |
| Sensitive CI/CD wordlist hits (Jenkinsfile, .gitlab-ci.yml on public repo) | MEDIUM | Build-script intel; often references secret names. |
| Public Postman workspace with internal API endpoints | MEDIUM | API attack surface mapped. |
| WAF/CDN trivially bypassable (origin discoverable via §16.15) | HIGH | All WAF protections null. |
| TLS 1.0/1.1 supported on prod | MEDIUM | Compliance gap; PCI-DSS forbids TLS 1.0. |
| RC4 / 3DES cipher accepted | MEDIUM | NOMORE / SWEET32 attacks. |
| Cert about to expire (<30 days) | LOW | Operational risk; not exploitable. |
| Self-signed cert on prod | MEDIUM | Trust failure for users. |
| Heartbleed (CVE-2014-0160) detected | **CRITICAL** | Memory disclosure including session tokens + keys. |
| Public Slack invite link discoverable | HIGH | Anyone joins workspace; full DM/channel access. |
| Vendor / supplier / e-procurement portal publicly exposed + breach corpus shows vendor accounts compromised | **HIGH** | Vendor impersonation + procurement fraud (BEC vector); regulatory exposure if PII/payment data flows. |
| Job-application / careers portal collects PII over plain HTTP (no TLS) | **HIGH** | Cleartext PII at scale; regulatory exposure under GDPR / CCPA / India DPDP Act / LGPD. |
| Decommissioned legacy mail (NXDOMAIN today) + breach corpus has historical employee URLs against it + cloud SSO migration confirmed via autodiscover IPs | **CRITICAL** | Stolen passwords almost certainly survived migration via reuse; SSO_EXPOSURE escalates regardless of the legacy host being dead. |
| Public-facing intranet (`intranet.<domain>` resolves and returns content without VPN) | MEDIUM | Internal-staff portal exposed; often leaks org structure, employee directory, internal apps. |
| Staging / preprod / UAT / sandbox subdomain publicly resolvable | MEDIUM | Often weaker auth, debug endpoints, test creds; sometimes mirrors prod data. |
| `vpn.<domain>` resolves but vendor + version unknown (passive only) | INFO | Attack surface flag only; escalate to HIGH-CRITICAL after active fingerprint matches a KEV CVE (§16.16). |
| DMARC RUA points to a third-party reporting vendor (kdmarc / dmarcian / Valimail / Agari / EasyDMARC) | INFO | Tenant signal only; vendor compromise = DMARC bypass for *all* their customers. |

---

