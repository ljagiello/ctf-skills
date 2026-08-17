# `offensive-osint` skill

The "what to reach for" operational arsenal for external red-team OSINT and bug-bounty reconnaissance.

| Field | Value |
|---|---|
| Name | `offensive-osint` |
| Version | 2.1 |
| Lines | ~3,800 |
| Top-level sections | 51 |
| Subsections | ~135 |
| Companion skill | [`osint-methodology`](../osint-methodology/) |

## When this skill triggers

Auto-triggers on prompts containing any of ~110 trigger phrases. Common ones:

- All triggers from `osint-methodology` (most prompts pull both)
- `swagger discovery`, `openapi discovery`, `graphql introspection`, `graphql field suggestion`
- `subdomain enumeration`, `subdomain takeover`, `cloud bucket enum`, `S3 enum`, `GCS enum`, `Azure blob enum`
- `okta enum`, `entra enum`, `azure AD enum`, `ADFS enum`, `SAML metadata`
- `mobile recon`, `APK analysis`, `Microsoft 365 deep`, `Teams federation`, `SharePoint enum`, `OneDrive enum`
- `secret scanning`, `secret leak`, `leaked credential`, `JWT triage`, `AWS key triage`
- `github dorking`, `google dorking`, `postman workspace`, `stack exchange OSINT`
- `breach lookup`, `have I been pwned`, `HudsonRock cavalier`, `infostealer`, `dehashed`, `intelx`
- `shodan recon`, `censys recon`, `certificate transparency`, `crt.sh`, `JARM`, `favicon mmh3`
- `JS endpoint extraction`, `sourcemap leak`
- `copy paste probes`, `curl one-liner`
- `email security analysis`, `SPF DMARC DKIM`
- `origin discovery`, `CDN bypass`, `WAF bypass`
- `vendor product fingerprints`, `Citrix Netscaler`, `F5 BIG-IP`, `Pulse Secure`, `FortiGate`, `PaloAlto GlobalProtect`, `Cisco AnyConnect`, `VMware vCenter`
- `cloud native fingerprint`, `Lambda function URL`, `Cloud Run`
- `kubernetes exposure`, `kubelet`, `etcd`
- `CI CD exposure`, `Jenkins recon`, `GitLab self-hosted`, `GitHub Actions secrets`
- `documentation leak`, `Notion public`, `Confluence anonymous`, `Trello board`
- `WHOIS RDAP`, `DNS record catalog`, `Wayback CDX`
- `LinkedIn enumeration`, `job posting tech stack`
- `Slack workspace discovery`, `Discord server discovery`
- `npm token leak`, `PyPI token leak`, `Docker Hub leak`
- `sat imagery physical recon`
- `TLS deep audit`, `JA3 JA4`, `reverse DNS sweep`, `IPv6 enumeration`
- `CVE prioritization`, `EPSS scoring`, `CISA KEV`, `vulnerability prioritization`
- `tooling install`
- `sector specific recon`, `healthcare DICOM`, `finance SWIFT`, `ICS SCADA`, `Modbus`, `BACnet`
- `post discovery workflow`
- `Anthropic API key`, `OpenAI API key`

Full trigger list in the SKILL.md frontmatter.

## What's in it

See the parent [README's "What's in the box" table](../../README.md#whats-in-the-box) for the full §-by-§ breakdown.

Highlights:

- **§16 — Pre-built wordlists & probe paths** including 28 Swagger paths, 13 GraphQL paths + introspection POST body, 35 high-risk ports, 6 missing security headers, 15 always-on HTTP checks, 5 SAML metadata paths, 8 SSO subdomain prefixes, cloud-bucket arsenal (6 prefixes × 15 suffixes × 47 stems × 3 providers), JS guess-paths, endpoint-extraction regex tiers, internal-host leakage regexes, 27 takeover provider fingerprints, copy-paste curl probes, email security analysis, origin discovery / CDN bypass, vendor product fingerprints, cloud-native fingerprints, container/K8s exposure, CI/CD exposure, doc/wiki leak paths, WHOIS/RDAP, DNS catalog with TXT verification token table, Wayback CDX deep usage.
- **§17 — Secret-pattern catalog (48 patterns)** with severity, category, false-positive notes.
- **§18 — Dork corpus (80+ templates, 9 categories)**.
- **§20 — Endpoint interest score (0–100 rubric)**.
- **§21 — Mobile app ownership confidence (0–100 rubric)**.
- **§22 — Identity-fabric concrete endpoints** (incl. M365 Deep + GraphQL field-suggestion enum).
- **§23 — 9 read-only secret validators** + post-discovery enumeration workflows.
- **§39 — 27 attack-path hint templates**.
- **§40 — Severity decision matrix (80+ worked examples)**.
- **§41–§47 — LinkedIn enum, job posting analysis, Slack/Discord discovery, package registry leaks, sat imagery, tooling install, sector notes**.
- **§48 — Runnable secret-scan helper** (stdlib-only Python, available standalone at [`scripts/secret_scan.py`](scripts/secret_scan.py)).

## Loading

```bash
# Local Claude Code install
cp SKILL.md ~/.claude/skills/offensive-osint/SKILL.md
cp scripts/secret_scan.py ~/.claude/skills/offensive-osint/scripts/secret_scan.py

# Or attach to a Claude.ai project / Claude API system prompt
```

The full content lives in this `SKILL.md` (or in `docs/full-skills/offensive-osint.SKILL.full.md` if this file is the structured-outline variant).

## Helper script

[`scripts/secret_scan.py`](scripts/secret_scan.py) — stdlib-only Python scanner mirroring the §17 secret-pattern catalog. Run standalone:

```bash
python3 scripts/secret_scan.py path/to/repo/        # scan a directory tree
python3 scripts/secret_scan.py file1 file2 file3    # scan specific files
cat my.log | python3 scripts/secret_scan.py         # pipe stdin
```

Output: JSONL — one finding per line — `jq`-friendly.

## Self-test

Run the prompts in [`../../tests/smoke-test-prompts.md`](../../tests/smoke-test-prompts.md). Arsenal-targeted prompts are tagged in the test file.

## License

MIT — see [LICENSE](../../LICENSE).
