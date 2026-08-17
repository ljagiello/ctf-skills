---
name: essential-tools
description: Core pentesting tools and methodology - Burp Suite usage, Playwright automation, binary analysis, testing methodology, and professional reporting standards.
---

# Essential Tools

Core tools, methodology, and reporting standards for penetration testing.

## Components

| Component | Purpose |
|-----------|---------|
| **Burp Suite** | Proxy, scanner, intruder, repeater, sequencer |
| **Playwright** | Browser automation, evidence capture, SPA testing |
| **Binary Analysis** | Static analysis, reverse engineering, string extraction |
| **Nuclei** | Templated exposure & misconfiguration scanning |
| **sslscan** | TLS posture (protocols, ciphers, cert) |
| **Methodology** | PTES, OWASP WSTG, attack prioritization |
| **Reporting** | Professional report templates, PDF generation |

## Reference

- `reference/essential-skills*.md` - Burp Suite techniques and web security testing methodology
- `reference/playwright-automation.md` - Playwright MCP usage for pentesting
- `reference/binary-analysis-quickstart.md` - Static analysis for executable files and reverse engineering
- `reference/web-application-attacks.md` - Web application attack methodology
- `formats/transilience-report-style/pentest-report.md` - Finding quality standards, compliance mapping, and pre-delivery checklist

## Required-at-start tooling (web/API engagements)

Run an availability check before declaring recon complete:

`command -v subfinder nuclei sslscan httpx; curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" | head -c1`

- Subdomain/CT enum: subfinder, certspotter, crt.sh
- TLS posture: sslscan
- Templated exposure: nuclei

If a tool-class is unavailable, record it as an explicit limitation — NEVER declare recon COMPLETE having skipped a whole class. Hand-rolled urllib is not a substitute (see skills/coordination/reference/principles.md 'Real tools before hand-rolled HTTP').
