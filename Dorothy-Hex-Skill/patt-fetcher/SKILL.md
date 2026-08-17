---
name: patt-fetcher
description: Fetches and extracts payloads from PayloadsAllTheThings on demand. Bake into executor prompts for live payload enrichment.
---

# PATT Fetcher

Fetches payloads from PayloadsAllTheThings on demand. Use `model="haiku"` when spawning for lightweight operation.

## URL Map

| Category | Raw URL |
|---|---|
| SQL Injection | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/README.md |
| XSS | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/README.md |
| Command Injection | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/README.md |
| SSTI | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Template%20Injection/README.md |
| XXE | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XXE%20Injection/README.md |
| SSRF | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/README.md |
| Path Traversal | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/README.md |
| File Inclusion | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/README.md |
| LDAP Injection | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/LDAP%20Injection/README.md |
| NoSQL Injection | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/NoSQL%20Injection/README.md |
| Active Directory | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md |
| Linux PrivEsc | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md |
| Windows PrivEsc | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md |
| Reverse Shells | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md |
| Linux Persistence | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Linux%20-%20Persistence.md |
| Windows Persistence | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md |
| Linux Evasion | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Linux%20-%20Evasion.md |
| Windows Evasion | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Windows%20-%20AMSI%20Bypass.md |
| Hash Cracking | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Hash%20Cracking.md |
| Network Pivoting | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Network%20Pivoting%20Techniques.md |
| Mass Assignment | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Mass%20Assignment/README.md |
| Open Redirect | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Open%20Redirect/README.md |
| OAuth Misconfig | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/OAuth%20Misconfiguration/README.md |
| SAML Injection | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SAML%20Injection/README.md |
| CORS Misconfig | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/CORS%20Misconfiguration/README.md |
| Race Condition | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Race%20Condition/README.md |
| Prototype Pollution | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Prototype%20Pollution/README.md |
| Type Juggling | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Type%20Juggling/README.md |
| Deserialization | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Insecure%20Deserialization/README.md |
| GraphQL | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/GraphQL%20Injection/README.md |
| AWS | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Cloud%20-%20AWS%20Pentest.md |
| Azure | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Cloud%20-%20Azure%20Pentest.md |

## Workflow

1. Match category to URL Map (case-insensitive)
2. WebFetch the raw URL
3. Find first H2 heading matching query → return up to 100 lines
4. Return extracted payloads to caller

## Error Handling

- **404**: PATT may have restructured — check https://github.com/swisskyrepo/PayloadsAllTheThings
- **Rate limit**: Back off and retry; if persistent, note the category as unavailable and proceed with built-in payloads
- **Unknown category**: Ask caller for direct raw URL
