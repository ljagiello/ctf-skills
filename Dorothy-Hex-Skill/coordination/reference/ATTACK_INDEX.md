# Attack Coverage Matrix

Authoritative inventory of attack classes, sub-techniques, and the skill / scenario file that covers each. Single source of truth for "what is covered." Update on every skill PR.

Format: each row is one applicable technique. `Status` is `covered` (scenario file exists), `referenced` (covered in a `*-patterns.md` or principles file but not yet a scenario), or `gap` (missing — file an issue).

## Web — Injection (`skills/injection/`)

| Sub-technique | Scenario | Status |
|---------------|----------|--------|
| SQL — Auth bypass | `scenarios/sql/auth-bypass.md` | covered |
| SQL — Union-based | `scenarios/sql/union-based.md` | covered |
| SQL — Error-based | `scenarios/sql/error-based.md` | covered |
| SQL — Boolean blind | `scenarios/sql/boolean-blind.md` | covered |
| SQL — Time-based blind | `scenarios/sql/time-based-blind.md` | covered |
| SQL — Stacked queries | `scenarios/sql/stacked-queries.md` | covered |
| SQL — Out-of-band | `scenarios/sql/out-of-band.md` | covered |
| SQL — Second-order | `scenarios/sql/second-order.md` | covered |
| SQL — Header injection | `scenarios/sql/header-injection.md` | covered |
| SQL — WAF bypass | `scenarios/sql/waf-bypass.md` | covered |
| SQL — WHERE-clause filter bypass | `scenarios/sql/where-clause-filter-bypass.md` | covered |
| SQL — DBMS-specific (MySQL / PostgreSQL / MSSQL / Oracle) | `scenarios/sql/per-dbms-*.md` | covered |
| NoSQL — Mongo operator injection | `scenarios/nosql/mongo-operator-injection.md` | covered |
| NoSQL — Mongo syntax injection | `scenarios/nosql/mongo-syntax-injection.md` | covered |
| NoSQL — Mongo type confusion | `scenarios/nosql/mongo-type-confusion.md` | covered |
| NoSQL — Mongo aggregation pipeline | `scenarios/nosql/mongo-aggregation-pipeline.md` | covered |
| NoSQL — Mongo `$where` JS injection | `scenarios/nosql/mongo-where-jsinjection.md` | covered |
| NoSQL — Cassandra CQL | `scenarios/nosql/cassandra-cql.md` | covered |
| NoSQL — Redis SSRF/gopher | `scenarios/nosql/redis-ssrf-gopher.md` | covered |
| OS command injection | `reference/os-command-injection-*.md` | referenced |
| SSTI | `reference/ssti-*.md` | referenced |
| XXE | `reference/xxe-*.md` | referenced |
| LDAP / XPath | `reference/*-resources.md` | gap |

## Web — Client-Side (`skills/client-side/`)

| Sub-technique | Scenario | Status |
|---------------|----------|--------|
| XSS — Cookie theft | `scenarios/xss/cookie-theft.md` | covered |
| XSS — Password capture | `scenarios/xss/password-capture.md` | covered |
| XSS — CSRF chaining | `scenarios/xss/csrf-via-xss.md` | covered |
| XSS — Keylogging | `scenarios/xss/keylogging.md` | covered |
| XSS — Defacement | `scenarios/xss/defacement.md` | covered |
| XSS — BeEF integration | `scenarios/xss/beef-integration.md` | covered |
| XSS — Internal network scan | `scenarios/xss/internal-network-scanning.md` | covered |
| XSS — Session hijacking | `scenarios/xss/session-hijacking.md` | covered |
| XSS — Data exfiltration | `scenarios/xss/data-exfiltration.md` | covered |
| XSS — Phishing via injected UI | `scenarios/xss/phishing-attacks.md` | covered |
| Prototype pollution — Detection | `scenarios/prototype-pollution/detection.md` | covered |
| Prototype pollution — Client-side | `scenarios/prototype-pollution/client-side-pollution.md` | covered |
| Prototype pollution — Server-side | `scenarios/prototype-pollution/server-side-pollution.md` | covered |
| Prototype pollution — Gadget discovery | `scenarios/prototype-pollution/gadget-discovery.md` | covered |
| Prototype pollution — Bypass techniques | `scenarios/prototype-pollution/bypass-techniques.md` | covered |
| DOM — Fundamentals & sinks | `scenarios/dom-vulnerabilities/dom-xss-fundamentals.md` + `*-sink.md` | covered |
| DOM — postMessage | `scenarios/dom-vulnerabilities/postmessage-vulnerabilities.md` | covered |
| DOM — Clobbering (globals + sanitizer bypass) | `scenarios/dom-vulnerabilities/dom-clobbering-*.md` | covered |
| DOM — AngularJS / jQuery sinks | `scenarios/dom-vulnerabilities/{angularjs-injection,jquery-sinks}.md` | covered |
| DOM — WAF/filter bypass | `scenarios/dom-vulnerabilities/waf-filter-bypass.md` | covered |
| CSRF — Generic | `reference/csrf-quickstart.md` | referenced |
| CORS misconfiguration | `reference/cors-cheat-sheet.md` | referenced |
| Clickjacking | `reference/clickjacking-cheat-sheet.md` | referenced |

## Web — Server-Side (`skills/server-side/`)

| Sub-technique | Scenario | Status |
|---------------|----------|--------|
| SSRF — Localhost / IP bypass | `scenarios/ssrf/localhost-and-ip-bypass.md` | covered |
| SSRF — URL parser / allowlist bypass | `scenarios/ssrf/url-parser-and-allowlist-bypass.md` | covered |
| SSRF — Gopher / protocol exploitation | `scenarios/ssrf/protocol-exploitation-gopher.md` | covered |
| SSRF — Cloud metadata | `scenarios/ssrf/cloud-metadata.md` | covered |
| SSRF — Blind detection / portscan | `scenarios/ssrf/blind-detection-and-portscan.md` | covered |
| SSRF — Proxy path traversal | `scenarios/ssrf/proxy-path-traversal.md` | covered |
| HTTP smuggling — CL.TE / TE.CL / TE.TE | `scenarios/http-smuggling/{cl-te,te-cl,te-te-obfuscation}.md` | covered |
| HTTP smuggling — H2 downgrade | `scenarios/http-smuggling/h2-downgrade.md` | covered |
| HTTP smuggling — CL.0 / pause-based | `scenarios/http-smuggling/cl-zero-and-pause-based.md` | covered |
| Path traversal — Encoding & filter bypass | `scenarios/path-traversal/{basic-payloads-and-encoding,filter-bypass-techniques}.md` | covered |
| Path traversal — Target files / platform-specific | `scenarios/path-traversal/{target-files,platform-specific}.md` | covered |
| Path traversal — LFI to RCE | `scenarios/path-traversal/lfi-to-rce.md` | covered |
| File upload — Web-shell payloads | `scenarios/file-upload/web-shell-payloads.md` | covered |
| File upload — Extension / MIME / magic-byte bypass | `scenarios/file-upload/{extension-bypass,content-type-and-magic-bytes}.md` | covered |
| File upload — Polyglots / metadata injection | `scenarios/file-upload/polyglot-and-metadata-injection.md` | covered |
| File upload — Path traversal & .htaccess | `scenarios/file-upload/path-traversal-and-htaccess.md` | covered |
| File upload — Race / YARA defense bypass | `scenarios/file-upload/{race-conditions,defense-evasion-and-yara}.md` | covered |
| Deserialization — PHP / Java / .NET / Python+Ruby | `scenarios/deserialization/{php,java,dotnet,python-and-ruby}-deserialization.md` | covered |
| Host-header — Password reset poisoning | `scenarios/host-header/password-reset-poisoning.md` | covered |
| Host-header — Auth bypass / cache poisoning / SSRF | `scenarios/host-header/{auth-bypass-localhost,cache-poisoning-via-host,routing-ssrf-and-flawed-parsing}.md` | covered |
| Cross-protocol coercion | `reference/protocol-coercion.md` | referenced |

## Web — Authentication (`skills/authentication/`)

| Sub-technique | Scenario | Status |
|---------------|----------|--------|
| JWT — alg confusion (none / RS-to-HS) | `scenarios/jwt/alg-confusion.md`, `scenarios/jwt/none-algorithm.md` | covered |
| JWT — kid path traversal | `scenarios/jwt/kid-path-traversal.md` | covered |
| JWT — JKU / JWK / x5u-x5c injection | `scenarios/jwt/{jku-injection,jwk-injection,x5u-x5c-injection}.md` | covered |
| JWT — Claim tampering / signature stripping | `scenarios/jwt/{claim-tampering,signature-stripping}.md` | covered |
| JWT — Weak secret crack | `scenarios/jwt/weak-secret-crack.md` | covered |
| JWT — JWE nested token | `scenarios/jwt/jwe-nested-token.md` | covered |
| JWT — Psychic signatures (CVE-2022-21449) | `scenarios/jwt/psychic-signatures-cve-2022-21449.md` | covered |
| OAuth — Redirect URI manipulation | `scenarios/oauth/redirect-uri-manipulation.md` | covered |
| OAuth — CSRF / state bypass | `scenarios/oauth/csrf-state.md` | covered |
| OAuth — PKCE downgrade | `scenarios/oauth/pkce-downgrade.md` | covered |
| OAuth — Code theft / postMessage | `scenarios/oauth/code-theft-postmessage.md` | covered |
| OAuth — Implicit-flow attacks | `scenarios/oauth/implicit-flow-attacks.md` | covered |
| OAuth — Scope escalation | `scenarios/oauth/scope-escalation.md` | covered |
| OAuth — SSRF via client registration | `scenarios/oauth/ssrf-client-registration.md` | covered |
| 2FA — Direct endpoint access / backup codes / brute / extraction / leakage / parameter manipulation / predictable / race / response manipulation / pre-2FA session / code reuse | `scenarios/2fa/*.md` (11 files) | covered |
| Password — Online brute / dictionary / spraying / stuffing | `scenarios/password-attacks/{online-brute-force,dictionary-attack,password-spraying,credential-stuffing}.md` | covered |
| Password — Hash cracking / encrypted containers / DB lateral movement | `scenarios/password-attacks/{hash-cracking,encrypted-container-cracking,db-hash-lateral-movement}.md` | covered |
| Password — Pass-the-hash | `scenarios/password-attacks/pass-the-hash.md` | covered |
| Password — Credential dumping / phishing / keylogging / SSH ControlMaster hijack | `scenarios/password-attacks/{credential-dumping,phishing,keylogging,ssh-controlmaster-hijack}.md` | covered |
| CAPTCHA / bot detection bypass | `reference/{CAPTCHA_BYPASS,BOT_DETECTION}.md` | referenced |

## Web — API (`skills/api-security/`)

| Sub-technique | Scenario | Status |
|---------------|----------|--------|
| GraphQL — Endpoint discovery / introspection | `scenarios/graphql/{endpoint-discovery,introspection-and-bypass}.md` | covered |
| GraphQL — IDOR / mass enumeration | `scenarios/graphql/idor-and-mass-enumeration.md` | covered |
| GraphQL — Auth bypass / injection | `scenarios/graphql/auth-bypass-and-injection.md` | covered |
| GraphQL — Rate-limit bypass / DoS+batching / CSRF / schema-reconstruction | `scenarios/graphql/{rate-limit-bypass,dos-and-batching,csrf-and-content-type,schema-reconstruction}.md` | covered |
| REST — Recon / OPTIONS / exposed docs / WAF bypass | `scenarios/rest/{api-recon-and-discovery,options-method-enumeration,exposed-documentation,waf-bypass-techniques}.md` | covered |
| REST — Mass assignment | `scenarios/rest/mass-assignment.md` | covered |
| REST — BOLA / BOPLA | `scenarios/rest/owasp-bola-bopla.md` | covered |
| REST — Server-side parameter pollution | `scenarios/rest/{sspp-query-string,sspp-rest-path}.md` | covered |
| REST — Content-type confusion / XXE | `scenarios/rest/content-type-confusion-xxe.md` | covered |
| WebSocket — Discovery / handshake | `scenarios/websocket/discovery-and-handshake.md` | covered |
| WebSocket — CSWSH / message injection / auth bypass | `scenarios/websocket/{cswsh,message-injection,auth-bypass-and-handshake-tricks}.md` | covered |
| Web LLM — Prompt injection (direct + indirect) | `scenarios/web-llm/{prompt-injection-direct,prompt-injection-indirect}.md` | covered |
| Web LLM — SQLi via LLM, OS-cmd via LLM, insecure-output XSS | `scenarios/web-llm/{sqli-via-llm,os-command-injection-via-llm,insecure-output-xss}.md` | covered |

## Web — Application Logic (`skills/web-app-logic/`)

| Sub-technique | Scenario | Status |
|---------------|----------|--------|
| Access control — IDOR (read + action) | `scenarios/access-control/{idor-read,idor-action}.md` | covered |
| Access control — Mass assignment / parameter / method / header / multi-step / referer / unprotected | `scenarios/access-control/*.md` | covered |
| Access control — Data leakage via redirect | `scenarios/access-control/data-leakage-redirect.md` | covered |
| Business logic — Price / quantity / coupon / gift-card-loop | `scenarios/business-logic/{price-manipulation,quantity-manipulation,coupon-stacking,gift-card-loop}.md` | covered |
| Business logic — Workflow / parameter pollution / regex bypass / CSRF-session / email-domain | `scenarios/business-logic/*.md` | covered |
| Race conditions — Limit-overrun / multi-endpoint / single-endpoint / partial / timestamp / file-upload / rate-limit / TOCTOU | `scenarios/race-conditions/*.md` | covered |
| Cache — Deception (path / delimiter / normalization / via-smuggling) | `scenarios/cache/deception-*.md` | covered |
| Cache — Poisoning (unkeyed headers / unkeyed params) | `scenarios/cache/poisoning-*.md` | covered |
| Info disclosure — Errors / debug pages / JS source / backups / methods / headers / storage / multi-port | `scenarios/info-disclosure/*.md` | covered |

## Network & System

### Active Directory (`skills/system/reference/scenarios/ad/`)
Kerberoast • AS-REP roast • PKINIT • Shadow Credentials • ADCS ESC1 / ESC4 / ESC6 / ESC7 / ESC16 • gMSA • RBCD • Unconstrained / Constrained Delegation • Silver / Golden ticket • DCSync • LDAP simple-bind capture • Certipy LDAP-shell fallback • NTLM relay • Kerberos-only domain • Pre-Windows-2000 access • ACL abuse chains • WSUS MITM • DNS record poisoning • RODC exploitation • LAPS readers • Protected Users bypass • Cross-forest trust • ADFS Golden SAML • Pass-the-hash • Pass-the-ticket (impacket) — **31 scenarios, all covered**.

### Linux privesc (`skills/system/reference/scenarios/linux-privesc/`)
binfmt-misc SUID laundering • info-zip symlink follow • cap_dac_override • sudo-symlink • pycache poisoning • Docker escape • LXD privesc • SUID binary exploitation • snap-confine race • polkit race • PwnKit • Baron Samedit • Credential files hunt • udisks2 polkit • SSH CA forgery • SSH ControlMaster hijack • AppArmor hat bypass • rbash escape • WCF SOAP localhost • buffer overflow — **20 scenarios, all covered**.

### Windows privesc (`skills/system/reference/scenarios/windows-privesc/`)
SeBackupPrivilege • Server Operators ImagePath • AutoAdminLogon • PSReadLine history • Service RequiredPrivileges • Potatoes sanity check • Multi-user flag sweep • IIS log credentials • Memory dump creds • DPAPI browser creds • Writable service binary race • Scheduled task ZIP poll • PrintNightmare • MSI repair TOCTOU • WCF named pipe • File transfer SSH PTY • Forgotten backup ZIP • DLL hijacking • Kernel EOP • Unquoted service path — **20 scenarios, all covered**.

### MSSQL (`skills/system/reference/scenarios/mssql/`)
xp_cmdshell • xp_dirtree NTLM coercion • Linked-server chain • ERRORLOG secrets — **4 scenarios, all covered**.

### Cloud / Containers (`skills/cloud-containers/reference/scenarios/`)
AWS recon + IAM privesc, MinIO, serverless+SaaS • Azure recon+storage • GCP recon+IAM • Docker escape • Kubernetes RBAC — **7 scenarios, covered**. Sub-techniques inside (S3 bucket enum, Lambda perms, Cosmos DB, GKE workload identity, etc.) are referenced inside the scenarios.

### Network infrastructure (`skills/infrastructure/`)
Port scanning • DNS attacks • SMB/NetBIOS • IPv6 • VLAN hopping • MITM • Sniffing • DoS — **referenced** in `reference/*.md`. **Gap:** no `scenarios/` directory yet; W4 follow-up to split.

## Specialized

| Skill | Scenarios? | Notes |
|-------|------------|-------|
| `cryptography` | No `scenarios/` | Reference files cover lattice, AGCD, linear-collapse, padding-oracle, signature forgery, secret-sharing recovery. **Gap:** split into per-technique scenarios. |
| `reverse-engineering` | No `scenarios/` | Reference files cover ELF/PE, custom-VM bytecode, callfuscation, MBA, anti-debug. **Gap:** scenario split. |
| `mobile-security` | No `scenarios/` | Reference files cover Flutter AOT, IL2CPP. **Gap:** add Frida hooking, root-detection-bypass, iOS Objection scenarios. |
| `ai-threat-testing` | No `scenarios/` | Reference files cover OWASP LLM Top 10. **Gap:** scenario split per LLM01-LLM10. |
| `blockchain-security` | No `scenarios/` | Reference describes reentrancy, integer overflow, delegatecall, signature replay. **Gap:** scenario split. |
| `dfir` | No `scenarios/` | Reference covers PCAP forensics, memory analysis, log analysis, AD attack detection. **Gap:** scenario split. |
| `firewall-review` | No `scenarios/` | 17 vendor-agnostic detectors. Each could become a scenario; currently bundled. **Gap.** |
| `social-engineering` | Yes (11 scenarios) | Phishing, vishing, physical, pretexting — covered. |
| `osint` | No `scenarios/` | Repository recon, secret scanning. **Gap.** |
| `reconnaissance` | No `scenarios/` | Subdomain discovery, port scanning, vhost enumeration, anti-bot bypass. **Gap.** |
| `source-code-scanning` | No `scenarios/` | SAST, dependency CVE scan, secret scan. **Gap.** |
| `essential-tools` | No `scenarios/` | Tooling reference; scenarios may not be the right shape. |

## Gap-fill priorities

Skills with content in `reference/` but missing scenarios — file follow-ups in this order:

1. Mobile security (Android smali / Frida / IL2CPP, iOS Objection / jailbreak)
2. Blockchain (Solidity reentrancy / overflow / delegatecall / signature-replay / front-running / flash-loan)
3. OSINT (git-history, secrets, dorks, wayback, job-postings)
4. Source code scanning (OWASP-Top-10 sinks, dependency-CVE scan, secret patterns)
5. Firewall review (one scenario per detector — 17 total)

## Per-attack file structure

Each `reference/` directory contains: `*-principles.md` (decision tree, ≤150), `INDEX.md` (TOC), `*-patterns.md` (≤200), `scenarios/<category>/<technique>.md` (≤400, self-contained), `*-resources.md` (link list).
