# Prototype Pollution — Resources

Curated links, tools, CVEs, books. For exploitation see `scenarios/prototype-pollution/`.

## Official documentation

- [PortSwigger: What is Prototype Pollution?](https://portswigger.net/web-security/prototype-pollution)
- [Client-Side PP](https://portswigger.net/web-security/prototype-pollution/client-side)
- [PP via Browser APIs](https://portswigger.net/web-security/prototype-pollution/browser-apis)
- [Server-Side PP](https://portswigger.net/web-security/prototype-pollution/server-side)
- [Preventing PP](https://portswigger.net/web-security/prototype-pollution/preventing)

## OWASP / standards

- [OWASP PP Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html) ([source](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.md))
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Top 10 — A03:2021 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-1321 Improperly Controlled Modification of Object Prototype Attributes](https://cwe.mitre.org/data/definitions/1321.html)
- [CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- [MITRE ATT&CK T1059](https://attack.mitre.org/techniques/T1059/), [T1068](https://attack.mitre.org/techniques/T1068/), [T1190](https://attack.mitre.org/techniques/T1190/)
- [CAPEC-113 Interface Manipulation](https://capec.mitre.org/data/definitions/113.html)
- NIST SP 800-53 (SI-10 input validation, SI-11 error handling, SC-3 isolation)
- PCI DSS Req 6.5.1 (injection), 6.5.7 (XSS), 11.3 (pentest)

## Research papers

- **Dasty: Unveiling the Invisible (2024)** — semi-automated gadget identification via dynamic taint analysis. ACM Web Conf 2024. [arXiv:2311.03919](https://arxiv.org/abs/2311.03919) · [ACM DL](https://dl.acm.org/doi/10.1145/3589334.3645579) · [PDF](https://people.kth.se/~musard/research/pubs/www24.pdf)
- **PP Detection for Node.js: A Review** — survey of static / dynamic / symbolic detection. [ResearchGate](https://www.researchgate.net/publication/382648784) · [Journal](https://matjournals.net/engineering/index.php/JCSPIC/article/view/682)
- **James Kettle — Server-Side PP: Black-box Detection Without the DoS (2022)** — JSON spaces, status code, charset techniques. [PortSwigger Research](https://portswigger.net/research/server-side-prototype-pollution).
- **Doyensec — PP Gadgets Finder (2024)** — automated gadget discovery, Burp BApp. [Blog](https://blog.doyensec.com/2024/02/17/server-side-prototype-pollution-Gadgets-scanner.html).
- HackTricks — [Client-Side PP](https://book.hacktricks.wiki/en/pentesting-web/deserialization/nodejs-proto-prototype-pollution/client-side-prototype-pollution.html).

## Critical CVEs

| CVE | Product | Severity | Notes |
|-----|---------|----------|-------|
| CVE-2025-55182 / CVE-2025-66478 | React Server Components / Next.js | CRITICAL 10.0 | "React2Shell" — RCE via deserialization. 145+ public PoCs within 24h. [Datadog](https://securitylabs.datadoghq.com/articles/cve-2025-55182-react2shell-remote-code-execution-react-server-components/) · [Picus](https://www.picussecurity.com/resource/blog/react-flight-protocol-rce-vulnerability-cve-2025-55182-and-cve-2025-66478-explained) · [OX Security](https://www.ox.security/blog/react2shell-going-granular-a-deep-deep-deep-technical-analysis-of-cve-2025-55182/) · [Praetorian](https://www.praetorian.com/blog/critical-advisory-remote-code-execution-in-next-js-cve-2025-66478-with-working-exploit/) · [Trend Micro](https://www.trendmicro.com/en_us/research/25/l/CVE-2025-55182-analysis-poc-itw.html) · [Akamai](https://www.akamai.com/blog/security-research/cve-2025-55182-react-nextjs-server-functions-deserialization-rce) · [Research repo](https://github.com/ejpir/CVE-2025-55182-research/blob/main/TECHNICAL-ANALYSIS.md) |
| CVE-2024-21505 | web3-utils | HIGH | Part of Shai-Hulud supply-chain attack. [Snyk](https://security.snyk.io/vuln/SNYK-JS-WEB3UTILS-6229337) |
| CVE-2023-3696 | Mongoose < 7.3.4 | HIGH | Document merge → PP → privesc |
| CVE-2021-23343 | path-parse < 1.0.7 | HIGH | Path parsing |
| CVE-2020-7598 | minimist < 1.2.2 | HIGH | CLI argv parsing |
| CVE-2019-11358 | jQuery < 3.4.0 | MEDIUM | `jQuery.extend()` |
| CVE-2019-7609 | Kibana | RCE | Canonical SSPP RCE pattern |

Search resources: [MITRE CVE](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=prototype+pollution) · [NVD](https://nvd.nist.gov/vuln/search/results?query=prototype+pollution) · [Snyk Vulnerability DB](https://security.snyk.io/) · [GitHub Advisories](https://github.com/advisories?query=prototype+pollution).

## Tools

### Burp Suite
- **DOM Invader** (built-in Pro) — [docs](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/prototype-pollution) · [testing workflow](https://portswigger.net/burp/documentation/desktop/testing-workflow/input-validation/prototype-pollution)
- **Server-Side PP Scanner** (BApp Store) — JSON spaces / status / charset / property reflection
- **PP Gadgets Finder** (Doyensec, BApp) — [BApp link](https://portswigger.net/bappstore/fcbc58b33fc1486d9a795dedba2ccbbb)
- **BCheck Server-Side PP** — [example](https://portswigger.net/burp/documentation/scanner/bchecks/worked-examples/server-side-prototype-pollution)

### CLI
- **ppmap** — `npm install -g ppmap`
- **ppfuzz** — fuzzing wrapper around ffuf-style requests
- **proto-find** — static + dynamic finder
- **silent-spring** — Node.js RCE-via-SSPP framework. [GitHub](https://github.com/yuske/silent-spring)
- **pp-finder** — CSPP/SSPP gadget discovery. [GitHub](https://github.com/yeswehack/pp-finder)

### Research tools
- **Dasty** — taint-analysis pipeline ([arXiv:2311.03919](https://arxiv.org/abs/2311.03919))
- **UOPF** — undefined-oriented programming framework for template-engine gadgets
- **DAPP** — npm-module static analyzer

### Browser extensions
- **PPScan** (Chrome / Firefox) — real-time CSPP detection while browsing

### Gadget databases
- **BlackFan/client-side-prototype-pollution** — CSPP gadget collection
- **yuske/server-side-prototype-pollution** — SSPP gadget DB (Node.js, npm)

### OWASP ZAP
- Community scripts for PP active scanning. [zaproxy/community-scripts](https://github.com/zaproxy/community-scripts)

## Training

- **TryHackMe** — JS security, Node.js vulns paths
- **PentesterLab** — JS vuln exercises, web security
- **NodeGoat** — [GitHub](https://github.com/OWASP/NodeGoat) — vulnerable Node app
- **Juice Shop** — [GitHub](https://github.com/juice-shop/juice-shop) — OWASP modern vulnerable app

## Bug bounty

- HackerOne — search "JavaScript" / "Node.js" programs
- Bugcrowd, Intigriti, Synack — same
- Notable: James Kettle's $60k+ from PP findings; React2Shell post-CVE-2025-55182 bounties $10k–$50k+

## Books

- **The Web Application Hacker's Handbook** (2nd ed., Stuttard/Pinto) — JS security chapters
- **Real-World Bug Hunting** (Yaworski, No Starch) — PP case studies
- **Bug Bounty Bootcamp** (Vickie Li, No Starch) — modern web vulns incl. PP
- **Eloquent JavaScript** (Haverbeke) — prototype inheritance fundamentals. [Free online](https://eloquentjavascript.net/)
- **You Don't Know JS: this & Object Prototypes** (Kyle Simpson). [GitHub](https://github.com/getify/You-Dont-Know-JS)

## Defense / WAF rules

### ModSecurity Core Rule Set
[CRS GitHub](https://github.com/coreruleset/coreruleset). Custom rules:
```apache
SecRule REQUEST_BODY "@rx __proto__" "id:1001,phase:2,deny,status:403,msg:'PP attempt'"
SecRule REQUEST_BODY "@rx \"constructor\"" "id:1002,phase:2,deny,status:403,msg:'Constructor pollution'"
```

### Cloudflare / AWS WAF
Managed rules + custom expressions for `__proto__` / `constructor` / `prototype` in body and query.

### SIEM detection
**Splunk:**
```spl
index=web_logs sourcetype=access_combined ("proto" OR "constructor" OR "prototype")
| rex field=_raw "__proto__\[(?<polluted>[^\]]+)\]"
| stats count by polluted, clientip
```

**Elastic:**
```json
{"query":{"bool":{"should":[
  {"match":{"request.body":"__proto__"}},
  {"match":{"request.body":"constructor"}},
  {"match":{"request.query":"__proto__"}}
]}}}
```

## Conferences / talks

- Black Hat — James Kettle on web vulns (2019, 2022, 2025)
- DEF CON — web village, JS security talks
- OWASP AppSec — PP workshops

## Communities

- Reddit: r/netsec, r/websecurity, r/bugbounty, r/javascript
- Stack Exchange: [security.stackexchange.com](https://security.stackexchange.com), [stackoverflow.com/questions/tagged/prototype-pollution](https://stackoverflow.com/questions/tagged/prototype-pollution)
- Twitter: @BurpSuite, @albinowax (James Kettle), @Doyensec, @InsiderPhD, @NahamSec, @stokfredrik
- YouTube: LiveOverflow, IppSec, John Hammond, PwnFunction
