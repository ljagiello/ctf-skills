# SSTI — Resources and References

## OWASP

- **OWASP Top 10:2021 — A03 Injection** — https://owasp.org/Top10/A03_2021-Injection/
- **WSTG SSTI** — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection
- **CWE-1336** — Improper Neutralization of Special Elements Used in a Template Engine.
- **CWE-94** — Code injection.

## Template engine docs

| Language | Engine | URL |
|---|---|---|
| Ruby | ERB | https://ruby-doc.org/stdlib/libdoc/erb/rdoc/ERB.html |
| Python | Jinja2 | https://jinja.palletsprojects.com/ (Sandbox: /sandbox/) |
| Python | Tornado | https://www.tornadoweb.org/en/stable/template.html |
| Python | Django | https://docs.djangoproject.com/en/stable/ref/templates/ |
| Python | Mako | https://www.makotemplates.org/ |
| Java | Freemarker | https://freemarker.apache.org/docs/ref_builtins.html |
| Java | Velocity | https://velocity.apache.org/ |
| Java | Thymeleaf | https://www.thymeleaf.org/doc/articles/standardurlsyntax.html |
| Node.js | Handlebars | https://handlebarsjs.com/installation/security.html |
| Node.js | Pug (Jade) | https://pugjs.org/api/getting-started.html |
| Node.js | EJS | https://ejs.co/ |
| Node.js | Nunjucks | https://mozilla.github.io/nunjucks/ |
| PHP | Twig | https://twig.symfony.com/ |
| PHP | Smarty | https://www.smarty.net/ |
| .NET | Razor | https://learn.microsoft.com/en-us/aspnet/core/mvc/views/razor |

## Notable CVEs

| CVE | Component | Issue |
|---|---|---|
| CVE-2024-22243 | Spring Cloud Function | SpEL injection RCE |
| CVE-2023-46604 | ActiveMQ | OpenWire SSTI-style RCE |
| CVE-2022-22965 | Spring4Shell | Class loader manipulation |
| CVE-2021-26084 | Confluence | OGNL injection |
| CVE-2019-3396 | Confluence | Velocity template injection |
| CVE-2019-9670 | Synacor Zimbra | XML / SSTI chain |
| CVE-2017-9805 | Apache Struts | OGNL injection |
| CVE-2017-5638 | Apache Struts | Content-Type OGNL injection |
| CVE-2016-3088 | Apache ActiveMQ | Velocity SSTI |
| CVE-2015-3269 | Apache Flex | Velocity SSTI |

Always run `python3 tools/nvd-lookup.py <CVE>` for current scoring.

## Tools

- **tplmap** — https://github.com/epinna/tplmap (sqlmap analog for SSTI)
- **SSTImap** — https://github.com/vladko312/SSTImap (modern fork)
- **Burp Suite** — manual probing + collaborator
- **PayloadsAllTheThings / SSTI** — comprehensive payload reference
- **synacktiv/php_filter_chain_generator** — PHP filter chain RCE generator (related; for include-based RCE)

## Detection / Discovery

- **Tplmap** — automated detection per-engine.
- **Burp BCheck** — SSTI signature checks.
- **OWASP ZAP** — built-in SSTI scanner.

## Research / Reading

- **PortSwigger SSTI labs (free)** — https://portswigger.net/web-security/server-side-template-injection
- **"Server-Side Template Injection: RCE for the Modern Web App"** — James Kettle (Black Hat 2015).
- **PayloadsAllTheThings SSTI section** — https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- **HackTricks SSTI** — comprehensive technique catalog.
- **Synacktiv research** — SSTI in real-world apps.
- **Snyk vulnerability database** — SSTI-related CVEs.

## Bug bounty / Lab

- **HackerOne** — Twig/Jinja2 SSTI common in PHP/Python apps.
- **PortSwigger Academy SSTI labs** (free).
- **TryHackMe** — SSTI-specific rooms.
- **PentesterLab Pro** — SSTI exercises.

## Frameworks with SSTI security guidance

- **Flask docs** — Jinja2 sandbox usage.
- **Django docs** — autoescaping behavior.
- **Spring docs** — SpEL evaluation context.
- **Symfony Twig** — sandbox extension.

## Compliance

- **PCI DSS v4.0.1** — input validation requirements (§6.5.1).
- **NIST SP 800-53 SI-10** — input validation control.
- **CWE Top 25** — injection ranks #3.

## Defense reference

- **Sandboxing** — Jinja2 SandboxedEnvironment, Twig SandboxExtension.
- **Logic-less templates** — Mustache (no embedded code).
- **AST-based template safety checks** — block dangerous globals.
- **Run-time policies** — Snyk, Imperva runtime application self-protection.
- **CSP** — limits damage from successful template-execution.

## Key takeaways

1. Identify the template engine (look at HTTP headers, error messages, JS bundles).
2. Use the engine's standard escape probes (`{{7*7}}`, `${7*7}`, `<%=7*7%>`).
3. Each engine has its own RCE primitive; learn the top 5 (Jinja2, Twig, Freemarker, ERB, Velocity).
4. SSTI often chains with file read → RCE via include of poisoned files.
5. Sandboxes (Jinja2 SandboxedEnvironment) can be escaped via `__class__.__mro__` chains.
6. Spring SpEL and Apache OGNL are the high-impact Java equivalents.
7. PHP Twig 1.19 has a famous CVE chain; many CMSes still ship vulnerable.
8. Always test both rendered and reflected output for SSTI.
9. Test ALL parameters — error pages, profile bios, comment templates.
10. Engine fingerprint determines payload — wrong engine = silent failure.
