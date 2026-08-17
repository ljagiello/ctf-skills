# Essential Skills - Resources and References

External links and reading list for web application security testing.

---

## Burp Suite / PortSwigger

- Web Security Academy: https://portswigger.net/web-security
- Essential Skills: https://portswigger.net/web-security/essential-skills (encoding, targeted scanning)
- Burp Scanner docs: https://portswigger.net/burp/documentation/scanner
- Collaborator: https://portswigger.net/burp/documentation/collaborator
- Repeater: https://portswigger.net/burp/documentation/desktop/tools/repeater
- Decoder: https://portswigger.net/burp/documentation/desktop/tools/decoder
- Research blog: https://portswigger.net/research

**Recommended BApps** (https://portswigger.net/bappstore):
- Active Scan++ — extra checks, edge cases, encoding bypass
- Param Miner — hidden params, cache poisoning, header fuzzing
- Turbo Intruder — high-speed attacks, race conditions
- HTTP Request Smuggler — smuggling detection and exploitation

---

## Related Vulnerability References (within repo)

- XXE: [xxe-quickstart](../../injection/reference/xxe-quickstart.md), [xxe-cheat-sheet](../../injection/reference/xxe-cheat-sheet.md)
- XSS: [client-side scenarios/xss/](../../client-side/reference/scenarios/xss/), [xss-bypass-techniques](../../client-side/reference/xss-bypass-techniques.md)
- SQLi: [sql-injection-quickstart](../../injection/reference/sql-injection-quickstart.md), [sql-injection-advanced](../../injection/reference/sql-injection-advanced.md)
- Path traversal: [server-side INDEX](../../server-side/reference/INDEX.md) → `scenarios/path-traversal/`
- OS command injection: [os-command-injection-cheat-sheet](../../injection/reference/os-command-injection-cheat-sheet.md)
- Authentication: [authentication-quickstart](../../authentication/reference/authentication-quickstart.md)
- Access control / IDOR: [web-app-logic INDEX](../../web-app-logic/reference/INDEX.md) → `scenarios/access-control/`

---

## OWASP

- Testing Guide (WSTG): https://owasp.org/www-project-web-security-testing-guide/
- Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- Top 10 (2021): https://owasp.org/www-project-top-ten/

**Key WSTG sections**: INPV-01 reflected XSS, INPV-02 stored XSS, INPV-05 SQLi, INPV-06 LDAP, INPV-07 XML, INPV-12 command injection.

**Key cheat sheets**: XSS Prevention, SQLi Prevention, OS Command Injection Defense, XXE Prevention.

**Top 10 highlights**: A01 Broken Access Control (IDOR, privesc), A03 Injection (SQLi/XSS/XXE/cmd), A05 Misconfiguration, A07 Auth Failures.

---

## Standards

- NIST SP 800-53 (security controls): https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- NIST SP 800-63B (digital identity): https://pages.nist.gov/800-63-3/sp800-63b.html
- CWE: https://cwe.mitre.org/ — 79 (XSS), 89 (SQLi), 78 (cmd inj), 611 (XXE), 22 (traversal), 284 (access ctrl), 287 (authn), 200 (info exposure)
- CAPEC: https://capec.mitre.org/ — 66, 86, 88, 221, 126
- MITRE ATT&CK: https://attack.mitre.org/ — T1190, T1059, T1189, T1078

---

## Books

- *The Web Application Hacker's Handbook* (2nd ed) — Stuttard & Pinto
- *Real-World Bug Hunting* — Yaworski
- *Web Security Testing Cookbook* — Hope & Walther
- *SQL Injection Attacks and Defense* (2nd ed) — Clarke
- *XSS Attacks: Cross Site Scripting Exploits and Defense* — Fogie et al.
- *The Hacker Playbook 3* — Kim
- *Penetration Testing: A Hands-On Introduction to Hacking* — Weidman

---

## Training Platforms

- Web Security Academy (free, BSCP path): https://portswigger.net/web-security
- TryHackMe: https://tryhackme.com/
- PentesterLab: https://pentesterlab.com/
- OverTheWire Natas: https://overthewire.org/wargames/natas/
- HackerOne Hacker101 (free): https://www.hacker101.com/
- Bugcrowd University: https://www.bugcrowd.com/resources/

---

## Bug Bounty Platforms

- HackerOne: https://www.hackerone.com/
- Bugcrowd: https://www.bugcrowd.com/
- Synack: https://www.synack.com/
- Intigriti: https://www.intigriti.com/
- YesWeHack: https://www.yeswehack.com/

---

## Tools

**Proxies**: Burp Suite Community / Pro (https://portswigger.net/burp), OWASP ZAP (https://www.zaproxy.org/), Caido (https://caido.io/), mitmproxy (https://mitmproxy.org/).

**Scanners**: Nikto (https://cirt.net/Nikto2), Nuclei (https://nuclei.projectdiscovery.io/), Wapiti (https://wapiti-scanner.github.io/).

**Encoding**: CyberChef (https://gchq.github.io/CyberChef/), Burp Decoder.

```bash
# Quick CLI encoding
python3 -c "import urllib.parse; print(urllib.parse.quote('payload'))"
echo -n "payload" | base64
echo -n "payload" | xxd -p
```

---

## Certifications

- BSCP (Burp Suite Certified Practitioner): https://portswigger.net/web-security/certification — practitioner-level lab proficiency, encoding bypass mastery
- OSWE (Offensive Security Web Expert): https://www.offensive-security.com/awae-oswe/ — source review + custom exploit dev
- GWAPT (GIAC Web Application Pen Tester): https://www.giac.org/certification/web-application-penetration-tester-gwapt
- CEH: https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/

---

## Community

**YouTube**: PortSwigger TV, STÖK, IppSec, The Cyber Mentor.
**Researchers (X/Twitter)**: @PortSwigger, @albinowax (James Kettle), @garethheyes, @insertScript, @stokfredrik, @nahamsec, @zseano.
**Orgs**: @OWASP, @hackerone, @Bugcrowd, @synack.
**Blogs**: PortSwigger Research (https://portswigger.net/research), Google Project Zero (https://googleprojectzero.blogspot.com/), OWASP Blog (https://owasp.org/blog/).
**Reddit**: r/AskNetsec, r/websecurity, r/netsec, r/bugbounty.
**Newsletters**: tl;dr sec (https://tldrsec.com/), SANS NewsBites (https://www.sans.org/newsletters/newsbites/), The Daily Swig (https://portswigger.net/daily-swig), The Hacker News (https://thehackernews.com/).
**Podcasts**: Darknet Diaries, Security Now, Critical Thinking (Bug Bounty Podcast), Hacker Valley Studio.

---

## Secure Coding (per language/framework)

- PHP: https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html
- Python/Django: https://docs.djangoproject.com/en/stable/topics/security/
- Flask: https://flask.palletsprojects.com/en/stable/security/
- Node/Express: https://expressjs.com/en/advanced/best-practice-security.html
- Java/Spring: https://docs.spring.io/spring-security/reference/index.html
- Ruby on Rails: https://guides.rubyonrails.org/security.html
- Laravel: https://laravel.com/docs/security
- Brakeman (Rails SAST): https://brakemanscanner.org/

---

## Practice Routine (Essential Skills)

- **Week 1**: targeted scanning across vuln labs under time constraint
- **Week 2**: non-standard data structures (`scan selected insertion point`)
- **Week 3**: encoding bypasses (URL/HTML/XML/double) on filtered targets
- **Week 4**: combined workflows — targeted scan + encoding + non-standard structures

**Self-check**: identify non-standard data structures fast; URL/HTML/XML/Unicode encoding fluency; pick targeted vs full scan; complete practitioner labs in &lt;20 min.

---

## Career Tracks

- Bug bounty: VDP → public programs → invitation-only / Synack
- Pentesting: Junior PT → PT → Senior PT / Lead Consultant / App Sec Architect / Red Team
- Freelance / consulting: web pentest, code review, training, BB program management

---

## Within This Skill

- [Quick Start](./essential-skills-quickstart.md)
- [Cheat Sheet](./essential-skills-cheat-sheet.md)
- [Index](./essential-skills-index.md)
