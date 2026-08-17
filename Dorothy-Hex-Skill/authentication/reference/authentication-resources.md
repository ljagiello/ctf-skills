# Authentication — Resources and References

## OWASP

- **OWASP Top 10 2021 — A07: Identification and Authentication Failures** — https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Authentication Cheat Sheet** — https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- **Session Management Cheat Sheet** — https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- **Password Storage Cheat Sheet** — https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- **Forgot Password Cheat Sheet** — https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
- **Multifactor Authentication Cheat Sheet** — https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
- **Web Security Testing Guide — Auth (WSTG-ATHN-01..10)** — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/

## Standards

| Spec | Topic |
|---|---|
| NIST SP 800-63B | Digital Identity (auth assurance levels) |
| NIST SP 800-132 | Password-based key derivation |
| ISO/IEC 27001:2022 | Information security controls (A.5.16, A.8.5) |
| PCI DSS v4.0.1 | Auth controls for cardholder data (8.x) |
| FIDO2 / WebAuthn | Passwordless authentication |
| SAML 2.0 | Federated SSO (OASIS standard) |
| OAuth 2.0 / 2.1 | Delegated authorization |
| OpenID Connect | Identity layer on OAuth |

## Notable CVEs

| CVE | Component | Issue |
|---|---|---|
| CVE-2022-21449 | Oracle JDK | ECDSA psychic signatures |
| CVE-2021-23337 | lodash | Prototype pollution → auth bypass |
| CVE-2021-44228 | Log4Shell | RCE via logged credentials |
| CVE-2020-14750 | Oracle WebLogic | Auth bypass |
| CVE-2020-13692 | PostgreSQL JDBC | XML signature bypass |
| CVE-2019-11324 | urllib3 | Cert validation bypass |
| CVE-2018-1000805 | Paramiko | SSH auth bypass |
| CVE-2017-9786 | Spring Security | Privilege escalation |

Always run `python3 tools/nvd-lookup.py <CVE>` for current scoring.

## Tools

**Brute force / credential testing:**
- Hydra — multi-protocol brute-forcer
- Patator — modular brute-forcer with retry logic
- Medusa — parallel brute-forcer
- Ncrack — high-speed network auth cracker

**Password cracking:**
- Hashcat (`-m 16500/16511/16512` for JWT)
- John the Ripper
- HashID — identify hash format
- Hashes.com — online lookup

**Web auth testing:**
- Burp Suite (Intruder, Repeater, Sequencer)
- OWASP ZAP
- ffuf / wfuzz — fast HTTP fuzzers
- jwt_tool — JWT-specific
- Authorize Burp extension — IDOR / authz testing

**MFA / OTP testing:**
- otpauth-tool
- TOTP/HOTP brute-forcers
- 2fa-bypass-poc-collection

**Session management:**
- Cookie Editor (browser)
- EditThisCookie
- Burp Suite session handling rules

## Wordlists

- **rockyou.txt** — generic passwords (14M).
- **SecLists** — comprehensive collection (Discovery/Passwords).
- **CrackStation wordlists** — 1.5B passwords.
- **Have I Been Pwned passwords** — known-leaked passwords.
- **CommonAdminPasswords** — defaults.
- **jwt.secrets.list** — JWT-specific.

## Implementation reference

| Language | Auth library |
|---|---|
| Python | Flask-Login, Django auth, Authlib |
| Node.js | Passport.js, NextAuth, Auth.js |
| Java | Spring Security, Apache Shiro |
| .NET | ASP.NET Identity, IdentityServer |
| Go | gorilla/securecookie, jwt-go |
| Ruby | Devise, Warden |
| PHP | Laravel Sanctum, Symfony Security |

## Bug bounty / Lab

- **HackerOne** — many auth-focused programs.
- **Bugcrowd** — auth vulnerabilities common.
- **PortSwigger Web Security Academy** — free auth labs.
- **PentesterLab Pro** — auth-specific exercises.
- **TryHackMe** — beginner-to-advanced auth rooms.
- **DVWA** — local lab.
- **WebGoat** — OWASP educational platform.

## Books

- **The Web Application Hacker's Handbook** — Stuttard & Pinto.
- **Real-World Bug Hunting** — Peter Yaworski.
- **OAuth 2 in Action** — Richer & Sanso.
- **Identity and Data Security for Web Development** — Sullivan.
- **Modern Authentication with Azure Active Directory** — Pelfrey.

## Research / Reading

- **Kim Zetter's Wired columns** on auth breaches.
- **PortSwigger Research blog** — https://portswigger.net/research
- **Krebs on Security** — incident analysis.
- **Auth0 blog** — https://auth0.com/blog/
- **Okta developer blog** — https://developer.okta.com/blog/
- **Troy Hunt's blog** (HIBP creator).

## Compliance

- **PCI DSS v4.0.1 §8** — auth requirements.
- **NIST SP 800-63B** — digital identity guidelines.
- **HIPAA Security Rule §164.312(d)** — auth controls.
- **GDPR Art. 32** — security of processing.
- **CIS Controls v8.1 — Control 5** — account management.

## Provider documentation

- **Microsoft Identity Platform** — https://learn.microsoft.com/en-us/entra/identity-platform/
- **Google Identity** — https://developers.google.com/identity
- **Auth0** — https://auth0.com/docs
- **Okta** — https://developer.okta.com/docs/
- **AWS Cognito** — https://docs.aws.amazon.com/cognito/

## Key takeaways

1. Use established libraries — never roll your own auth.
2. Argon2id (preferred) / bcrypt for password storage.
3. MFA wherever possible; prefer TOTP / WebAuthn over SMS.
4. Short session lifetimes; secure cookies (httpOnly + Secure + SameSite).
5. Rate-limit auth endpoints; account lockout with backoff.
6. Use OAuth 2.1 / OIDC for federated identity.
7. Validate all auth tokens server-side.
8. Audit account-recovery flows; they bypass primary auth.
9. Monitor for credential stuffing, password spraying.
10. Test auth bypass with WSTG-ATHN methodology.
