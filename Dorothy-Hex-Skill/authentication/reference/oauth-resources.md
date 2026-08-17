# OAuth — Resources and References

## OWASP

- **OAuth 2.0 Cheat Sheet** — https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
- **WSTG OAuth Weaknesses** — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_OAuth_Weaknesses
- **API Security Top 10** — https://owasp.org/www-project-api-security/

Key recommendations: Authorization Code Flow + PKCE for all client types; never Implicit Flow; sender-constrained tokens (mTLS / DPoP); short-lived access + refresh rotation; validate `state` always; exact-match `redirect_uri`.

## Standards & RFCs

| RFC | Topic |
|---|---|
| RFC 6749 | OAuth 2.0 core |
| RFC 6750 | Bearer tokens |
| RFC 7636 | PKCE |
| RFC 7519 | JWT |
| RFC 8252 | Native apps best practices |
| RFC 8628 | Device authorization grant |
| RFC 8705 | mTLS client auth |
| RFC 9126 | Pushed Authorization Requests (PAR) |
| RFC 9449 | DPoP (sender-constrained tokens) |
| OAuth 2.1 draft | https://oauth.net/2.1/ |
| OpenID Connect | https://openid.net/connect/ |
| FAPI 2.0 | https://openid.net/specs/fapi-2_0-security-profile.html |

## Notable CVEs

| CVE | Component | Issue |
|---|---|---|
| CVE-2023-26031 | Apache OpenWhisk | Auth bypass via JWT confusion |
| CVE-2022-39226 | OAuthlib | Authorization code reuse |
| CVE-2022-31813 | Apache mod_proxy | OAuth header smuggling |
| CVE-2021-32785 | Apereo CAS | OAuth 2.0 client_secret check bypass |
| CVE-2021-21290 | Netty | Insecure temp file (token leakage) |
| CVE-2020-15240 | OmniAuth | redirect_uri bypass |
| CVE-2020-7711 | Auth0 | Misconfigured callback |
| CVE-2019-13608 | OpenLDAP | Resource exhaustion via OAuth flow |

Always run `python3 tools/nvd-lookup.py <CVE>` for current scoring.

## Tools

- **Burp Suite + JWT Editor / OAuth extensions**
- **OWASP ZAP** — automated OAuth scanning
- **OAuth.tools** — https://oauth.tools/
- **JWT.io** — token inspection
- **OAuth Debugger** — https://oauthdebugger.com/
- **mitmproxy** — OAuth flow inspection
- **OAuth-Scanner** — automated misconfiguration scanner
- **postman-oauth** — flow testing collections

## Research / Reading

- **"OAuth 2 in Action"** — Justin Richer & Antonio Sanso (Manning).
- **"Mastering OAuth 2.0"** — Charles Bihis.
- **PortSwigger OAuth labs** — https://portswigger.net/web-security/oauth
- **Auth0 blog** — https://auth0.com/blog/
- **Okta developer blog** — https://developer.okta.com/blog/
- **Daniel Fett's OAuth research** — formal verification papers.
- **OAuth Security Workshop** — annual academic conference.

## Implementation reference

| Language | Framework | Library |
|---|---|---|
| Python | Flask | Authlib, Flask-OAuthlib |
| Python | Django | django-oauth-toolkit |
| Node | Express | Passport, openid-client |
| Java | Spring | Spring Security OAuth2 |
| .NET | ASP.NET | IdentityServer, OpenIddict |
| Go | net/http | golang.org/x/oauth2 |

## Bug bounty / Lab

- **HackerOne** — many OAuth-related programs (Slack, GitHub, Microsoft, etc.).
- **Bugcrowd** — OAuth vulnerabilities common in mobile / SaaS programs.
- **PortSwigger Web Security Academy** — free OAuth labs.
- **PentesterLab Pro** — OAuth-specific exercises.

## Provider documentation

- **Google OAuth** — https://developers.google.com/identity/protocols/oauth2
- **Microsoft Identity** — https://learn.microsoft.com/en-us/entra/identity-platform/
- **Auth0 docs** — https://auth0.com/docs
- **Okta docs** — https://developer.okta.com/docs/
- **GitHub OAuth Apps** — https://docs.github.com/en/apps/oauth-apps
- **Slack OAuth** — https://api.slack.com/authentication/oauth-v2

## Compliance

- **PCI DSS v4.0.1** — secure auth requirements (sections 8.x).
- **NIST SP 800-63B** — Digital Identity Guidelines (auth assurance levels).
- **ISO/IEC 27001:2022** — information security control A.5.16 (identity management).
- **HIPAA** — auth controls for healthcare PHI.
- **GDPR** — consent + data processing for OAuth-shared user data.

## Key takeaways

1. Always use Authorization Code + PKCE, even for confidential clients.
2. Validate `state` and bind to session via HMAC.
3. Exact-match `redirect_uri`; never prefix or regex.
4. Short-lived access tokens; refresh-token rotation.
5. Validate scope, audience, issuer at token-introspection time.
6. Never trust client-side parameters paired with tokens.
7. Block private IPs in any URL the server fetches (logo_uri, jwks_uri).
8. Audit dynamic client registration; restrict to authenticated admins.
