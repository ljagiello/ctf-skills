# JWT — Resources and References

## OWASP

- **OWASP JWT Cheat Sheet (Java)** — https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
- **OWASP API Security Top 10** — https://owasp.org/www-project-api-security/
- **OWASP Authentication Cheat Sheet** — https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

Key recommendations: never `decode()` without `verify()`; explicit `algorithms=` allowlist; reject `alg:none`; short expiration + refresh tokens; HTTPS-only; no tokens in localStorage; httpOnly + Secure + SameSite cookies; rotate signing keys.

## Standards

| RFC | Topic |
|---|---|
| RFC 7515 | JSON Web Signature (JWS) |
| RFC 7516 | JSON Web Encryption (JWE) |
| RFC 7517 | JSON Web Key (JWK) |
| RFC 7518 | JSON Web Algorithms (JWA) |
| RFC 7519 | JSON Web Token (JWT) |
| RFC 8725 | JWT Best Current Practices |
| RFC 8392 | CBOR Web Token (CWT) |

## Notable CVEs

| CVE | Component | Issue |
|---|---|---|
| CVE-2022-21449 | Oracle JDK ECDSA | Psychic signatures (r=0,s=0) |
| CVE-2022-23529 | jsonwebtoken | Verify with malicious key type |
| CVE-2018-1000531 | Auth0 jwks-rsa | RegEx ReDoS |
| CVE-2020-26271 | jose | Algorithm confusion |
| CVE-2020-15693 | Nim httpauth | Signature stripping |
| CVE-2019-7644 | Auth0-jwt | None algorithm acceptance |
| CVE-2019-11792 | python-jose | Key confusion |
| CVE-2018-15133 | Laravel | Signing-key prediction |
| CVE-2017-12865 | jsonwebtoken | RS256→HS256 confusion |
| CVE-2015-9235 | jsonwebtoken | Algorithm confusion |

Always run `python3 tools/nvd-lookup.py <CVE>` for current scoring.

## Tools

- **jwt_tool** — https://github.com/ticarpi/jwt_tool (Swiss army knife)
- **JWT.io** — https://jwt.io/ (decode/verify in browser)
- **Burp Suite JWT Editor extension**
- **Hashcat** — `-m 16500/16511/16512` for HS-* cracking
- **John the Ripper** — `--format=HMAC-SHA256`
- **JWTear** — JWT parsing & exploitation
- **JWTcat** — JWT cracker
- **jwks-converter** — JWK ↔ PEM conversion

## Wordlists

- **jwt.secrets.list** — JWT-specific secret wordlist (rockyou-style for JWTs).
- **SecLists** — Discovery/JWT/jwt.secrets.list.
- **rockyou.txt** — generic password wordlist; covers many weak JWT secrets.

## Implementation reference

| Language | Library | Notes |
|---|---|---|
| Python | PyJWT 2.x | Modern, enforces alg/key consistency |
| Python | python-jose | Supports JWE; pre-2.0 had alg confusion |
| Node.js | jsonwebtoken 9.x | Modern; reject none by default |
| Node.js | jose | JWE + JWS; modern best-practices |
| Java | JJWT 0.10+ | Modern; explicit algorithm parsing |
| Java | nimbus-jose-jwt | JWE + JWS; widely used |
| Go | golang-jwt/jwt | Verify needs explicit alg method |
| .NET | System.IdentityModel.Tokens.Jwt | Microsoft official |
| Ruby | ruby-jwt | Modern with explicit algorithms |
| PHP | firebase/php-jwt | Modern; uses key/alg pairs |

## Research / Reading

- **Critical vulnerabilities in JSON Web Token libraries** — Tim McLean (2015 original alg-confusion writeup).
- **JWT attacks (2023)** — PortSwigger Research.
- **Hacking JSON Web Token (JWT)** — Auth0 blog.
- **Common JWT security vulnerabilities** — Snyk blog series.
- **PortSwigger Web Security Academy — JWT** — https://portswigger.net/web-security/jwt
- **JWT Handbook** — Auth0 free book.

## Frameworks

- **Spring Security** — JwtDecoder / JwtAuthenticationFilter.
- **Express** — express-jwt + jsonwebtoken.
- **Django REST framework** — djangorestframework-simplejwt.
- **ASP.NET Core** — Microsoft.AspNetCore.Authentication.JwtBearer.
- **FastAPI** — python-jose-based dependencies.

## Lab / Practice

- **PortSwigger JWT labs** (free).
- **JWT.io decoder** (sandbox testing).
- **TryHackMe** — JWT room.
- **PentesterLab** — JWT exercises.

## Training

- **Web Security Academy** — JWT path.
- **OffSec OSWE** — JWT exploitation in source-review context.
- **PEN-300** — bug bounty methodology.

## Compliance

- **PCI DSS v4.0.1** — auth controls for cardholder data.
- **NIST SP 800-63B** — token-based authentication.
- **ISO/IEC 27001:2022 A.5.16** — identity management.
- **HIPAA** — auth controls for PHI.
- **FedRAMP** — JWT requirements for cloud services.

## Key takeaways

1. Always `verify()`, never `decode()` for production validation.
2. Explicit algorithm allowlist (e.g. `algorithms=["RS256"]`); reject `none`.
3. Symmetric secrets ≥ 256 bits, generated cryptographically.
4. Public keys come from a configured trusted source (JWKS endpoint with TLS); never trust `jwk` / `jku` / `x5u` / `x5c` in token headers.
5. Validate `exp`, `nbf`, `iat`, `iss`, `aud` always.
6. Short expiration + refresh tokens with rotation.
7. Token storage: httpOnly Secure SameSite cookies; never localStorage.
8. Treat `kid` as untrusted — never use directly in file paths / SQL / shell.
9. Test JWE-wrapped tokens for inner-layer signature bypass.
10. Audit dependencies; CVEs in JWT libraries are common.
