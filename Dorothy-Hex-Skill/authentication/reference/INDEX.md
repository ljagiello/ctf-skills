# Authentication — Scenario Index

Read `authentication-principles.md` first for the decision tree and sequencing principles. This index maps fingerprints to scenario files.

## JWT

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| `alg: none` accepted | `scenarios/jwt/none-algorithm.md` | Unsigned token + case/null/whitespace variants |
| `alg: HS256` with weak secret | `scenarios/jwt/weak-secret-crack.md` | Hashcat `-m 16500 jwt.txt jwt.secrets.list` |
| `alg: RS256` with public JWKS | `scenarios/jwt/alg-confusion.md` | Forge HS256 signed with public key as secret |
| `jwk` header trusted | `scenarios/jwt/jwk-injection.md` | Embed your public key, sign with private |
| `jku` header dereferenced | `scenarios/jwt/jku-injection.md` | Host attacker JWKS, point `jku` at it |
| `kid` → file path / SQL / shell | `scenarios/jwt/kid-path-traversal.md` | Traverse to predictable file, sign with content |
| `x5u` / `x5c` headers trusted | `scenarios/jwt/x5u-x5c-injection.md` | Self-signed cert via `x5c` (embed) or `x5u` (host) |
| Signature not verified | `scenarios/jwt/signature-stripping.md` | Modify payload, keep/strip signature |
| Java ECDSA (specific JVMs) | `scenarios/jwt/psychic-signatures-cve-2022-21449.md` | r=0, s=0 ECDSA signature |
| ECDSA `k` reused across signatures (same `r`) | `scenarios/jwt/ecdsa-nonce-reuse.md` | Recover private key from two JWTs via `k=(z1-z2)/(s1-s2)` |
| Have a forgery primitive | `scenarios/jwt/claim-tampering.md` | Modify sub / role / exp / tenant claims |
| 5-part JWE token | `scenarios/jwt/jwe-nested-token.md` | Wrap unsigned PlainJWT in JWE |

## OAuth

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Weak `redirect_uri` validation | `scenarios/oauth/redirect-uri-manipulation.md` | Prefix/traversal/encoding bypass to attacker URL |
| Missing/weak `state` parameter | `scenarios/oauth/csrf-state.md` | Account-linking CSRF (incl. SameSite=Lax bypass) |
| Implicit Flow (`response_type=token`) | `scenarios/oauth/implicit-flow-attacks.md` | Fragment theft via postMessage / open redirect |
| Open redirect + redirect_uri | `scenarios/oauth/code-theft-postmessage.md` | Chain redirect to leak code/token |
| PKCE optional or `plain` method | `scenarios/oauth/pkce-downgrade.md` | Exchange code without `code_verifier` |
| Scope unenforced at token endpoint | `scenarios/oauth/scope-escalation.md` | Request elevated scope at token request |
| Dynamic client reg + URL fetch | `scenarios/oauth/ssrf-client-registration.md` | logo_uri to cloud metadata / internal services |
| Token + email/user_id sent together | `scenarios/oauth/parameter-manipulation.md` | Keep token, modify identity to impersonate |

## 2FA Bypass

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Frontend trusts MFA result | `scenarios/2fa/response-manipulation.md` | Flip JSON success field at proxy |
| Protected endpoints don't re-check MFA | `scenarios/2fa/direct-endpoint-access.md` | Skip 2FA page, hit `/dashboard` directly |
| OTP param weakly validated | `scenarios/2fa/otp-parameter-manipulation.md` | Empty / null / array / magic value |
| Codes accepted multiple times | `scenarios/2fa/code-reuse.md` | Replay valid OTP across sessions |
| No rate limit on OTP attempts | `scenarios/2fa/brute-force-otp.md` | Iterate 4/6-digit OTP space |
| Predictable OTP generation | `scenarios/2fa/predictable-codes.md` | Recover TOTP secret / weak RNG |
| Pre-2FA sessions still valid | `scenarios/2fa/session-pre-2fa.md` | Replay old session cookie post-2FA-enable |
| Backup codes weak | `scenarios/2fa/backup-codes.md` | Reuse / brute-force / leak backup codes |
| TOCTOU on OTP validation | `scenarios/2fa/race-condition.md` | Parallel-submit same valid OTP |
| OTP visible in side channels | `scenarios/2fa/otp-leakage.md` | Response/log/Referer/SMS preview leak |
| Have inbox access (email/SMS) | `scenarios/2fa/email-sms-extraction.md` | Auto-poll IMAP/Twilio + verify |

## Password Attacks

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Auth endpoint without rate limiting | `scenarios/password-attacks/online-brute-force.md` | Hydra/Medusa/Patator credential brute force |
| Wordlist-friendly target | `scenarios/password-attacks/dictionary-attack.md` | Curated wordlists + rules + custom CeWL |
| Have password hashes | `scenarios/password-attacks/hash-cracking.md` | Hashcat / John with appropriate `-m` mode |
| Have encrypted ZIP/PFX/KDBX/Vault | `scenarios/password-attacks/encrypted-container-cracking.md` | `<format>2john` then crack offline |
| Foothold on Windows/Linux host | `scenarios/password-attacks/credential-dumping.md` | Mimikatz / secretsdump / LaZagne |
| Have NTLM hash | `scenarios/password-attacks/pass-the-hash.md` | impacket / CME / evil-winrm with hash |
| Many users + lockout policy | `scenarios/password-attacks/password-spraying.md` | 1-3 common passwords across many users |
| Have breach corpus | `scenarios/password-attacks/credential-stuffing.md` | Combo lists (`<user>:<pass>`) at target |
| App DB hashes recoverable | `scenarios/password-attacks/db-hash-lateral-movement.md` | Crack DB hashes → reuse on SSH/su |
| Active SSH multiplex socket | `scenarios/password-attacks/ssh-controlmaster-hijack.md` | Cred-less pivot via existing tunnel |
| Engagement allows phishing | `scenarios/password-attacks/phishing.md` | Gophish / Evilginx2 (MFA-bypass) |
| Foothold + interactive user | `scenarios/password-attacks/keylogging.md` | Meterpreter / Get-Keystrokes / pynput |
