# Authentication Principles

This file is the entry point for JWT, OAuth, 2FA, and password-attack scenarios. It contains decision logic for picking the right scenario and cross-cutting gotchas. Specific techniques live under `scenarios/<family>/<scenario>.md`. Use `INDEX.md` to pick a scenario by trigger.

## Decision tree

Pick the scenario family from the auth flow / token fingerprint, then read the matching file from INDEX.md.

**JWT / OAuth (token-based):**

| Fingerprint | Family | Where to start |
|---|---|---|
| 3-part token (`header.payload.signature`) | `scenarios/jwt/` | Fingerprint `alg`, then pick |
| 5-part token (JWE) | `scenarios/jwt/jwe-nested-token.md` | Wrap unsigned PlainJWT in JWE |
| `alg: none` accepted | `scenarios/jwt/none-algorithm.md` | Unsigned token variants |
| HS256 with weak secret | `scenarios/jwt/weak-secret-crack.md` | Hashcat `-m 16500` |
| RS256 + public JWKS | `scenarios/jwt/alg-confusion.md` | Forge HS256 with public key |
| OAuth `redirect_uri` weakly validated | `scenarios/oauth/redirect-uri-manipulation.md` | Prefix/traversal/encoding bypass |
| OAuth `state` missing/replayable | `scenarios/oauth/csrf-state.md` | Account-linking CSRF |
| Implicit Flow | `scenarios/oauth/implicit-flow-attacks.md` | Fragment theft / postMessage |
| Dynamic client registration | `scenarios/oauth/ssrf-client-registration.md` | logo_uri to cloud metadata |

**2FA / MFA:**

| Fingerprint | Family | Where to start |
|---|---|---|
| Frontend trusts MFA outcome | `scenarios/2fa/response-manipulation.md` | Flip JSON success field |
| Protected endpoints skip MFA check | `scenarios/2fa/direct-endpoint-access.md` | Direct navigation post-password |
| No rate limit on OTP | `scenarios/2fa/brute-force-otp.md` | Iterate 4/6-digit space |
| OTP code reusable | `scenarios/2fa/code-reuse.md` | Replay valid code |
| Inbox access (IMAP/SMS) | `scenarios/2fa/email-sms-extraction.md` | Auto-poll + auto-verify |

**Password attacks:**

| Fingerprint | Family | Where to start |
|---|---|---|
| Live auth endpoint, no lockout | `scenarios/password-attacks/online-brute-force.md` | Hydra / Medusa |
| Hashes available offline | `scenarios/password-attacks/hash-cracking.md` | Hashcat with right `-m` mode |
| Encrypted file (ZIP/PFX/KDBX) | `scenarios/password-attacks/encrypted-container-cracking.md` | `<format>2john` |
| Foothold on Windows/Linux | `scenarios/password-attacks/credential-dumping.md` | Mimikatz / secretsdump |
| NTLM hash in hand | `scenarios/password-attacks/pass-the-hash.md` | impacket / CME / evil-winrm |
| Many users + lockout policy | `scenarios/password-attacks/password-spraying.md` | 1-3 passwords × many users |
| Active SSH multiplex socket | `scenarios/password-attacks/ssh-controlmaster-hijack.md` | Cred-less pivot |

## Sequencing principles

1. **Decode the token first.** Read header + payload to identify `alg`, `typ`, `kid`, `jku`, `jwk`, custom claims. The attack vector is usually visible in the structure.
2. **Try cheap attacks first.** `alg:none`, signature stripping, weak secrets — minutes of effort. Save expensive attacks (JWE wrapping, certificate forging) for when easier paths fail.
3. **Observe what the verifier validates.** Modify claim, keep signature → 200 means signature is unchecked. Modify alg → 200 means alg is unchecked. Modify kid → reveals key-lookup path.
4. **Read source code if accessible.** Custom JWT verifiers are where most bugs live. Look for `jwt.verify` / `jwt.decode` calls and check the `algorithms` parameter, secret source, and verify flag.
5. **Check OAuth provider's discovery doc.** `/.well-known/openid-configuration` reveals JWKS URL, supported algorithms, registration endpoint, supported scopes, supported response_types — every endpoint to attack.
6. **CSRF-test before PKCE-test.** Missing `state` is more common than missing PKCE, and a CSRF-vulnerable flow is broken regardless of PKCE.
7. **Combine techniques.** Weak-secret-crack alone isn't useful unless you also tamper claims. JKU SSRF alone gets cloud metadata only if the response is observable.
8. **Test JWE format specifically.** A 5-part token is a JWE — different attack class. Wrapping unsigned PlainJWT inside JWE is a specific bypass that works on layered-crypto failures.

## Cross-cutting gotchas

- **`alg: none` is rejected by default in modern libraries** (PyJWT 2.x, jsonwebtoken 9.x, jjwt 0.10+). Found mostly in legacy code or hand-rolled verifiers.
- **`jwt.decode` ≠ `jwt.verify`.** PyJWT's `decode` accepts `verify=False`; `verify` is the strict path. Code review for `decode(verify=False)` finds many vulnerabilities.
- **Algorithm-key consistency** is enforced by modern libraries — you can't pass an RSA public key with `algorithms=['HS256']`. Older libraries didn't enforce this, enabling RS256→HS256 confusion.
- **`kid` is application-controlled metadata** with no security guarantees. Treating it as a file path / SQL value / shell argument is always a bug.
- **`jwk` / `jku` / `x5u` / `x5c` should NEVER be trusted from token headers** in production. Keys must come from a configured trusted source (JWKS endpoint with TLS pinning, hard-coded cert).
- **Trailing dot vs no trailing dot** in JWT signature segment matters per-library. Test BOTH.
- **OAuth `state` should be HMAC-bound to session** (not just random). Random-but-not-bound states are still vulnerable to replay.
- **PKCE `plain` method = no PKCE.** Treat `code_challenge_method=plain` as PKCE-bypassable.
- **`redirect_uri` MUST exact-match.** Prefix matching, suffix matching, regex — all bypassable. Strict equality (after normalization) is the only safe validation.
- **Refresh token scope expansion** is RFC-prohibited but commonly allowed. Test by requesting elevated scope on refresh.
- **JWE outer encryption ≠ inner signature verification.** Decryption proves the sender knew the public encryption key (which everyone has) — does NOT prove the inner content is signed.
- **Modern OAuth providers default to PKCE-required**, but legacy clients pre-dating PKCE may have it disabled at the client-config level. Check the discovery doc for `code_challenge_methods_supported` AND the actual server behavior.
- **Dynamic Client Registration is rare in production** but common in dev/staging environments. Test the registration endpoint even when the production app doesn't use it.
- **Browser cookie `SameSite=Lax`** allows top-level GET navigation to send session cookies — enabling re-linking CSRF even with Lax. SameSite=Strict is the only safe setting against this.
