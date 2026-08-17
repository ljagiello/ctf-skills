# 2FA — Direct Endpoint Access (Skip the Challenge Page)

## When this applies

- The 2FA challenge is enforced ONLY by the routing layer (e.g. middleware on `/2fa/verify`) and not by the protected endpoints themselves.
- Sessions are established at the password step BEFORE 2FA verification — leaving a window where the cookie has no MFA flag but the protected endpoints don't check for one.

## Technique

Authenticate with username/password (which sets a session cookie). Then skip the 2FA challenge page entirely and navigate directly to a protected resource (`/dashboard`, `/api/user`, `/admin`). If the protected endpoint trusts the session without re-checking MFA state, you've bypassed 2FA.

## Steps

### 1. Login and capture session cookie

```bash
curl -i -c cookies.txt -X POST https://target.com/login \
  -d 'username=test&password=test123'
```

Response sets `Set-Cookie: session=...; HttpOnly`. The user is now password-authenticated but MFA is pending.

### 2. Navigate directly to protected resource

```bash
curl -b cookies.txt https://target.com/dashboard
curl -b cookies.txt https://target.com/api/user
curl -b cookies.txt https://target.com/admin
```

If the protected resource returns 200 with user data, MFA enforcement is missing on that endpoint.

### 3. Use Playwright for SPA targets

```javascript
await page.fill('#username', 'test');
await page.fill('#password', 'test123');
await page.click('button[type="submit"]');

// Skip 2FA page
await page.goto('https://target.com/dashboard');
const snapshot = await page.screenshot();
```

### 4. Try multiple protected endpoints

Some endpoints may enforce MFA, others not. Test:
- `/dashboard`
- `/profile`
- `/account/settings`
- `/api/user/me`
- `/api/orders`
- `/admin`
- `/api/admin/*`

### 5. Test API direct access

GraphQL / REST APIs are particularly prone to this — the API may trust the session set at login without checking the user's MFA status.

```bash
curl -b cookies.txt -X POST https://target.com/api/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ me { email } }"}'
```

### 6. Test mobile app endpoints

Mobile apps frequently use the same backend with different auth flow:
```bash
curl -b cookies.txt https://target.com/api/v2/mobile/profile
```

## Verifying success

- Protected endpoint returns user data (200 with user-specific content).
- Session is treated as fully authenticated despite no OTP submission.
- Same endpoint requested AFTER logging out returns 401 (control test).

## Common pitfalls

- Modern apps store MFA state IN the session (e.g. `session.mfa_verified = false`) — endpoint middleware checks this. Bypass impossible.
- Some apps use TWO different cookies: pre-MFA (limited scope) and post-MFA (full scope). Verify which cookie you have.
- API endpoints may use a different auth mechanism (JWT) that requires MFA proof claim — bypass requires JWT manipulation.
- WAF / API gateway may enforce MFA at the edge — backend allows direct access but the gateway blocks.

## Tools

- Burp Suite (HTTP history → Send to Repeater for direct endpoint testing).
- curl with persistent cookies.
- Playwright for SPA navigation.
- Postman for systematic API endpoint testing.
