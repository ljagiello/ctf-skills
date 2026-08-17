# 2FA — Response Manipulation

## When this applies

- Application validates 2FA in the BROWSER and uses the response to decide whether to grant access (client-side trust).
- Modify the server's response (status code, body, JSON fields) at the proxy and bypass 2FA without knowing the OTP.

## Technique

The auth flow returns `{success: false, mfa_required: true}` until the OTP is verified. If the application's frontend trusts this JSON to gate access (e.g. checks `success` field client-side), an attacker can intercept the response with a proxy and flip the boolean — the frontend then treats the user as authenticated.

## Steps

### 1. Capture the verification response

Original (failed verification):
```http
HTTP/1.1 401 Unauthorized
{
  "success": false,
  "mfa_required": true,
  "authenticated": false
}
```

### 2. Modify response in proxy

Use Burp Suite "Match and Replace" or Playwright route interception:

```javascript
await page.route('**/verify-2fa', route => {
    route.fulfill({
        status: 200,
        body: JSON.stringify({success: true, authenticated: true, mfa_required: false})
    });
});
await page.goto('https://target.com/dashboard');
```

### 3. Status code manipulation

If the frontend decides based on HTTP status:
- Original: `HTTP/1.1 401`
- Replace with: `HTTP/1.1 200`

### 4. Body field manipulation

Common boolean fields to flip:
- `success: true`
- `authenticated: true`
- `verified: true`
- `mfa_required: false`
- `is_2fa_complete: true`

### 5. Burp Match-and-Replace rule

```
Type: Response body
Match: "success":false,"mfa_required":true
Replace: "success":true,"mfa_required":false
```

### 6. Verify access to protected pages

Once the response is modified, the SPA stores auth state and lets you navigate to `/dashboard`, `/profile`, `/admin` without the server enforcing 2FA.

## Verifying success

- After modification, the protected page renders user data.
- Subsequent API calls use the session cookie / token (which was set after PASSWORD step) and are accepted.
- The 2FA challenge UI doesn't reappear.

## Common pitfalls

- Server-side enforcement (modern SPAs) — `/dashboard` re-verifies the session's MFA state via a separate API call. Response manipulation only fools the frontend, not the backend.
- Some apps store MFA state in the session/JWT — flipping the response doesn't change the server's view.
- HTTPS pinning (mobile apps) prevents proxy interception without root + cert pinning bypass.
- Two-step UIs may store partial auth state in localStorage — also bypass possible if state checks are frontend-only.

## Tools

- Burp Suite Match and Replace.
- Playwright route interception.
- mitmproxy.
- ZAP Replacer add-on.
