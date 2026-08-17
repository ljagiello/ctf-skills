# OAuth — PKCE Downgrade & Bypass

## When this applies

- Application uses Authorization Code Flow + PKCE.
- The OAuth provider does not REQUIRE PKCE for clients that registered without it (or treats `code_challenge` as optional).
- Goal: steal authorization code AND exchange it for a token without the `code_verifier`.

## Technique

PKCE binds the `code` to a `code_verifier` known only to the legitimate client. The provider verifies `SHA256(code_verifier) == code_challenge` at the token exchange. If PKCE is optional (the provider accepts code-exchange without `code_verifier`), an attacker who steals a code can exchange it freely — defeating the entire defense.

## Steps

### 1. Detect PKCE-optionality

Capture a legitimate flow. Note the `code_challenge` in the authorization request:

```http
GET /auth?client_id=ID&redirect_uri=...&response_type=code&code_challenge=ABC&code_challenge_method=S256
```

At token exchange, send the request WITHOUT `code_verifier`:

```http
POST /token HTTP/1.1
Host: oauth-server.com

grant_type=authorization_code&code=CODE&redirect_uri=...&client_id=ID
```

(No `code_verifier=...` parameter.)

If the response returns a token instead of an error, PKCE is optional / not enforced.

### 2. Detect `plain` PKCE method

```http
GET /auth?...&code_challenge=ABC&code_challenge_method=plain
```

`plain` means `code_verifier == code_challenge` (no hashing). If accepted, an attacker who sees the `code_challenge` in the network can replay it as the `code_verifier`.

### 3. Steal authorization code (combined with redirect_uri / state attacks)

PKCE-bypass alone isn't useful — you still need to steal the code. Combine with:

- `redirect-uri-manipulation.md` — redirect code to attacker.
- `csrf-state.md` — re-link via CSRF.
- `code-theft-postmessage.md` — exfiltrate from fragment / redirected page.

Once you have the code, exchange it without PKCE:

```http
POST /token HTTP/1.1

grant_type=authorization_code&code=STOLEN_CODE&redirect_uri=...&client_id=ID
```

### 4. PKCE downgrade via `code_challenge_method` confusion

Send authorization request with `code_challenge_method=S256` but specifying a `code_challenge` that is actually a plain string (not SHA256 hash). Some providers fall back to `plain` validation when the challenge format doesn't match expected hash output.

### 5. Test public client (mobile / SPA)

Public clients (no client_secret) are MORE likely to enforce PKCE strictly. Confidential clients (with client_secret) sometimes treat PKCE as optional because they have client_secret as another defense. Test both flows.

### 6. PKCE-required workaround on confidential clients

For confidential clients that require BOTH client_secret AND PKCE, you need both to exchange the code. Without `client_secret`:

- Find the secret in JS bundles (`grep -i 'client_secret' /static/*.js`).
- Find it in the OpenID configuration (some providers leak it).
- Use a confused-deputy pattern: have a legitimate flow exchange the code on your behalf.

### 7. Validate the stolen token

```http
GET /userinfo HTTP/1.1
Authorization: Bearer STOLEN_TOKEN
```

Returns the user the code was originally bound to.

## Verifying success

- Token endpoint returns 200 with access_token despite missing/invalid `code_verifier`.
- The token's identity matches the user who initiated the original auth flow (not the attacker).
- Attempting the same exchange WITH a wrong `code_verifier` either returns an error (PKCE active) or also succeeds (PKCE bypassed).

## Common pitfalls

- OAuth 2.1 mandates PKCE for ALL clients (confidential and public) — modern providers enforce it strictly.
- Authorization Code Flow without PKCE is still RFC 6749 compliant; many providers still allow it for backwards compatibility.
- Some providers store the `code_challenge` and require `code_verifier` even when not initially present — server-side enforcement varies.
- `code_challenge_method=plain` is technically RFC-compliant but trivially bypassable; some providers reject it.
- The `code` is single-use; once exchanged (legitimately or by attacker), it's invalid. Race against the legitimate client.

## Tools

- Burp Suite Repeater for token-endpoint manipulation.
- OAuth introspection (`/introspect`) to confirm token issuance.
- Custom scripts to generate valid PKCE pairs for comparison testing.
- Browser DevTools to capture legitimate `code_verifier` for replay.
