# WebSocket Discovery + Handshake Inspection

## When this applies

- Application uses real-time features (chat, notifications, dashboards, live trading).
- You need to find WebSocket endpoints, characterize the handshake, and identify CSRF tokens / origin checks.
- Identifying authentication mechanism (cookie, bearer, custom header) drives later attacks.

## Technique

Find the upgrade requests in proxy history, check JS for `new WebSocket(...)`, fingerprint common paths. Then inspect handshake for CSRF tokens, origin checks, and which credentials the server requires.

## Steps

### Identify endpoints — Browser DevTools

```
1. Open DevTools (F12)
2. Network tab
3. Filter: WS (WebSockets)
4. Observe connections
```

### Burp Suite

```
Proxy → HTTP history → Filter: WebSocket upgrade
Look for:
  - Upgrade: websocket
  - Connection: Upgrade
  - Sec-WebSocket-Key
```

### JavaScript source code

```javascript
// Search for:
new WebSocket(
WebSocket(
wss://
ws://
```

### Common WebSocket paths

```
/ws
/websocket
/socket.io
/chat
/live
/stream
/updates
/notifications
/realtime
```

### Connection flow

```
1. Client → HTTP Upgrade Request → Server
2. Server → 101 Switching Protocols → Client
3. Bi-directional messages over persistent connection
4. Either party can close connection
```

### Protocol comparison

| Protocol | Persistent | Bi-directional | Encrypted | Default Port |
|----------|-----------|----------------|-----------|--------------|
| ws:// | Yes | Yes | No | 80 |
| wss:// | Yes | Yes | Yes (TLS) | 443 |

### Client request headers

```http
GET /chat HTTP/1.1
Host: target.com
Connection: keep-alive, Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Origin: https://target.com
Cookie: session=abc123
```

### Server response

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

### Common custom headers

```http
Authorization: Bearer <token>
X-Auth-Token: <token>
X-CSRF-Token: <token>
X-Session-ID: <session>
```

### cURL handshake test

```bash
curl -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  https://target.com/chat
```

### Vulnerability indicators

**CSWSH vulnerable:**
```
Handshake contains only session cookie
No CSRF token
No state parameter
No nonce
No origin validation
```

### Common ports

| Port | Protocol | Usage |
|------|----------|-------|
| 80 | ws:// | Unencrypted WebSocket |
| 443 | wss:// | Encrypted WebSocket (TLS) |
| 8080 | ws:// | Development/proxy |
| 3000 | ws:// | Node.js default |

### Common close codes (when probing)

| Code | Meaning | Description |
|------|---------|-------------|
| 1000 | Normal Closure | Connection closed normally |
| 1001 | Going Away | Server/client going offline |
| 1002 | Protocol Error | Protocol violation |
| 1003 | Unsupported Data | Received unsupported data type |
| 1006 | Abnormal Closure | Connection lost without close frame |
| 1007 | Invalid Data | Received inconsistent data |
| 1008 | Policy Violation | Generic policy violation |
| 1009 | Message Too Big | Message exceeds size limit |
| 1011 | Internal Error | Server encountered error |

## Verifying success

- All WebSocket endpoints identified (paths, ports, message format).
- Handshake headers documented (which carry auth, which carry CSRF tokens).
- Origin validation behavior characterized (rejects forged origin? echoes it?).

## Common pitfalls

- Some apps use Socket.IO over WebSocket — different path / framing — check `socket.io.js` in JS bundles.
- Long-polling fallback may hide WebSocket — check transport negotiation.
- Some apps require a separate authentication step in the FIRST message, not the handshake — observe the initial frames.

## Tools

- Browser DevTools (Network → WS)
- Burp Suite (Proxy → WebSockets history)
- wscat / websocat (manual connect)
- curl `-N -H Upgrade:` for raw handshake
