# WebSockets — Resources

## Standards

- RFC 6455 — The WebSocket Protocol — https://datatracker.ietf.org/doc/html/rfc6455
- RFC 7692 — Compression Extensions
- RFC 8441 — Bootstrapping WebSockets with HTTP/2
- WebSocket-over-HTTP/2 (RFC 8441) and HTTP/3 drafts
- IANA WebSocket Subprotocol Names registry

## OWASP

- OWASP WebSocket Security Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html
- OWASP API Security Top 10 — overlaps with WS authn/authz
- OWASP Top 10 (A01 Broken Access Control covers CSWSH)

## Notable CVEs

- CVE-2024-55591 — Node.js `ws` / FortiOS / FortiProxy — auth bypass via crafted handshake
- CVE-2023-46366 — Spring STOMP-over-WebSocket
- CVE-2018-1270 — Spring 4.x/5.x STOMP RCE
- CVE-2023-26136 — tough-cookie prototype pollution (impacts WS clients)
- CVE-2022-29965 — Apache Tomcat WebSocket message-fragment DoS
- CVE-2021-32796 — xmldom DTD parsing in WS payloads
- Gitpod CSWSH (2023, no CVE) — origin validation missing

## Tools

### Clients

- **wscat** — `npm install -g wscat`
- **websocat** — Rust, full TLS/SOCKS support — https://github.com/vi/websocat
- **Burp Suite** — built-in WebSocket Proxy + Repeater
- **OWASP ZAP** — WebSocket support
- **Browser DevTools** Network → WS

### Burp extensions

- **SocketSleuth** — WebSocket fuzzing — https://github.com/snyk/socketsleuth
- **WebSocket Turbo Intruder** — high-speed payload delivery
- **AutoRepeater** — replay across roles

### Python

```python
import asyncio, websockets
async def test():
    async with websockets.connect("wss://target/chat", extra_headers={"Origin": "https://attacker"}) as ws:
        await ws.send("READY")
        print(await ws.recv())
asyncio.run(test())
```

### Wordlists

- SecLists `Discovery/Web-Content/api/websocket-paths.txt`
- Common paths: `/ws`, `/websocket`, `/socket.io`, `/chat`, `/live`, `/notifications`, `/realtime`

## Attack technique writeups

- HackTricks WebSockets — https://book.hacktricks.xyz/pentesting-web/websocket-attacks
- PayloadsAllTheThings — WebSockets Attacks
- PortSwigger Research — "Cross-site WebSocket hijacking" (Christian Schneider)
- Snyk — "WebSocket Security: Authentication Issues"
- Doyensec — Socket.IO security
- HackerOne — disclosed CSWSH reports

## Practice / labs

- PortSwigger Web Security Academy — https://portswigger.net/web-security/websockets
- TryHackMe — WebSocket rooms
- Damn Vulnerable WebSocket Server (DVWS)

## Frameworks landscape

- Socket.IO (Node)
- ws (Node) — most-deployed WS lib
- Spring WebSocket / STOMP (JVM)
- Tornado / aiohttp / FastAPI (Python)
- Phoenix Channels (Elixir)
- ActionCable (Rails)

## Detection / SIEM

- Apache/Nginx access logs — `Upgrade: websocket`
- ModSecurity rules — block `Upgrade` from disallowed origins
- AWS WAF — origin validation
- DataDog APM — WebSocket monitoring

## Defensive references

- OWASP Cheat Sheet (above)
- Use SameSite=Strict cookies + CSRF tokens in handshake
- Validate `Origin` header against allowlist
- Authentication beyond cookies (JWT, signed tokens in handshake or first message)
- Rate limiting per connection / per user
- Sanitize ALL message content; never trust the channel

## Bug bounty programs with WebSocket scope

- Slack, Discord, Microsoft Teams, Trello — chat / realtime APIs
- Most SaaS dashboards — Stripe, Asana, Linear, Notion
- Trading platforms — Binance, Coinbase, Kraken (SocketIO)
- Streaming — Twitch, YouTube Live

## Wireshark / network analysis

- Wireshark `websocket` dissector
- mitmproxy WebSocket interception
- tcpdump — `tcp port 443 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x4754)` (HTTP upgrade)

## Cheat-sheet companions in this repo

- See `scenarios/websocket/discovery-and-handshake.md`
- `scenarios/websocket/cswsh.md`
- `scenarios/websocket/message-injection.md`
- `scenarios/websocket/auth-bypass-and-handshake-tricks.md`
