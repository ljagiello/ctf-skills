# IPv6 Reconnaissance — NDP and DHCPv6 Enumeration

## When this applies

- Target network has IPv6 enabled (most modern segments do, even when admins focus on IPv4).
- Goal is to enumerate IPv6-reachable hosts, learn the prefix(es) in use, and identify routers/DHCPv6 servers.
- Often a precursor to IPv6 attacks (mitm6, fake RA, NDP spoofing).

## Technique

IPv6 host discovery relies on multicast (`ff02::1` all-nodes, `ff02::2` all-routers) and Neighbor Discovery Protocol (NDP) instead of ARP. DHCPv6 is optional but common in enterprise networks. SLAAC-derived addresses use either EUI-64 (deterministic from MAC, easy to predict) or RFC 4941 privacy extensions (random, not predictable). Enumeration combines passive sniffing (RA/RS/NS/NA) with active probes.

## Steps

### 1. Identify your interface and link-local address

```bash
# Linux
ip -6 addr show eth0
# Look for fe80::... — the link-local address

# macOS
ifconfig en0 inet6
```

### 2. All-nodes multicast probe

```bash
# Ping all IPv6 hosts on the link
ping6 -c 3 ff02::1%eth0

# All routers
ping6 -c 3 ff02::2%eth0
```

Collect responding addresses from `ping6` output or run `tcpdump -i eth0 -nn icmp6` in parallel.

### 3. THC-IPv6 active discovery

```bash
# Alive scanner (NS/NA-based)
sudo atk6-alive6 eth0

# Discover routers
sudo atk6-dnsrevenum6 dns_server target_prefix::/64

# Smurf-style discovery (some hosts respond)
sudo atk6-smurf6 eth0 victim
```

`atk6-alive6` is the most reliable IPv6 host discovery tool.

### 4. Sniff for RA / DHCPv6 / NDP traffic

```bash
# Passive listening — discovers prefixes, gateways, DHCPv6 servers without sending probes
sudo tcpdump -i eth0 -nn 'icmp6 and (ip6[40]=134 or ip6[40]=133 or ip6[40]=135 or ip6[40]=136)'
# Type 134 = RA (Router Advertisement), 133 = RS, 135 = NS, 136 = NA

# DHCPv6 client/server traffic
sudo tcpdump -i eth0 -nn 'udp port 546 or udp port 547'
```

RA messages disclose:
- Prefix(es) in use (`prefix-info` option)
- M (managed) and O (other) flags — M=1 means DHCPv6 is being used for addresses
- Default gateway (RA source link-local address)
- DNS Recursive Server (RDNSS option) and Search List (DNSSL option)

### 5. Neighbor cache inspection

```bash
# Linux — current neighbor cache (post-NDP exchanges)
ip -6 neigh

# macOS
ndp -an
```

Reachable neighbors appear after any IPv6 traffic. Combine with `atk6-alive6` to populate the cache.

### 6. nmap IPv6 scanning

```bash
# IPv6 host discovery on a /64 isn't feasible (2^64 addresses) — must have a list
nmap -6 -sn fe80::/10                      # link-local probe
nmap -6 -sn -PE -PS22,80 TARGET_LIST       # specific addresses

# Service scan an IPv6 host
nmap -6 -sV -sC TARGET_IPV6
```

### 7. EUI-64 address recovery from MAC

When a host uses SLAAC without privacy extensions, its IPv6 address contains its MAC:

```text
MAC:  00:1A:2B:3C:4D:5E
EUI-64 derivation:
    Insert FF:FE in middle:  00:1A:2B:FF:FE:3C:4D:5E
    Flip 7th bit (Universal):02:1A:2B:FF:FE:3C:4D:5E
Address: <prefix>::021A:2BFF:FE3C:4D5E
```

Inversely, an IPv6 address with `:FF:FE:` in the lower 64 bits leaks the host's MAC — useful for inventory and asset correlation.

### 8. DHCPv6 enumeration

```bash
# Send a SOLICIT, capture ADVERTISE replies (passive listen)
sudo dhcping -6 -s ff02::1:2 -c eth0

# THC-IPv6 alternative
sudo atk6-dhcpv6_client eth0
```

DHCPv6 ADVERTISE messages disclose:
- DHCPv6 server identity (DUID)
- Available IA_NA (non-temporary address) range
- DNS recursive servers (option 23)
- Domain search list (option 24)

### 9. RDNSS / Search List harvest

```bash
# rdisc6 prints all RA-supplied DNS info
rdisc6 eth0
```

DNS server info from RAs / DHCPv6 feeds the next step (DNS enumeration of the prefix).

### 10. Reverse DNS sweep (when prefix known)

For a small subnet (DHCPv6 typically allocates from a small pool), reverse DNS the assigned addresses:

```bash
for addr in $(nmap -6 -sL <prefix>::1-100 -oG - | awk '/Status/ {print $2}'); do
  host $addr 2>/dev/null
done
```

Reverse PTR records for IPv6 use the `ip6.arpa` zone — often misconfigured / leaked, see `scenarios/dns/zone-transfer.md`.

## Verifying success

- List of IPv6-reachable hosts on the segment.
- Documented prefix(es), default gateway, DHCPv6 server, RDNSS / DNSSL.
- For each host: link-local + global address, MAC (when EUI-64 in use), reachable services.

## Common pitfalls

- **IPv6 host discovery cannot scan a full /64** — 18 quintillion addresses. Use multicast probes and passive listening only.
- **Privacy extensions** (RFC 4941, default on Windows since Vista) generate random suffixes that change daily — EUI-64 recovery doesn't work.
- **mDNS / DNS-SD over IPv6** (`ff02::fb`) often discloses Bonjour services on macOS / Linux hosts.
- **Link-local addresses require `%iface` suffix** — `ping6 fe80::1` fails; `ping6 fe80::1%eth0` works.
- **Many tools need root** — `atk6-*`, `tcpdump`, `nmap -sn`. Run with sudo.
- **Some Windows hosts have temp addresses with very short lifetime** — recon snapshots may differ between scans.
- **No ARP** — don't try `arp-scan -6`; use NDP (`ip -6 neigh`) instead.

## Tools

- THC-IPv6 (`atk6-alive6`, `atk6-fake_router6`, `atk6-dnsrevenum6`)
- nmap (with `-6`)
- ping6 (multicast probes)
- tcpdump / Wireshark (passive sniffing)
- rdisc6 / radvdump (RA inspection)
- dhcping, dhcpv6 client tools
- mitm6 (also useful for recon — logs DHCPv6 solicits without responding)
- ip / ndp (neighbor cache inspection)
