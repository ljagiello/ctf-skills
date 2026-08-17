# Alive Hosts Discovery — ICMP, ARP, Broadcast

## When this applies

- You have a CIDR / IP range and need to enumerate live hosts before port-scanning.
- Goal is to reduce port-scan footprint (skip dead hosts) and map the network topology.
- Different probes yield different results depending on firewall/segmentation.

## Technique

Use multiple discovery methods in parallel — ICMP echo, timestamp/netmask requests, ARP for local subnets, and TCP ACK probes for firewalled segments. Cross-reference results: a host that answers ARP but not ICMP is alive but ICMP-blocked.

## Steps

### 1. ICMP ping sweep

```bash
# Standard ICMP echo sweep
nmap -sn -PE TARGET_RANGE

# Multiple ICMP types (echo + timestamp + netmask)
nmap -sn -PE -PP -PM TARGET_RANGE
```

ICMP types worth trying:
- **Echo (Type 8)**: standard ping
- **Timestamp (Type 13)**: time sync probe — often allowed when echo is blocked
- **Address Mask (Type 17)**: subnet info request

### 2. ARP discovery (local subnets only)

```bash
# ARP ping — only works on the same broadcast domain
nmap -sn -PR TARGET_RANGE

# arp-scan tool (faster, more reliable)
sudo arp-scan -l                # auto-detect interface, scan local /24
sudo arp-scan -I eth0 192.168.1.0/24

# netdiscover (passive + active)
sudo netdiscover -i eth0 -r 192.168.1.0/24
```

ARP is the gold standard for local-subnet host discovery — every IPv4 host responds, regardless of host firewall.

### 3. TCP ACK / SYN ping (firewall bypass)

```bash
# TCP SYN to port 80 — many firewalls allow this for HTTP
nmap -sn -PS80,443,22 TARGET_RANGE

# TCP ACK ping — bypasses some stateless firewalls
nmap -sn -PA80,443,22 TARGET_RANGE

# UDP probe to common UDP services
nmap -sn -PU53,161 TARGET_RANGE
```

When ICMP is blocked at the perimeter, TCP/UDP probes to expected open ports usually elicit responses (SYN/ACK or RST = host alive).

### 4. Combined sweep (recommended default)

```bash
# Combine all probe types — slowest but most thorough
nmap -sn -PE -PP -PM -PS21,22,23,25,80,443,3389 -PA80 -PU53,161 TARGET_RANGE
```

### 5. Skip discovery (when range is small or you already know hosts are up)

```bash
# Treat all hosts as up — useful when ICMP is filtered everywhere
nmap -Pn -sS -p 80,443 TARGET_RANGE
```

`-Pn` skips host discovery entirely and scans every IP. Use for small ranges or when discovery probes are blocked.

### 6. IPv6 host discovery

```bash
# IPv6 link-local discovery
nmap -6 -sn fe80::/10

# IPv6 multicast discovery via THC-IPv6
atk6-alive6 eth0
```

See `scenarios/ipv6/ipv6-recon.md` for detailed IPv6 enumeration.

### 7. Passive discovery

```bash
# Listen for broadcast/multicast traffic — discovers hosts without sending probes
sudo tcpdump -i eth0 -n 'arp or icmp6 or (udp port 5353)' -c 100

# netdiscover passive mode
sudo netdiscover -p
```

Passive discovery picks up ARP requests, mDNS announcements (`_services._dns-sd._udp.local`), DHCP, and SSDP traffic — useful when active probes would be detected.

### 8. mDNS / SSDP / NetBIOS discovery

```bash
# mDNS (Bonjour) services
dns-sd -B _services._dns-sd._udp local.    # macOS
avahi-browse -a -t                          # Linux

# SSDP (UPnP)
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n', ('239.255.255.250', 1900))
while True:
    try: print(s.recv(4096).decode())
    except: break
"

# NetBIOS name service
nmblookup -A TARGET_IP
```

## Verifying success

- List of live hosts saved (`nmap -sn ... -oA recon/alive`).
- Each host has at least one positive response (ICMP, ARP, TCP, UDP).
- Cross-check: ARP-only hosts (firewall blocks ICMP/TCP) appear in `arp-scan` output but not in ICMP sweep.

## Common pitfalls

- **ARP only works on local subnets** — across routers, ARP responses are not forwarded.
- **`-sn -PE` alone misses many hosts** behind ICMP-blocking firewalls. Always combine probes.
- **`-Pn` is heavy** — scans every IP including dead ones. Slow on /16 or larger.
- **VPN tap interfaces** sometimes drop ARP — use `-PE -PS80,443` for VPN-routed targets.
- **Cloud networks** (AWS, GCP) often allow ICMP only inside the VPC; from outside, only TCP probes work.
- **Some hosts respond to one ICMP type and not others** — `-PE -PP -PM` together catches more.

## Tools

- nmap (`-sn` host discovery, multiple probe types)
- arp-scan (fastest local-subnet ARP)
- netdiscover (active + passive ARP)
- THC-IPv6 (`atk6-alive6` for IPv6)
- tcpdump (passive listening)
- avahi-browse / dns-sd (mDNS)
- nbtscan, nmblookup (NetBIOS)
