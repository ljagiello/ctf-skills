# Promiscuous Network Capture

## When this applies

- You have a network interface that can be put into promiscuous (or monitor) mode.
- Goal is to passively collect L2/L3 traffic for credential extraction, protocol analysis, or post-incident forensics.
- Common positions: SPAN/mirror port, network tap, hub (rare today), wireless monitor mode, or a host already with elevated NIC privileges (root).

## Technique

A promiscuous-mode NIC accepts every frame on the wire, not just frames addressed to its MAC. On switched networks, this only collects broadcast/multicast and traffic destined for/from the host — combine with ARP poisoning, port mirroring, or a tap to see other hosts' unicast traffic. Wireless requires monitor mode (separate from promiscuous) to capture 802.11 frames.

## Steps

### 1. Set the interface to promiscuous mode

```bash
# Linux
sudo ip link set eth0 promisc on
ip link show eth0       # verify "PROMISC" flag

# Or implicit: tcpdump/Wireshark/dumpcap auto-enable promisc
sudo tcpdump -i eth0 -p   # -p disables promiscuous if needed
```

### 2. Capture with tcpdump

```bash
# Full capture to a pcap file
sudo tcpdump -i eth0 -w capture.pcap

# With size limit + ring buffer (rolling 100 MB files, keep 10)
sudo tcpdump -i eth0 -w capture.pcap -C 100 -W 10

# BPF filter (only HTTP, FTP, SMB)
sudo tcpdump -i eth0 -w capture.pcap 'tcp port 80 or tcp port 21 or tcp port 445'

# Snaplen for full packet (default 262144 in modern tcpdump)
sudo tcpdump -i eth0 -s 0 -w capture.pcap
```

### 3. Capture with dumpcap (Wireshark's CLI)

```bash
sudo dumpcap -i eth0 -w capture.pcapng -b filesize:102400 -b files:10

# Auto-stop after 5 minutes
sudo dumpcap -i eth0 -w capture.pcapng -a duration:300
```

dumpcap is more reliable than tcpdump for long captures (better packet drop accounting, native pcapng).

### 4. Capture with tshark (analysis-ready)

```bash
# Live capture with display filter
sudo tshark -i eth0 -Y "http.request.method == POST" -T fields \
    -e ip.src -e http.host -e http.request.uri

# Decode as
sudo tshark -i eth0 -d tcp.port==8443,ssl
```

### 5. Wireless monitor mode

```bash
# Set wireless interface to monitor mode
sudo airmon-ng start wlan0
# Or manually:
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# Capture on a specific channel
sudo iw dev wlan0 set channel 6
sudo airodump-ng wlan0mon -c 6 -w wifi-cap
```

### 6. SPAN / port mirror setup (when you control the switch)

For non-MITM passive capture, request a SPAN port on the target switch:
- Cisco: `monitor session 1 source interface Gi0/24 ; monitor session 1 destination interface Gi0/48`
- Juniper: similar `mirror` configuration
- The destination port receives a copy of all traffic on the source port — connect your capture station here.

### 7. BPF filter examples

```text
# Specific host
host 192.168.1.10

# Subnet
net 192.168.1.0/24

# Port
port 22

# Direction
src host X
dst host Y

# Protocol
tcp[tcpflags] & (tcp-syn|tcp-fin) != 0     # SYN or FIN packets

# Combine with not / and / or
host 10.0.0.5 and not port 22
```

### 8. Avoid pcap rotation issues

For long captures: use `-W` ring buffer or `tcpdump -G 3600 -w 'capture-%Y%m%d-%H.pcap'` for hourly rotation. Single uncompressed pcaps over 10 GB become unwieldy.

### 9. Sanitize captured pcaps before sharing

```bash
# Anonymize MACs
tcprewrite --enet-smac=00:00:00:00:00:01 --enet-dmac=00:00:00:00:00:02 \
    -i capture.pcap -o sanitized.pcap

# Strip payloads
editcap -L capture.pcap stripped.pcap     # truncate to header only
```

### 10. Detection caveats

```bash
# Detect promiscuous NICs on the LAN
nmap --script sniffer-detect -p1 TARGET_RANGE

# Or via ARP
sudo arping -i eth0 -p TARGET   # some NICs respond to broadcast ARP only in promiscuous mode
```

Modern OS kernels filter many of these detection vectors, but the techniques still flag misconfigured endpoints.

## Verifying success

- pcap file accumulates packets at expected rate (`tcpdump -i eth0` rolling counter, or `capinfos capture.pcap`).
- `Wireshark → Statistics → Endpoints` shows traffic from hosts other than the capture station.
- `capinfos capture.pcap` reports packet count, average rate, capture duration.

## Common pitfalls

- **Switched networks** + no MITM/mirror = you only see your own traffic + broadcast. Use ARP poisoning or SPAN.
- **Wireless monitor mode** is OS / driver specific — many built-in laptop wireless chipsets don't support it. Use a USB adapter known to support monitor mode (Atheros AR9271, Realtek 8812AU).
- **Snaplen truncation** — old tcpdump default was 68 bytes. Always use `-s 0` for full packets.
- **Packet drops** — `tcpdump` reports `N packets dropped by kernel` on exit. If non-zero, increase `-B <buffer_size_kb>`.
- **VLAN tags** stripped by some NICs in software — Wireshark won't show them. Use `tcpdump -i eth0 -e` to include MAC + VLAN.
- **Encrypted traffic** (TLS, SSH, WireGuard) is opaque without keys. Capture is still useful for metadata (which hosts talk to which).
- **Privacy/legal**: capturing other users' traffic without authorization is illegal in many jurisdictions. Verify scope before enabling promiscuous mode on production networks.

## Tools

- tcpdump (CLI capture)
- dumpcap (Wireshark backend, more reliable for long captures)
- tshark (CLI analysis with display filters)
- Wireshark (GUI analysis)
- airodump-ng (wireless capture)
- airmon-ng (wireless monitor mode setup)
- editcap, mergecap (pcap manipulation)
- capinfos (pcap statistics)
- tcprewrite, tcpreplay (replay / sanitize)
