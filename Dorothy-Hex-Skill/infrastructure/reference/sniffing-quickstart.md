# Network Sniffing

Passive and active network traffic capture and analysis.

## Techniques
- **Passive Sniffing**: Capturing traffic on shared networks
- **Active Sniffing**: ARP poisoning to redirect traffic
- **Protocol Analysis**: Extracting credentials and data from protocols
- **Wireless Sniffing**: 802.11 frame capture

## Tools
- Wireshark, tcpdump, tshark, NetworkMiner, dsniff

## Quick Commands
```bash
# Capture all traffic
tcpdump -i eth0 -w capture.pcap

# Filter HTTP traffic
tcpdump -i eth0 port 80 -A

# Extract credentials
dsniff -i eth0

# Wireshark display filter
http.request.method == "POST"
ftp.request.command == "PASS"
```

## Methodology
1. Identify network position and capture capability
2. Capture traffic on target segments
3. Analyze protocols for cleartext credentials
4. Extract files and data from streams
5. Document findings with packet captures

**MITRE**: T1040 | **CWE**: CWE-319 | **CAPEC**: CAPEC-157
