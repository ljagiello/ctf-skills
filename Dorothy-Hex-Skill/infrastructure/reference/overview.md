# IP Infrastructure Attacks

Network and IP-level attack techniques for pentesting IP addresses and network infrastructure.

## Categories

| Attack Type | Focus | Key Tools |
|-------------|-------|-----------|
| **port-scanning** | Port discovery, service enumeration | nmap, masscan, RustScan |
| **dns** | DNS spoofing, cache poisoning, zone transfers | dig, dnsrecon, fierce |
| **mitm** | ARP spoofing, SSL stripping, traffic interception | Ettercap, Bettercap, mitmproxy |
| **sniffing** | Packet capture, credential extraction | Wireshark, tcpdump, tshark |
| **smb-netbios** | SMB relay, EternalBlue, LLMNR poisoning | Responder, CrackMapExec, enum4linux |
| **ipv6** | IPv6 protocol attacks, RA flooding | THC-IPv6, Scapy |
| **vlan-hopping** | VLAN isolation bypass, switch spoofing | Yersinia, Scapy |
| **dos** | Denial of service, traffic flooding | hping3, Slowloris |

## Usage

When pentesting IP addresses or network infrastructure:

1. Start with **port-scanning** for discovery
2. Use **sniffing** for passive reconnaissance
3. Apply **mitm** for traffic interception
4. Target specific protocols (**dns**, **smb-netbios**, **ipv6**)
5. Test isolation with **vlan-hopping**
6. Assess resilience with **dos** (authorized only)

Each folder contains `quickstart.md` with immediate test vectors and commands.

## Reference Logging

**CRITICAL**: All IP infrastructure tests MUST be logged to `reference/` files.

When pentester-executor agents run IP tests:
1. **Read** `reference/{scan-type}.md` for prior learnings
2. **Execute** test using proven techniques
3. **Append** result row to test matrix
4. **Update** learnings section if new patterns discovered

This creates a **feedback loop**: test → learn → improve → test better.

See `reference/README.md` for complete logging workflow.

## Structure

```
ip-infrastructure/
├── port-scanning/     # Service discovery
├── dns/               # DNS attacks
├── mitm/              # MitM & ARP
├── sniffing/          # Traffic capture
├── smb-netbios/       # Windows protocols
├── ipv6/              # IPv6 attacks
├── vlan-hopping/      # Network isolation
├── dos/               # DoS/DDoS
└── reference/         # Test logs & learnings
    ├── syn-scan.md
    ├── icmp-scan.md
    ├── udp-scan.md
    ├── service-enum.md
    ├── os-fingerprint.md
    ├── ip-reputation.md
    ├── firewall-detection.md
    └── README.md
```

All files < 50 lines, minimal duplication, synthesized from network attack knowledge.
