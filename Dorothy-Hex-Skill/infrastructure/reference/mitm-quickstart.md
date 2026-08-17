# Man-in-the-Middle Attacks

Intercepting and manipulating network communications.

## Techniques
- **ARP Spoofing**: Poisoning ARP cache for traffic interception
- **DNS Spoofing**: Redirecting DNS queries to attacker-controlled servers
- **SSL Stripping**: Downgrading HTTPS to HTTP
- **LLMNR/NBT-NS Poisoning**: Capturing credentials via name resolution

## Tools
- Bettercap, Responder, mitmproxy, arpspoof, ettercap

## Quick Commands
```bash
# ARP spoofing
arpspoof -i eth0 -t victim gateway
arpspoof -i eth0 -t gateway victim

# Bettercap
bettercap -iface eth0 -eval "net.sniff on; arp.spoof on"

# Responder (LLMNR/NBT-NS)
responder -I eth0 -wrf
```

## Methodology
1. Map network topology and targets
2. Position for interception (ARP, DNS, LLMNR)
3. Capture credentials and traffic
4. Test SSL/TLS stripping defenses
5. Document captured data and attack paths

**MITRE**: T1557 | **CWE**: CWE-300 | **CAPEC**: CAPEC-94
