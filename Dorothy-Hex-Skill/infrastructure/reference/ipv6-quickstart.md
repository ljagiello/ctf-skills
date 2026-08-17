# IPv6 Attacks

Exploiting IPv6 implementation and transition mechanism vulnerabilities.

## Techniques
- **RA Flooding**: Router Advertisement spoofing for MitM
- **Neighbor Spoofing**: NDP cache poisoning (IPv6 ARP equivalent)
- **Tunneling Attacks**: 6to4, Teredo, ISATAP abuse
- **Extension Header Abuse**: Fragmentation, routing header manipulation

## Tools
- THC-IPv6, Scapy, nmap (IPv6), RouterSploit

## Quick Commands
```bash
# IPv6 host discovery
nmap -6 -sn fe80::/10

# Router advertisement attack
atk6-fake_router6 eth0

# Neighbor discovery
atk6-alive6 eth0
```

## Methodology
1. Discover IPv6-enabled hosts
2. Test RA guard implementation
3. Attempt neighbor spoofing
4. Check for tunneling protocols
5. Test extension header handling

**MITRE**: T1557 | **CWE**: CWE-284 | **CAPEC**: CAPEC-158
