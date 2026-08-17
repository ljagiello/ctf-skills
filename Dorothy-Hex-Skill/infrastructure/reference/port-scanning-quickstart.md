# Port Scanning

Network service discovery and enumeration.

## Techniques
- **SYN Scan**: Half-open scanning (fast, stealthy)
- **TCP Connect**: Full connection scan
- **UDP Scan**: UDP service discovery
- **Service Detection**: Banner grabbing and version identification

## Tools
- nmap, masscan, Rustscan, unicornscan

## Quick Commands
```bash
# Quick SYN scan
nmap -sS -T4 target

# Full port scan with version detection
nmap -sS -sV -p- -T4 target

# Fast scan with masscan
masscan target -p0-65535 --rate=1000

# Service enumeration
nmap -sC -sV -p 80,443,22,21 target
```

## Methodology
1. Host discovery (ping sweep, ARP scan)
2. Port scanning (top 1000, then full)
3. Service and version detection
4. OS fingerprinting
5. Script scanning for known vulnerabilities

See also: `syn-scan.md`, `udp-scan.md`, `service-enum.md`, `os-fingerprint.md`, `firewall-detection.md`

**MITRE**: T1046 | **CWE**: N/A | **CAPEC**: CAPEC-300
