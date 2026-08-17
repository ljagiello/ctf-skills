# Port Scanning — TCP and UDP

## When this applies

- You have an authorized target IP (single host or CIDR range) and need to enumerate listening services.
- Goal is to map the attack surface (open TCP/UDP ports) before service-level testing.
- Both initial discovery (top 1000) and exhaustive (`-p-`) scans may be required.

## Technique

Send probes to each port and infer state from responses (SYN/ACK = open, RST = closed, no response = filtered). Use SYN scans for TCP (half-open, fast, requires root) and UDP scans (slow, ambiguous "open|filtered" responses) for UDP services. Combine with version detection for service banners.

## Steps

### 1. Fast TCP SYN scan (top 1000 ports)

```bash
# Stealth half-open scan, requires root
nmap -sS -T4 TARGET

# With reason explanation (why a port is filtered/open)
nmap -sS -p- --reason TARGET
```

Port states:
- **open**: SYN/ACK received
- **closed**: RST received
- **filtered**: No response (firewall drops)

### 2. Full TCP port range

```bash
# All 65535 ports — use --min-rate for speed
nmap -sS -p- --min-rate 10000 TARGET

# Specific port ranges
nmap -sS -p 1-1024,8000-9000 TARGET

# Fast alternative with masscan
masscan TARGET -p0-65535 --rate=1000
```

### 3. UDP scan — top 100 then targeted

```bash
# UDP top 100 (slow — UDP has no handshake)
nmap -sU --top-ports 100 TARGET

# Specific UDP services
nmap -sU -p 53,161,162,500 TARGET

# UDP with version detection (helps confirm "open|filtered")
nmap -sU -sV --top-ports 20 TARGET

# Fast UDP — short retries
nmap -sU -T4 --max-retries 1 --top-ports 100 TARGET
```

High-value UDP services:
- **53** DNS, **161/162** SNMP, **123** NTP, **500** IPSec IKE, **1434** MSSQL Monitor, **5353** mDNS

### 4. Service version detection

```bash
# Service version detection on discovered ports
nmap -sV -p PORTS TARGET

# Aggressive (slowest, most accurate)
nmap -sV --version-intensity 9 TARGET

# Combined version + default scripts
nmap -sV -sC TARGET

# Banner grabbing without nmap
nc -v TARGET PORT
```

Version intensity:
- 0 = light probes only
- 5 = default balance
- 9 = all probes (slowest, most accurate)

### 5. Focused scans for known archetypes

When initial fingerprinting suggests a Windows DC archetype (any of 53/135/139/445/389 open), run a focused 13-port scan instead of `-p-`:

```bash
nmap -Pn -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,5986,9389 \
    -oA recon/ad-focused TARGET
```

Ports: 53 DNS, 88 Kerberos, 135 RPC, 139/445 SMB, 389/636 LDAP/LDAPS, 464 kpasswd, 593 RPC-over-HTTPS, 3268/3269 GC/GC-LDAPS, 5985/5986 WinRM, 9389 AD Web Services.

### 6. TCP connect (when SYN unavailable)

```bash
# Full handshake — works without root, more easily detected
nmap -sT TARGET
```

### 7. Mass-host discovery (parallel host + port)

```bash
# masscan: discover any host on any port range very fast
masscan 10.0.0.0/24 -p1-65535 --rate=10000 -oG out.gnmap

# Pipe into nmap for version detection on confirmed open ports only
```

## Verifying success

- Discovered ports list (`nmap -oA <prefix>` writes `.nmap`, `.gnmap`, `.xml`).
- Service/version banners returned for each open port.
- Cross-check with `nc -v`/`telnet` against any port that nmap flagged "filtered" — sometimes scans miss services protected by SYN-cookies or rate limits.

## Common pitfalls

- **SYN scan needs root/sudo** — falls back to `-sT` connect scan unprivileged.
- **UDP "open|filtered"** is the most common state — UDP services don't reply to empty probes; only version detection (`-sV`) can confirm.
- **`--min-rate`** values too high cause packet loss → false negatives. Tune per network.
- **Firewall path TTL changes** can split a host into "two hosts" in nmap output — always inspect raw nmap XML.
- **Top-ports lists vary** between nmap versions — record `--top-ports` value in the report.
- **`-Pn`** assumes host is up; use it when ICMP is filtered, but it scans every port even on dead hosts.

## Tools

- nmap (primary, all scan types, NSE scripts)
- masscan (raw speed for large ranges)
- RustScan (parallelized nmap front-end)
- unicornscan (alternative async scanner)
- hping3 (manual probe crafting for evasion tests)
- nc/ncat (manual banner grabbing)
