# Service Fingerprinting — Banner Grabbing & NSE Scripts

## When this applies

- You have a list of open ports and need to identify the running service, version, and exposed metadata.
- Goal is to feed CVE lookups, default-credential checks, and protocol-specific enumeration.

## Technique

Combine nmap version detection (`-sV`) with NSE scripts for protocol-aware banner extraction. For services where automated probes fail, drop to manual `nc`/`telnet`/`openssl s_client` interactions to read banners directly. Every banner line is a CVE candidate.

## Steps

### 1. Version detection sweep

```bash
# Service version detection on a port list
nmap -sV -p PORTS TARGET

# Full default + version probes (NSE -sC)
nmap -sV -sC -p PORTS TARGET

# Aggressive version detection (more probes, slower)
nmap -sV --version-intensity 9 TARGET
```

### 2. NSE scripts for high-value protocols

```bash
# HTTP methods + headers
nmap --script http-methods,http-headers,http-title -p 80,443,8080 TARGET

# SSH auth methods + algorithms
nmap --script ssh-auth-methods,ssh2-enum-algos -p 22 TARGET

# SMB OS + shares
nmap --script smb-os-discovery,smb-enum-shares -p 445 TARGET

# SSL/TLS cert + ciphers
nmap --script ssl-cert,ssl-enum-ciphers -p 443 TARGET

# MSSQL info
nmap --script ms-sql-info -p 1433 TARGET

# MongoDB info + DB enumeration
nmap --script mongodb-info,mongodb-databases -p 27017 TARGET
```

### 3. Manual banner grabbing

```bash
# TCP banner via netcat
nc -v TARGET PORT

# HTTP HEAD for server header
curl -sI http://TARGET:PORT/

# TLS banner + cert
openssl s_client -connect TARGET:443 -servername TARGET </dev/null

# SMTP banner
nc -v TARGET 25
# server greets: 220 mail.example.com ESMTP Postfix
EHLO test
```

### 4. Per-protocol enumeration

**HTTP/HTTPS (80/443/8080)**: server header, framework, CMS fingerprint via `whatweb`, `httpx -tech-detect`.

**SSH (22)**: banner reveals OpenSSH version → CVE lookup. Algorithm enumeration shows weak crypto support.

**SMB (445)**: see `scenarios/smb/` for full enumeration. Quick: `smbclient -L //TARGET -N` (null), `smbclient -L //TARGET -U guest%` (guest).

**MySQL/PostgreSQL (3306/5432)**: version banner → CVE. PostgreSQL: `psql -h TARGET -p 5432 -U user -c '\l'` lists DBs. Try reused credentials from other services.

**Apache Tomcat (8080/8443)**: version from default page or `Server` header. Check `/manager/html` with default creds (`tomcat:s3cret`, `tomcat:tomcat`, `manager:manager`, `admin:admin`). Authenticated → deploy WAR webshell.

**RDP (3389)**: `nmap --script rdp-enum-encryption,rdp-ntlm-info -p 3389`.

**MSSQL (1433)**: version + linked server enumeration after auth: `SELECT * FROM sys.servers WHERE is_linked = 1;`.

**MongoDB (27017)**: check no-auth access. `pymongo`: `MongoClient(host, 27017).list_database_names()`. Compat: `pymongo>=4.0` requires MongoDB 4.2+; for 3.x targets pin `pymongo<4.0`.

**FTP (21)**: anonymous access (`curl ftp://anonymous:anonymous@TARGET/`). Recursively download — config files, password databases (`.psafe3`, `.kdbx`).

**SNMP (UDP 161)**: try community string `public` first. Highest-yield OID:

```bash
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.25.4.2.1.5 > recon/snmp-procs-args.txt
grep -iE 'pass|pwd|-p |--password|secret|token|key=' recon/snmp-procs-args.txt
```

Other useful OIDs:
- `1.3.6.1.2.1.25.4.2.1.4` hrSWRunPath (process binary paths)
- `1.3.6.1.2.1.25.6.3.1.2` hrSWInstalledName (installed packages → version-specific CVEs)
- `1.3.6.1.2.1.4.20.1.1` ipAdEntAddr (interface IPs — pivot targets)
- `1.3.6.1.2.1.6.13.1` tcpConnTable (active TCP connections)

Other community strings to try after `public`: `private`, `community`, `manager`, the company name lowercased, the hostname.

**Modbus TCP (502)**: ICS/SCADA — see `scenarios/ics/modbus.md`.

**CUPS / IPP (TCP/631 + UDP/631)**: `Server: CUPS/2.4 IPP/2.1` banner; web UI title shows exact version. Pre-fix cups-browsed (UDP/631 open) is unauthenticated RCE via the CVE-2024-47176/47076/47175/47177 chain — see `scenarios/network-recon/cups-browsed-rce.md`.

### 5. CVE lookup

For every banner line with a version number, run NVD/exploit-db search. CVE-yielding banners are typically formatted like `OpenSSH_7.6p1`, `Apache/2.4.50`, `Microsoft IIS/10.0`.

## Verifying success

- Each open port has a service name + version recorded.
- NSE script output saved (`-oA` writes `.nmap`/`.gnmap`/`.xml`).
- Manual banner captures saved alongside (e.g. `nc -v TARGET 25 | tee recon/smtp-banner.txt`).

## Common pitfalls

- **`-sV` low intensity** misses services on uncommon ports — bump to `--version-intensity 9` when service is unknown.
- **Encrypted protocols** (HTTPS, LDAPS, SMB w/ encryption) hide banners — use `openssl s_client` for TLS-wrapped probes.
- **Some services** require valid handshake before sending banner (FTP requires USER, IMAP requires CAPABILITY) — NSE scripts handle this; manual `nc` may not.
- **Rate-limited services** drop probes when scanned aggressively — fall back to `-T2` or single-port checks.
- **SNMP `nmap -sU -p 161`** is much slower than `snmpwalk` directly. Use `snmpwalk` once you suspect SNMP is open.

## Tools

- nmap with NSE (primary)
- whatweb / httpx (HTTP fingerprint)
- nc, ncat, openssl s_client (manual banners)
- snmpwalk, snmpcheck (SNMP)
- smbclient, rpcclient, enum4linux-ng (SMB)
- amap (alternative banner grabber for non-standard ports)
