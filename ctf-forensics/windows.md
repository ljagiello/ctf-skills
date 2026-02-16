# CTF Forensics - Windows

## Table of Contents
- [Windows Event Logs (.evtx)](#windows-event-logs-evtx)
- [Registry Analysis](#registry-analysis)
  - [OEMInformation Backdoor Detection](#oeminformation-backdoor-detection)
- [SAM Database Analysis](#sam-database-analysis)
- [Recycle Bin Forensics](#recycle-bin-forensics)
- [Browser History](#browser-history)
- [Windows Telemetry (imprbeacons.dat)](#windows-telemetry-imprbeaconsdat)
- [Hosts File Hidden Data](#hosts-file-hidden-data)
- [Contact Files (.contact)](#contact-files-contact)
- [WinZip AES Encrypted Archives](#winzip-aes-encrypted-archives)
- [NTFS MFT Analysis](#ntfs-mft-analysis)
- [USN Journal ($J) Analysis](#usn-journal-j-analysis)
- [SAM Account Creation Timing](#sam-account-creation-timing)
- [Impacket wmiexec.py Artifacts](#impacket-wmiexecpy-artifacts)
- [PowerShell History as Timeline](#powershell-history-as-timeline)
- [User Profile Creation as First Login Indicator](#user-profile-creation-as-first-login-indicator)
- [RDP Session Event IDs](#rdp-session-event-ids)
- [Windows Defender MPLog Analysis](#windows-defender-mplog-analysis)
- [Anti-Forensics Detection Checklist](#anti-forensics-detection-checklist)

---

## Windows Event Logs (.evtx)

**Key Event IDs:**

| Event ID | Description |
|----------|-------------|
| 1001 | Bugcheck/reboot |
| 41 | Unclean shutdown |
| 4720 | User account created |
| 4722 | User account enabled |
| 4724 | Password reset attempted |
| 4726 | User account deleted |
| 4738 | User account changed |
| 4781 | Account name changed (renamed) |

**Parse with python-evtx:**
```python
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

with evtx.Evtx("Security.evtx") as log:
    for record in log.records():
        xml_str = record.xml()
        root = ET.fromstring(xml_str)
        ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

        event_id = root.find('.//ns:EventID', ns).text
        if event_id == '4720':
            data = {}
            for d in root.findall('.//ns:Data', ns):
                data[d.get('Name')] = d.text
            print(f"User created: {data.get('TargetUserName')}")
```

---

## Registry Analysis

```bash
# RegRipper
rip.pl -r NTUSER.DAT -p all

# Key hives
NTUSER.DAT   # User settings
SAM          # User accounts
SYSTEM       # System config
SOFTWARE     # Installed software
```

### OEMInformation Backdoor Detection

**Location:** `SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation`

```python
from Registry import Registry

reg = Registry.Registry("SOFTWARE")
key = reg.open("Microsoft\\Windows\\CurrentVersion\\OEMInformation")
for val in key.values():
    print(f"{val.name()}: {val.value()}")
```

**Malware indicator:** Modified `SupportURL` pointing to C2.

---

## SAM Database Analysis

**Required files:**
- `Windows/System32/config/SAM` - Password hashes
- `Windows/System32/config/SYSTEM` - Boot key

**Extract hashes with impacket:**
```python
from impacket.examples.secretsdump import LocalOperations, SAMHashes

localOps = LocalOperations('SYSTEM')
bootKey = localOps.getBootKey()
sam = SAMHashes('SAM', bootKey)
sam.dump()  # username:RID:LM:NTLM:::
```

**Verify/Crack NTLM:**
```python
from Crypto.Hash import MD4

def ntlm_hash(password):
    h = MD4.new()
    h.update(password.encode('utf-16-le'))
    return h.hexdigest()

# Crack with hashcat
# hashcat -m 1000 hashes.txt wordlist.txt
```

**Common RIDs:**
- 500 = Administrator
- 501 = Guest
- 1000+ = User accounts

---

## Recycle Bin Forensics

**Location:** `$Recycle.Bin\<SID>\`

**File structure:**
- `$R<random>.<ext>` - Actual deleted content
- `$I<random>.<ext>` - Metadata (original path, timestamp)

**Parse $I metadata:**
```python
# strings shows original path
# C.:.\.U.s.e.r.s.\.U.s.e.r.4.\.D.o.c.u.m.e.n.t.s.\.file.docx
```

**Hex-encoded flag fragments:**
```bash
cat '$R_InternSecret.txt'
# Output: 4B4354467B72656330...
echo "4B4354467B72656330..." | xxd -r -p
```

---

## Browser History

**Edge/Chrome (SQLite):**
```python
import sqlite3

history = "Users/<user>/AppData/Local/Microsoft/Edge/User Data/Default/History"
conn = sqlite3.connect(history)
cur = conn.cursor()
cur.execute("SELECT url, title FROM urls ORDER BY last_visit_time DESC")
for url, title in cur.fetchall():
    print(f"{title}: {url}")
```

---

## Windows Telemetry (imprbeacons.dat)

**Location:** `Users/<user>/AppData/Local/Packages/Microsoft.Windows.ContentDeliveryManager_*/LocalState/`

```bash
strings imprbeacons.dat | tr '&' '\n' | grep -E "CIP|geo_|COUNTRY"
```

**Key fields:** `CIP` (client IP), `geo_lat/long`, `COUNTRY`, `SMBIOSDM`

---

## Hosts File Hidden Data

**Location:** `Windows/System32/drivers/etc/hosts`

Attackers hide data with excessive whitespace:
```bash
# Detect hidden content
xxd hosts | tail -20
```

---

## Contact Files (.contact)

**Location:** `Users/<user>/Contacts/*.contact`

**Hidden data in Notes:**
```xml
<c:Notes>h1dden_c0ntr4ct5</c:Notes>
```

---

## WinZip AES Encrypted Archives

```bash
# Extract hash
zip2john encrypted.zip > zip_hash.txt

# Crack with hashcat (mode 13600)
hashcat -m 13600 zip_hash.txt wordlist.txt

# Hybrid: word + 4 digits
hashcat -m 13600 zip_hash.txt wordlist.txt -a 6 '?d?d?d?d'
```

---

## NTFS MFT Analysis

**Location:** `C:\$MFT` (Master File Table)

**Key techniques:**
- Filenames are stored in UTF-16LE in the MFT
- Each file has two timestamp sets: `$STANDARD_INFORMATION` (user-modifiable) and `$FILE_NAME` (system-controlled)
- Timestomping detection: Compare SI vs FN timestamps; if SI dates are much older than FN dates, the file was timestomped

```python
# Search MFT for filenames (binary file, use strings)
# ASCII:
# strings $MFT | grep -i "suspicious"
# UTF-16LE:
# strings -el $MFT | grep -i "suspicious"

# MFT record structure (1024 bytes each, starting at offset 0):
# - Offset 0x00: "FILE" signature
# - Attribute 0x30 ($FILE_NAME): Contains FN timestamps (reliable)
# - Attribute 0x10 ($STANDARD_INFORMATION): Contains SI timestamps (modifiable)
```

---

## USN Journal ($J) Analysis

**Location:** `C:\$Extend\$J` (Update Sequence Number Journal)

Tracks all file system changes. Critical when event logs are cleared.

```python
import struct, datetime

def parse_usn_record(data, offset):
    """Parse USN_RECORD_V2 at given offset"""
    rec_len = struct.unpack_from('<I', data, offset)[0]
    major = struct.unpack_from('<H', data, offset + 4)[0]  # Must be 2
    file_ref = struct.unpack_from('<Q', data, offset + 8)[0] & 0xFFFFFFFFFFFF
    parent_ref = struct.unpack_from('<Q', data, offset + 16)[0] & 0xFFFFFFFFFFFF
    timestamp = struct.unpack_from('<Q', data, offset + 32)[0]
    reason = struct.unpack_from('<I', data, offset + 40)[0]
    file_attr = struct.unpack_from('<I', data, offset + 52)[0]
    fn_len = struct.unpack_from('<H', data, offset + 56)[0]
    fn_off = struct.unpack_from('<H', data, offset + 58)[0]  # Usually 60
    filename = data[offset + fn_off:offset + fn_off + fn_len].decode('utf-16-le')
    dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=timestamp // 10)
    return dt, filename, reason, file_attr, parent_ref

# USN Reason flags:
# 0x1=DATA_OVERWRITE, 0x2=DATA_EXTEND, 0x4=DATA_TRUNCATION
# 0x100=FILE_CREATE, 0x200=FILE_DELETE, 0x1000=NAMED_DATA_OVERWRITE
# 0x80000000=CLOSE
```

**Key forensic uses:**
- Find file creation/deletion times even when logs are cleared
- Track wmiexec.py output files (`__<timestamp>.<random>`)
- Determine when PowerShell history was written (timeline of commands)
- Detect user profile creation (first interactive login time)

---

## SAM Account Creation Timing

When Security event logs (EventID 4720) are cleared, determine account creation time from the SAM registry:

```python
from regipy.registry import RegistryHive

sam = RegistryHive('SAM')
# Navigate to: SAM\Domains\Account\Users\Names\<username>
# The key's last_modified timestamp = account creation time
names_key = sam.get_key('SAM\\Domains\\Account\\Users\\Names')
for subkey in names_key.iter_subkeys():
    print(f"{subkey.name}: created {subkey.header.last_modified}")
```

---

## Impacket wmiexec.py Artifacts

**wmiexec.py** is a popular remote command execution tool using WMI. Key artifacts:

1. **Output files:** Creates `__<unix_timestamp>.<random>` in `C:\Windows\` (ADMIN$ share)
   - File is created, written with command output, read back, then deleted
   - Each command execution creates a new cycle
   - USN journal preserves create/delete timestamps even after file deletion

2. **WMI Provider Host:** `WMIPRVSE.EXE` prefetch file confirms WMI usage

3. **Timeline reconstruction:** Count USN create-delete cycles for the output file to determine number of commands executed

```python
# Search for wmiexec output files in MFT
# strings -el $MFT | grep -E '^__[0-9]{10}'
# The unix timestamp in the filename = approximate execution start time
```

---

## PowerShell History as Timeline

**Location:** `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

PSReadLine writes commands incrementally. **USN journal DATA_EXTEND events on this file correspond to individual command executions:**

```
08:05:19 - FILE_CREATE + DATA_EXTEND → First command entered
08:05:50 - DATA_EXTEND → Second command entered
08:09:57 - DATA_EXTEND → Third command entered
```

This provides exact execution timestamps for each command even when PowerShell logs are cleared.

---

## User Profile Creation as First Login Indicator

When event logs are cleared, the user profile directory creation in USN journal reveals the first interactive login:

```python
# Search USN journal for username directory creation
# Reason flag 0x100 (FILE_CREATE) with parent ref matching C:\Users (MFT ref 512)
# Example: ithelper DIR FILE_CREATE parent=512 at 08:03:51
# → First login (RDP/console) was at approximately 08:03
```

**Key insight:** User profiles are only created on first interactive logon (RDP or console), not via WMI/wmiexec remote execution.

---

## RDP Session Event IDs

**TerminalServices-LocalSessionManager\Operational:**

| Event ID | Description |
|----------|-------------|
| 21 | Session logon succeeded |
| 22 | Shell start notification received |
| 23 | Session logoff succeeded |
| 24 | Session disconnected |
| 25 | Session reconnection succeeded |
| 40 | Session created |
| 41 | Session begin (user notification) |
| 42 | Shell start (user notification) |

**TerminalServices-RemoteConnectionManager\Operational:**

| Event ID | Description |
|----------|-------------|
| 261 | Listener received connection |
| 1149 | RDP user authentication succeeded (contains source IP) |

**RemoteDesktopServices-RdpCoreTS\Operational:**

| Event ID | Description |
|----------|-------------|
| 131 | Connection accepted (TCP, contains ClientIP:port) |
| 102 | Connection from client |
| 103 | Disconnected (check ReasonCode) |

---

## Windows Defender MPLog Analysis

**Location:** `C:\ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log`

Rich source of threat detection timeline, even when other logs are cleared:

```bash
# Find threat detections
grep -i "DETECTION\|THREAT\|QUARANTINE" MPLog*.log

# Find ASR (Attack Surface Reduction) rule activity
grep -i "ASR\|Process.*Block" MPLog*.log

# Key ASR rules (indicators of attack attempts):
# - "Block Process Creations originating from PSExec & WMI commands"
# - "Block credential stealing from lsass.exe"
```

**Detection History files:** `C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\`
- Binary files containing SHA256, file paths, and detection names
- Parse with `strings` to extract IOCs

---

## Anti-Forensics Detection Checklist

When event logs are cleared (attacker used `wevtutil cl` or `Clear-EventLog`):

1. **USN Journal** - Survives log clearing; shows file operations timeline
2. **SAM registry** - Account creation timestamps preserved
3. **PowerShell history** - ConsoleHost_history.txt often survives
4. **Prefetch files** - Shows executed programs (C:\Windows\Prefetch\)
5. **MFT** - File metadata preserved even for deleted files
6. **Defender MPLog** - Separate from Windows event logs, often not cleared
7. **RDP event logs** - TerminalServices logs are separate from Security.evtx
8. **WMI repository** - C:\Windows\System32\wbem\Repository\OBJECTS.DATA
9. **Browser history** - SQLite databases in user AppData
10. **Registry timestamps** - Key last_modified times reveal activity

**Security.evtx EventID 1102** = "The audit log was cleared" (ironically logged even during clearing)
