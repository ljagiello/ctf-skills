# Filesystem Forensics

## MFT Analysis

The Master File Table ($MFT) records metadata for every file on an NTFS volume.

### Parsing with analyzeMFT

```bash
pip install analyzeMFT
analyzeMFT -f '$MFT' -o mft_output.csv
```

### Finding Dumped Files

Search for recently created sensitive files:
```bash
# Search for ntds.dit, SYSTEM hive, SAM, or other dump artifacts
grep -ai "ntds\.dit\|SYSTEM\|SAM\|\.dit" mft_output.csv | grep "2024-" | head
```

### Path Reconstruction

MFT records reference parent directories by record number. Trace the full path:

```python
import csv

records = {}
with open('mft_output.csv', 'r', errors='replace') as f:
    reader = csv.reader(f)
    header = next(reader)
    for row in reader:
        if row:
            records[row[0]] = row  # Key: Record Number

def get_path(record_num):
    path = []
    current = record_num
    seen = set()
    while current in records and current not in seen:
        seen.add(current)
        rec = records[current]
        path.append(rec[7])           # Filename (column 7)
        current = rec[5]              # Parent Record Number (column 5)
    path.reverse()
    return 'C:\\' + '\\'.join(path)
```

### File Size from Raw MFT

When `analyzeMFT` reports `content_size=None` (non-resident data), read directly:

```python
import struct

with open('$MFT', 'rb') as f:
    f.seek(record_number * 1024)  # Each MFT record = 1024 bytes
    data = f.read(1024)

    offset = struct.unpack_from('<H', data, 20)[0]  # First attribute offset
    while offset < len(data) - 4:
        attr_type = struct.unpack_from('<I', data, offset)[0]
        if attr_type == 0xFFFFFFFF: break
        attr_len = struct.unpack_from('<I', data, offset + 4)[0]
        if attr_len == 0: break

        if attr_type == 0x80:  # $DATA attribute
            if data[offset + 8]:  # Non-resident flag
                real_size = struct.unpack_from('<Q', data, offset + 48)[0]
                # real_size = actual file size in bytes
        offset += attr_len
```

### Key Timestamps

MFT stores 4 timestamps per file (in both $STANDARD_INFORMATION and $FILE_NAME):
- **Created** (column 9 in analyzeMFT CSV)
- **Modified** (column 10)
- **MFT Modified** (column 11)
- **Accessed** (column 12)

**SI vs FN timestamps**: $STANDARD_INFORMATION timestamps can be tampered. $FILE_NAME timestamps (columns 13-16) are harder to forge — compare both for timestomping detection.

## Windows Prefetch Analysis

Prefetch files record program execution history. Located at `C:\Windows\prefetch\`.

### File Naming

`PROGRAM.EXE-HASHVALUE.pf` — hash is based on the executable path.

### Win10 Decompression

Win10 prefetch uses MAM compression (header: `MAM\x04`):

```python
import struct
from dissect.util.compression import lzxpress_huffman

with open('PROGRAM.EXE-HASH.pf', 'rb') as f:
    data = f.read()

if data[:4] == b'MAM\x04':
    decomp_size = struct.unpack_from('<I', data, 4)[0]
    decompressed = lzxpress_huffman.decompress(data[8:])
```

### Extracting Execution Times and File References

From decompressed prefetch v30 (Win10):
```python
import re, struct, datetime

# Last run timestamps: offset 80, up to 8 entries of 8 bytes each
epoch = datetime.datetime(1601, 1, 1)
for i in range(8):
    ts = struct.unpack_from('<Q', decompressed, 80 + i*8)[0]
    if ts > 0:
        dt = epoch + datetime.timedelta(microseconds=ts // 10)
        if 2000 < dt.year < 2030:
            print(f"Run time: {dt}")

# Run count at offset 200
run_count = struct.unpack_from('<I', decompressed, 200)[0]

# File references (UTF-16LE strings)
for s in re.findall(b'(?:[\x20-\x7e]\x00){4,}', decompressed):
    decoded = s.decode('utf-16-le', errors='ignore')
    if '\\USERS\\' in decoded.upper() or '\\DOWNLOADS\\' in decoded.upper():
        print(f"Referenced: {decoded}")
```

**Note**: `windowsprefetch` Python library only works on Windows (needs `ctypes.windll`). Use manual binary parsing on macOS/Linux.

## MFT Resident Files (Small File Content Recovery)

Files < ~700 bytes are stored directly in the MFT record ($DATA attribute is "resident"). To recover:
1. Find MFT entry number from `analyzeMFT` CSV → calculate hex offset: `entry * 1024`
2. Read at that offset in `$MFT` with hex editor or `xxd`

```bash
# Calculate offset and extract
python3 -c "print(hex(5443 * 1024))"  # → 0x550C00
xxd -s 0x550C00 -l 1024 '$MFT'
```

Useful for recovering deleted notes, small configs, scripts.

## Windows Firewall Logs

Windows firewall log (`pfirewall.txt`) at `C:\Windows\System32\LogFiles\Firewall\pfirewall.txt`.

```
# Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path
2023-05-05 15:24:17 ALLOW TCP 172.17.79.129 13.232.96.186 50045 80 0 - 0 0 0 - - - SEND
```

Useful for: identifying highest source port to malicious IP, confirming C2 connections, network timeline.

## VSS Artifacts

Volume Shadow Copy creates snapshots visible as `\Device\HarddiskVolumeShadowCopy<N>`.

- **Volume GUID**: Found in NTFS operational log — `\\?\Volume{GUID}` associated with the shadow copy device
- **Snapshot path**: `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\<path>` — visible in ESENT Event 216/330
- **ntdsutil snapshot mount**: Creates `C:\$SNAP_<timestamp>_VOLUMEC$\` mount point

## Linux Persistence Artifacts

### Systemd Service Units

Malicious services installed to persistence directories:
- `/usr/lib/systemd/system/` (system-wide, requires root)
- `/etc/systemd/system/` (admin overrides)
- `~/.config/systemd/user/` (user-level, no root needed)

**Analysis checklist**:
1. Check all fields — payloads hide in any field (`Description`, `ExecStart`, `ExecStop`, `ExecStartPre`)
2. Decode embedded base64 blobs (`echo -e "..." | base64 --decode`)
3. Look for `WantedBy=multi-user.target` (auto-start on boot)
4. Trace downloaded binaries (`curl`/`wget` targets in installer scripts)

### Bash Persistence Scripts

Common patterns:
- **Environment gating**: `whoami`/`hostname` checks limit execution to target host
- **Fake package repos**: Domains mimicking legitimate registries (e.g., `pypi-install.com` vs `pypi.org`)
- **Encoded payloads**: Base64/hex-encoded configs written via `echo -e "..." | base64 --decode > /path`

### Other Linux Persistence Locations

| Location | Purpose |
|----------|---------|
| `/etc/cron.d/`, crontab entries | Scheduled execution |
| `~/.bashrc`, `/etc/profile.d/` | Shell initialization hooks |
| `/etc/ld.so.preload` | Shared library injection |
| Authorized SSH keys | `~/.ssh/authorized_keys` backdoor |
| PAM modules | `/etc/pam.d/` authentication hooks |
