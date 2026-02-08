---
name: ctf-forensics
description: Digital forensics and blockchain analysis for CTF challenges. Use when analyzing disk images, memory dumps, event logs, network captures, or cryptocurrency transactions.
user-invocable: false
allowed-tools: ["Bash", "Read", "Write", "Edit", "Glob", "Grep", "Task", "WebFetch", "WebSearch"]
---

# CTF Forensics & Blockchain

Quick reference for forensics challenges. For detailed techniques, see supporting files.

## Additional Resources

- [3d-printing.md](3d-printing.md) - 3D printing forensics (PrusaSlicer binary G-code, QOIF, heatshrink)
- [windows.md](windows.md) - Windows forensics (registry, SAM, event logs, recycle bin)
- [network.md](network.md) - Network forensics (PCAP, SMB3, WordPress, credentials)

---

## Quick Start Commands

```bash
# File analysis
file suspicious_file
exiftool suspicious_file     # Metadata
binwalk suspicious_file      # Embedded files
strings -n 8 suspicious_file
hexdump -C suspicious_file | head  # Check magic bytes

# Disk forensics
sudo mount -o loop,ro image.dd /mnt/evidence
fls -r image.dd              # List files
photorec image.dd            # Carve deleted files

# Memory forensics (Volatility 3)
vol3 -f memory.dmp windows.info
vol3 -f memory.dmp windows.pslist
vol3 -f memory.dmp windows.filescan
```

## Log Analysis

```bash
# Search for flag fragments
grep -iE "(flag|part|piece|fragment)" server.log

# Reconstruct fragmented flags
grep "FLAGPART" server.log | sed 's/.*FLAGPART: //' | uniq | tr -d '\n'

# Find anomalies
sort logfile.log | uniq -c | sort -rn | head
```

## Windows Event Logs (.evtx)

**Key Event IDs:**
- 1001 - Bugcheck/reboot
- 1102 - Audit log cleared
- 4720 - User account created
- 4781 - Account renamed

**RDP Session IDs (TerminalServices-LocalSessionManager):**
- 21 - Session logon succeeded
- 24 - Session disconnected
- 1149 - RDP auth succeeded (RemoteConnectionManager, has source IP)

```python
import Evtx.Evtx as evtx
with evtx.Evtx("Security.evtx") as log:
    for record in log.records():
        print(record.xml())
```

## When Logs Are Cleared

If attacker cleared event logs, use these alternative sources:
1. **USN Journal ($J)** - File operations timeline (MFT ref, timestamps, reasons)
2. **SAM registry** - Account creation from key last_modified timestamps
3. **PowerShell history** - ConsoleHost_history.txt (USN DATA_EXTEND = command timing)
4. **Defender MPLog** - Separate log with threat detections and ASR events
5. **Prefetch** - Program execution evidence
6. **User profile creation** - First login time (profile dir in USN journal)

## Steganography

```bash
steghide extract -sf image.jpg
zsteg image.png              # PNG/BMP analysis
stegsolve                    # Visual analysis
```

## PDF Analysis

```bash
exiftool document.pdf        # Metadata (often hides flags!)
pdftotext document.pdf -     # Extract text
strings document.pdf | grep -i flag
binwalk document.pdf         # Embedded files
```

### Advanced PDF Steganography (Nullcon 2026 rdctd series)

Six distinct hiding techniques in a single PDF:

**1. Invisible text separators:** Underscores rendered as invisible line segments. Extract with `pdftotext -layout` and normalize whitespace to underscores.

**2. URI annotations with escaped braces:** Link annotations contain flag in URI with `\{` and `\}` escapes:
```python
import pikepdf
pdf = pikepdf.Pdf.open(pdf_path)
for page in pdf.pages:
    for annot in (page.get("/Annots") or []):
        obj = annot.get_object()
        if obj.get("/Subtype") == pikepdf.Name("/Link"):
            uri = str(obj.get("/A").get("/URI")).replace(r"\{", "{").replace(r"\}", "}")
            # Check for flag pattern
```

**3. Blurred/redacted image with Wiener deconvolution:**
```python
from skimage.restoration import wiener
import numpy as np

def gaussian_psf(sigma):
    k = int(sigma * 6 + 1) | 1
    ax = np.arange(-(k//2), k//2 + 1, dtype=np.float32)
    xx, yy = np.meshgrid(ax, ax)
    psf = np.exp(-(xx**2 + yy**2) / (2 * sigma * sigma))
    return psf / psf.sum()

img_arr = np.asarray(img.convert("L")).astype(np.float32) / 255.0
deconv = wiener(img_arr, gaussian_psf(3.0), balance=0.003, clip=False)
```

**4. Vector rectangle QR code:** Hundreds of tiny filled rectangles (e.g., 1.718×1.718 units) forming a QR code. Parse PDF content stream for `re` operators, extract centers, render as grid, decode with `zbarimg`.

**5. Compressed object streams:** Use `mutool clean -d -c -m input.pdf output.pdf` to decompress all streams, then `strings` to search.

**6. Document metadata:** Check Producer, Author, Keywords fields: `pdfinfo doc.pdf` or `exiftool doc.pdf`.

## ZFS Forensics (Nullcon 2026)

**Pattern:** Corrupted ZFS pool image with encrypted dataset.

**Recovery workflow:**
1. **Label reconstruction:** All 4 ZFS labels may be zeroed. Find packed nvlist data elsewhere in the image using `strings` + offset searching.
2. **MOS object repair:** Copy known-good nvlist bytes to block locations, recompute Fletcher4 checksums:
```python
def fletcher4(data):
    a = b = c = d = 0
    for i in range(0, len(data), 4):
        a = (a + int.from_bytes(data[i:i+4], 'little')) & 0xffffffff
        b = (b + a) & 0xffffffff
        c = (c + b) & 0xffffffff
        d = (d + c) & 0xffffffff
    return (d << 96) | (c << 64) | (b << 32) | a
```
3. **Encryption cracking:** Extract PBKDF2 parameters (iterations, salt) from ZAP objects. GPU-accelerate with PyOpenCL for PBKDF2-HMAC-SHA1, verify AES-256-GCM unwrap on CPU.
4. **Passphrase list:** rockyou.txt or similar. GPU rate: ~24k passwords/sec.

## Memory Forensics

```bash
vol3 -f memory.dmp windows.info
vol3 -f memory.dmp windows.pslist
vol3 -f memory.dmp windows.cmdline
vol3 -f memory.dmp windows.netscan
vol3 -f memory.dmp windows.dumpfiles --physaddr <addr>
```

## Disk Image Analysis

```bash
# Mount
sudo mount -o loop,ro image.dd /mnt/evidence

# Autopsy / Sleuth Kit
fls -r image.dd              # List files
icat image.dd <inode>        # Extract by inode

# Carving
photorec image.dd
foremost -i image.dd
```

## VM Forensics (OVA/VMDK)

```bash
# OVA = TAR archive
tar -xvf machine.ova

# 7z reads VMDK directly
7z l disk.vmdk | head -100
7z x disk.vmdk -oextracted "Windows/System32/config/SAM" -r
```

## Windows Password Hashes

```python
from impacket.examples.secretsdump import LocalOperations, SAMHashes

localOps = LocalOperations('SYSTEM')
bootKey = localOps.getBootKey()
sam = SAMHashes('SAM', bootKey)
sam.dump()  # username:RID:LM:NTLM:::
```

```bash
# Crack with hashcat
hashcat -m 1000 hashes.txt wordlist.txt
```

## Bitcoin Tracing

- Use mempool.space API: `https://mempool.space/api/tx/<TXID>`
- **Peel chain:** ALWAYS follow LARGER output
- Look for consolidation transactions
- Round amounts (5.0, 23.0 BTC) indicate peels

## Coredump Analysis

```bash
gdb -c core.dump
(gdb) info registers
(gdb) x/100x $rsp
(gdb) find 0x0, 0xffffffff, "flag"
```

## Uncommon File Magic Bytes

| Magic | Format | Extension | Notes |
|-------|--------|-----------|-------|
| `OggS` | Ogg container | `.ogg` | Audio/video |
| `RIFF` | RIFF container | `.wav`,`.avi` | Check subformat |
| `%PDF` | PDF | `.pdf` | Check metadata & embedded objects |
| `GCDE` | PrusaSlicer binary G-code | `.g`, `.bgcode` | See 3d-printing.md |

## Common Flag Locations

- PDF metadata fields (Author, Title, Keywords)
- Image EXIF data
- Deleted files (Recycle Bin `$R` files)
- Registry values
- Browser history
- Log file fragments
- Memory strings

## VMware Snapshot Forensics

**Converting VMware snapshots to memory dumps:**
```bash
# .vmss (suspended state) + .vmem (memory) → memory.dmp
vmss2core -W path/to/snapshot.vmss path/to/snapshot.vmem
# Output: memory.dmp (analyzable with Volatility/MemprocFS)
```

**Malware hunting in snapshots (Armorless):**
1. Check Amcache for executed binaries near encryption timestamp
2. Look for deceptive names (Unicode lookalikes: `ṙ` instead of `r`)
3. Dump suspicious executables from memory
4. If PyInstaller-packed: `pyinstxtractor` → decompile `.pyc`
5. If PyArmor-protected: use PyArmor-Unpacker

**Ransomware key recovery via MFT:**
- Even if original files deleted, MFT preserves modification timestamps
- Seed-based encryption: recover mtime → derive key
```bash
vol3 -f memory.dmp windows.mftparser | grep flag
# mtime as Unix epoch → seed for PRNG → derive encryption key
```

## TFTP Netascii Decoding

**Problem:** TFTP netascii mode corrupts binary transfers; Wireshark doesn't auto-decode.

**Fix exported files:**
```python
# Replace netascii sequences:
# 0d 0a → 0a (CRLF → LF)
# 0d 00 → 0d (escaped CR)
with open('file_raw', 'rb') as f:
    data = f.read()
data = data.replace(b'\r\n', b'\n').replace(b'\r\x00', b'\r')
with open('file_fixed', 'wb') as f:
    f.write(data)
```

## TLS Traffic Decryption via Weak RSA

**Pattern (Tampered Seal):** TLS 1.2 with `TLS_RSA_WITH_AES_256_CBC_SHA` (no PFS).

**Attack flow:**
1. Extract server certificate from Server Hello packet (Export Packet Bytes → `public.der`)
2. Get modulus: `openssl x509 -in public.der -inform DER -noout -modulus`
3. Factor weak modulus (dCode, factordb.com, yafu)
4. Generate private key: `rsatool -p P -q Q -o private.pem`
5. Add to Wireshark: Edit → Preferences → TLS → RSA keys list

**After decryption:**
- Follow TLS streams to see HTTP traffic
- Export objects (File → Export Objects → HTTP)
- Look for downloaded executables, API calls

## Browser Credential Decryption

**Chrome/Edge Login Data decryption (requires master_key.txt):**
```python
from Crypto.Cipher import AES
import sqlite3, json, base64

# Load master key (from Local State file, DPAPI-protected)
with open('master_key.txt', 'rb') as f:
    master_key = f.read()

conn = sqlite3.connect('Login Data')
cursor = conn.cursor()
cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
for url, user, encrypted_pw in cursor.fetchall():
    # v10/v11 prefix = AES-GCM encrypted
    nonce = encrypted_pw[3:15]
    ciphertext = encrypted_pw[15:-16]
    tag = encrypted_pw[-16:]
    cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
    password = cipher.decrypt_and_verify(ciphertext, tag)
    print(f"{url}: {user}:{password.decode()}")
```

## Common Encodings

```bash
echo "base64string" | base64 -d
echo "hexstring" | xxd -r -p
# ROT13: tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

## WMI Persistence Analysis

**Pattern (Backchimney):** Malware uses WMI event subscriptions for persistence (MITRE T1546.003).

**Analysis tool:**
```bash
# PyWMIPersistenceFinder on OBJECTS.DATA file
python PyWMIPersistenceFinder.py OBJECTS.DATA
```

**What to look for:**
- FilterToConsumerBindings with CommandLineEventConsumer
- Base64-encoded PowerShell in consumer commands
- Event filters triggered on system events (logon, timer)

## Deleted Partition Recovery

**Pattern (Till Delete Do Us Part):** USB image with deleted partition table.

**Recovery workflow:**
```bash
# Check for partitions
fdisk -l image.img              # Shows no partitions

# Recover partition table
testdisk image.img              # Interactive recovery

# Or use kpartx to map partitions
kpartx -av image.img            # Maps as /dev/mapper/loop0p1

# Mount recovered partition
mount /dev/mapper/loop0p1 /mnt/evidence

# Check for hidden directories
ls -la /mnt/evidence            # Look for .dotfolders
find /mnt/evidence -name ".*"   # Find hidden files
```

**Flag hiding:** Path components as flag chars (e.g., `/.Meta/CTF/{f/l/a/g}`)

## USB Audio Extraction from PCAP

**Pattern (Talk To Me):** USB isochronous transfers contain audio data.

**Extraction workflow:**
```bash
# Export ISO data with tshark
tshark -r capture.pcap -T fields -e usb.iso.data > audio_data.txt

# Convert to raw audio and import into Audacity
# Settings: signed 16-bit PCM, mono, appropriate sample rate
# Listen for spoken flag characters
```

**Identification:** USB transfer type URB_ISOCHRONOUS = real-time audio/video

## PowerShell Ransomware Analysis

**Pattern (Email From Krampus):** PowerShell memory dump + network capture.

**Analysis workflow:**
1. Extract script blocks from minidump:
```bash
python power_dump.py powershell.DMP
# Or: strings powershell.DMP | grep -A5 "function\|Invoke-"
```

2. Identify encryption (typically AES-CBC with SHA-256 key derivation)

3. Extract encrypted attachment from PCAP:
```bash
# Filter SMTP traffic in Wireshark
# Export attachment, base64 decode
```

4. Find encryption key in memory dump:
```bash
# Key often generated with Get-Random, regex search:
strings powershell.DMP | grep -E '^[A-Za-z0-9]{24}$' | sort | head
```

5. Find archive password similarly, decrypt layers

## Linux Attack Chain Forensics

**Pattern (Making the Naughty List):** Full attack timeline from logs + PCAP + malware.

**Evidence sources:**
```bash
# SSH session commands
grep -A2 "session opened" /var/log/auth.log

# User command history
cat /home/*/.bash_history

# Downloaded malware
find /usr/bin -newer /var/log/auth.log -name "ms*"

# Network exfiltration
tshark -r capture.pcap -Y "tftp" -T fields -e tftp.source_file
```

**Common malware pattern:** AES-ECB encrypt + XOR with same key, save as .enc

## Firefox Browser History (places.sqlite)

**Pattern (Browser Wowser):** Flag hidden in browser history URLs.

```bash
# Quick method
strings places.sqlite | grep -i "flag\|MetaCTF"

# Proper forensic method
sqlite3 places.sqlite "SELECT url FROM moz_places WHERE url LIKE '%flag%'"
```

**Key tables:** `moz_places` (URLs), `moz_bookmarks`, `moz_cookies`

## DTMF Audio Decoding

**Pattern (Phone Home):** Audio file contains phone dialing tones encoding data.

```bash
# Decode DTMF tones
sox phonehome.wav -t raw -r 22050 -e signed-integer -b 16 -c 1 - | \
    multimon-ng -t raw -a DTMF -
```

**Post-processing:** Phone number may contain octal-encoded ASCII after delimiter (#):
```python
# Convert octal groups to ASCII
octal_groups = ["115", "145", "164", "141"]  # M, e, t, a
flag = ''.join(chr(int(g, 8)) for g in octal_groups)
```
