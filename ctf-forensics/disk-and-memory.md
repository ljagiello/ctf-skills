# CTF Forensics - Disk and Memory Analysis

## Table of Contents
- [Memory Forensics (Volatility 3)](#memory-forensics-volatility-3)
- [Disk Image Analysis](#disk-image-analysis)
- [VM Forensics (OVA/VMDK)](#vm-forensics-ovavmdk)
- [VMware Snapshot Forensics](#vmware-snapshot-forensics)
- [Coredump Analysis](#coredump-analysis)
- [Deleted Partition Recovery](#deleted-partition-recovery)
- [ZFS Forensics (Nullcon 2026)](#zfs-forensics-nullcon-2026)
- [GPT Partition GUID Data Encoding (VuwCTF 2025)](#gpt-partition-guid-data-encoding-vuwctf-2025)
- [Windows Minidump String Carving (0xFun 2026)](#windows-minidump-string-carving-0xfun-2026)
- [VMDK Sparse Parsing (0xFun 2026)](#vmdk-sparse-parsing-0xfun-2026)
- [Memory Dump String Carving (Pragyan 2026)](#memory-dump-string-carving-pragyan-2026)
- [Memory Dump Malware Extraction + XOR (VuwCTF 2025)](#memory-dump-malware-extraction--xor-vuwctf-2025)
- [Linux Ransomware Memory-Key Recovery (MetaCTF 2026)](#linux-ransomware-memory-key-recovery-metactf-2026)
- [WordPerfect Macro XOR Extraction (srdnlenCTF 2026)](#wordperfect-macro-xor-extraction-srdnlenctf-2026)
- [Minidump ISO 9660 Recovery + XOR Key (srdnlenCTF 2026)](#minidump-iso-9660-recovery--xor-key-srdnlenctf-2026)
- [APFS Snapshot Historical File Recovery (srdnlenCTF 2026)](#apfs-snapshot-historical-file-recovery-srdnlenctf-2026)
- [RAID 5 Disk Recovery via XOR (Crypto-Cat)](#raid-5-disk-recovery-via-xor-crypto-cat)
- [Windows KAPE Triage Analysis (UTCTF 2026)](#windows-kape-triage-analysis-utctf-2026)
- [PowerShell Ransomware Analysis](#powershell-ransomware-analysis)
- [Android Forensics](#android-forensics)
- [Container Forensics (Docker)](#container-forensics-docker)
- [Cloud Storage Forensics (AWS S3 / GCP / Azure)](#cloud-storage-forensics-aws-s3--gcp--azure)

---

## Memory Forensics (Volatility 3)

```bash
vol3 -f memory.dmp windows.info
vol3 -f memory.dmp windows.pslist
vol3 -f memory.dmp windows.cmdline
vol3 -f memory.dmp windows.netscan
vol3 -f memory.dmp windows.filescan
vol3 -f memory.dmp windows.dumpfiles --physaddr <addr>
vol3 -f memory.dmp windows.mftscan | grep flag
```

**Common plugins:**
- `windows.pslist` / `windows.pstree` - Process listing
- `windows.cmdline` - Command line arguments
- `windows.netscan` - Network connections
- `windows.filescan` - File objects in memory
- `windows.dumpfiles` - Extract files by physical address
- `windows.mftscan` - MFT FILE objects in memory (timestamps, filenames). Note: `mftparser` was Volatility 2 only; Vol3 uses `mftscan`

---

## Disk Image Analysis

```bash
# Mount read-only
sudo mount -o loop,ro image.dd /mnt/evidence

# Autopsy / Sleuth Kit
fls -r image.dd              # List files recursively
icat image.dd <inode>        # Extract file by inode

# Carving deleted files
photorec image.dd
foremost -i image.dd
```

---

## VM Forensics (OVA/VMDK)

```bash
# OVA = TAR archive containing VMDK + OVF
tar -xvf machine.ova

# 7z reads VMDK directly (no mount needed)
7z l disk.vmdk | head -100
7z x disk.vmdk -oextracted "Windows/System32/config/SAM" -r
```

**Key files to extract from VM images:**
- `Windows/System32/config/SAM` - Password hashes
- `Windows/System32/config/SYSTEM` - Boot key
- `Windows/System32/config/SOFTWARE` - Installed software
- `Users/*/NTUSER.DAT` - User registry
- `Users/*/AppData/` - Browser data, credentials

---

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
vol3 -f memory.dmp windows.mftscan | grep flag
# mtime as Unix epoch → seed for PRNG → derive encryption key
```

---

## Coredump Analysis

```bash
gdb -c core.dump
(gdb) info registers
(gdb) x/100x $rsp
(gdb) find 0x0, 0xffffffff, "flag"
```

---

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

---

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

---

## GPT Partition GUID Data Encoding (VuwCTF 2025)

**Pattern (Undercut):** "LLMs only" + "undercut" → not AI GPT, but GUID Partition Table.

**Key insight:** GPT partition GUIDs are 16 arbitrary bytes — can encode anything. Look for file magic headers in GUIDs.

```bash
# Parse GPT partition table
gdisk -l image.img
# Or with Python:
python3 -c "
import struct
data = open('image.img','rb').read()
# GPT header at LBA 1 (offset 512)
# Partition entries start at LBA 2 (offset 1024)
# Each entry is 128 bytes, GUID at offset 16 (16 bytes)
for i in range(128):
    entry = data[1024 + i*128 : 1024 + (i+1)*128]
    guid = entry[16:32]
    if guid != b'\x00'*16:
        print(f'Partition {i}: {guid.hex()}')
"
```

**First GUID starts with `BZh11AY&SY`** (bzip2 magic) → concatenate GUIDs, decompress as bzip2, then decode ASCII85.

---

## Windows Minidump String Carving (0xFun 2026)

**Pattern (kd):** Go binary crash dump. Flag as plaintext string constant in .data section survives in minidump memory.

```bash
strings -a minidump.dmp | grep -i "flag\|ctf\|0xFUN"
```

**Lesson:** Minidumps contain full memory regions. String constants, keys, and secrets persist. `strings -a` + `grep` is the fast path.

---

## VMDK Sparse Parsing (0xFun 2026)

**Pattern (VMware):** Split sparse VMDK requires grain directory + grain table traversal.

**Key steps:**
1. Parse VMDK sparse header (grain size, GD offset, GT coverage)
2. Follow grain directory → grain table → data grains
3. Calculate absolute disk offsets across split files
4. Mount extracted filesystem (ext4, NTFS)

**Lesson:** Don't assume VM images can be mounted directly. Parse the VMDK sparse format manually.

---

## Memory Dump String Carving (Pragyan 2026)

**Pattern (c47chm31fy0uc4n):** Linux memory dump with flag in environment variables or process data.

```bash
strings -a -n 6 memdump.bin | grep -E "SYNC|FLAG|SSH_CLIENT|SESSION_KEY"
# SSH artifacts reveal source IP and ephemeral port
# Environment variables may contain keys/tokens
```

---

## Memory Dump Malware Extraction + XOR (VuwCTF 2025)

**Pattern (Jellycat):** Extract fake executable from Windows memory dump. Cipher: subtract 0x32, then XOR with cycling key (large multi-line string, e.g., ASCII art).

**Key lesson:** Always extract and reverse the actual binary from memory rather than trusting `strings` output (string tables may be red herrings). XOR keys can be hundreds of bytes (ASCII art, lorem ipsum).

```python
# Extract binary, find XOR key in data section
key = b"..."  # Large ASCII art string
cipher = open('extracted.bin', 'rb').read()
plaintext = bytes((b - 0x32) ^ key[i % len(key)] for i, b in enumerate(cipher))
```

---

## Linux Ransomware Memory-Key Recovery (MetaCTF 2026)

**Pattern:** Linux memory dump + encrypted `.veg` files + `enc_key.bin`; ransomware uses hybrid crypto (AES for files, RSA-wrapped key). Volatility may fail process enumeration due symbol/KASLR (Kernel Address Space Layout Randomization) mismatch.

**Fast workflow:**
1. **Confirm archive integrity before analysis.**
```bash
unzip -l encrypted_files.zip
# Compare listed files/sizes vs extracted tree; re-extract cleanly if mismatch
unzip -o encrypted_files.zip -d encrypted_full
```

2. **Reverse ransomware binary quickly to identify mode/layout.**
```bash
strings -a ransomware.elf | grep -E "enc_key|EVP_aes|PUBLIC KEY|.veg"
objdump -d ransomware.elf | less
```
- Typical finding: `AES-256-OFB`, IV prepended to each `.veg`, global 32-byte AES key, RSA public key hardcoded.

3. **Try Volatility normally, then pivot immediately if empty/unstable.**
```bash
vol -f memdump.raw linux.pslist
vol -f memdump.raw linux.proc.Maps
vol -f memdump.raw linux.vmayarascan
```
- If Linux plugins return empty/invalid output despite correct banner/symbols, do **raw-memory candidate scanning**.

4. **Recover AES key via anchored candidate scan + magic validation.**
- Use recurring anchor strings in memory (e.g., `/home/.../enc_key.bin`, HOME path).
- Derive candidate offsets near anchors (page-aligned windows).
- Test each 32-byte candidate by decrypting first blocks of multiple `.veg` files and checking magic bytes (`%PDF-`, `PK\x03\x04`, `\x89PNG\r\n\x1a\n`).
- Keep candidates that satisfy multiple independent signatures.

5. **Decrypt full dataset and verify output completeness.**
```bash
# OFB: iv = first 16 bytes, ciphertext starts at +16
# Decrypt all *.veg recursively from a clean extraction directory
```
- Validate recovered file count against zip listing.
- Watch for duplicated mirror trees (e.g., `snap/*/Downloads/...`) and deduplicate logically.

6. **Defend against false flags.**
- Treat metadata-only flags as suspicious until corroborated by challenge context.
- Prefer tokens from primary project artifacts and perform uniqueness checks:
```bash
rg -n -a '[A-Za-z]+CTF\\{[^}]+\\}' recovered_full
pdftotext recovered_full/**/*.pdf - 2>/dev/null | rg '[A-Za-z]+CTF\\{'
```

**Key lessons:**
- Don’t trust a partial/stale extraction tree; re-extract zip cleanly.
- In OFB ransomware, magic-byte validation is a fast key oracle.
- A plausible `CTF{...}` in metadata can be a decoy; confirm with corpus-wide consistency.

---

## WordPerfect Macro XOR Extraction (srdnlenCTF 2026)

**Pattern (Trilogy of Death Vol I: Corel):** Corel Linux disk image containing WordPerfect macro file (fc.wcm) with XOR-encrypted byte arrays.

**Key insight:** WordPerfect macro files (`.wcm`) can contain executable macros with embedded encrypted data. The XOR formula `(bb + kb) - 2*(bb & kb)` is mathematically equivalent to bitwise XOR.

**Brute-force 4-byte XOR key under charset constraints:**
```python
import string

docbody = [206, 56, 8, 128, 209, 47, 2, 149, ...]  # encrypted bytes from macro
allowed = set(map(ord, string.ascii_lowercase + string.digits + "_{}"))

# Find valid key bytes independently for each position mod 4
cands = []
for j in range(4):
    good = []
    for k in range(256):
        if all((docbody[i] ^ k) in allowed for i in range(j, len(docbody), 4)):
            good.append(k)
    cands.append(good)

# Try all combinations (usually very few candidates per position)
for k0 in cands[0]:
    for k1 in cands[1]:
        for k2 in cands[2]:
            for k3 in cands[3]:
                key = [k0, k1, k2, k3]
                pt = ''.join(chr(c ^ key[i % 4]) for i, c in enumerate(docbody))
                if pt.startswith("srd") and pt.endswith("}"):
                    print(pt)
```

**Lesson:** Legacy document formats (WordPerfect, Lotus 1-2-3) can embed executable macros with obfuscated data. When you know the flag charset, brute-forcing a short XOR key is trivial by filtering each key byte independently.

---

## Minidump ISO 9660 Recovery + XOR Key (srdnlenCTF 2026)

**Pattern (Trilogy of Death Vol II: The Legendary Armory):** Two relics in volatile memory (minidump) must be XORed; ISO 9660 directory entries in memory fragments point to hidden data.

**Technique:**
1. Search minidump for ISO 9660 directory entry signatures
2. Parse directory entries to locate target file offset and size
3. Decrypt file using recovered XOR key (e.g., 8-byte repeating key)
4. Parse resulting data as ZIP without central directory (local headers only)

**ZIP local header parsing without central directory:**
```python
import struct, zlib

pos = 0
files = {}
while True:
    off = dec.find(b"PK\x03\x04", pos)
    if off < 0:
        break
    (ver, flag, method, _, _, crc, csize, usize, nlen, xlen) = struct.unpack_from(
        "<HHHHHIIIHH", dec, off + 4)
    name = dec[off + 30:off + 30 + nlen].decode()
    data_off = off + 30 + nlen + xlen
    comp = dec[data_off:data_off + csize]
    if method == 8:  # Deflate
        raw = zlib.decompress(comp, -15)
    else:
        raw = comp
    files[name] = raw
    pos = data_off + csize
```

**Key insight:** When ZIP central directory is missing/corrupt, iterate local file headers (`PK\x03\x04`) directly. Each local header contains enough metadata (compression method, sizes, filename) to extract files independently.

---

## APFS Snapshot Historical File Recovery (srdnlenCTF 2026)

**Pattern (Trilogy of Death Vol III: The Poisoned Apple):** APFS volume maintains historical snapshots; recovering earlier state of a key file reveals authentic value before poisoning.

**Technique:**
1. Extract APFS partition from DMG (locate by sector offset)
2. Search for APFS volume superblocks (magic `APSB`) across all snapshots, noting transaction IDs (XIDs)
3. Use `icat` (Sleuth Kit with APFS support) to read specific inodes across different snapshot XIDs
4. Compare file content across XID boundaries to identify when poisoning occurred
5. Use pre-poisoning value for decryption

**Finding APFS volume superblocks across snapshots:**
```python
import struct

with open("apfs_partition.img", "rb") as f:
    mm = f.read()

snaps = []
pos = 0
while True:
    idx = mm.find(b"APSB", pos)
    if idx < 0:
        break
    # XID is at offset -16 from magic (in block header)
    hdr_start = idx - 32
    xid = struct.unpack_from("<Q", mm, hdr_start + 16)[0]
    blk = hdr_start // 4096
    snaps.append((xid, blk))
    pos = idx + 1

# Read target inode across snapshots
import subprocess
for xid, blk in sorted(set(snaps)):
    try:
        out = subprocess.check_output(
            ["icat", "-f", "apfs", "-P", "apfs", "-B", str(blk),
             "apfs_partition.img", "449414"])  # target inode number
        print(f"XID {xid}: {out[:64]}...")
    except:
        pass
```

**Decryption with recovered authentic key:**
```python
import hashlib
from Cryptodome.Cipher import AES

# Pre-poisoning key value (found in earlier snapshot)
authentic_key_hex = "39f520679fd68654500f9cd44e8caed2bc897a3227dc297c4520336de2a59dd7"
key = hashlib.pbkdf2_hmac('sha256', bytes.fromhex(authentic_key_hex), salt, iterations)
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(encrypted_flag)
```

**Key insight:** APFS (and other copy-on-write filesystems like ZFS/Btrfs) preserve historical file states in snapshots. When a challenge involves "poisoned" or "tampered" data, always check for older snapshots containing the original values. Use `icat` with different block offsets to read the same inode across different transaction IDs.

---

## RAID 5 Disk Recovery via XOR (Crypto-Cat)

**Pattern:** RAID 5 array with one damaged/missing disk. Two working disks are provided and the third must be reconstructed using XOR parity.

**How RAID 5 parity works:** Data is striped across N disks with distributed parity. For any stripe, `Disk1 XOR Disk2 XOR ... XOR DiskN = 0`. If one disk is missing, XOR the remaining disks to recover it.

**Recovery script:**
```python
# Recover missing disk2 from disk1 and disk3
with open('disk1.img', 'rb') as f:
    disk1 = f.read()
with open('disk3.img', 'rb') as f:
    disk3 = f.read()

# XOR byte-by-byte to recover the missing disk
disk2 = bytes(a ^ b for a, b in zip(disk1, disk3))

with open('disk2.img', 'wb') as f:
    f.write(disk2)
```

**After recovery:**
```bash
# Reassemble the RAID array
mdadm --create /dev/md0 --level=5 --raid-devices=3 \
  disk1.img disk2.img disk3.img

# Or mount individual recovered disk if it contains a filesystem
mount -o loop,ro disk2.img /mnt/recovered
```

**Key insight:** RAID 5 uses XOR parity across all disks in each stripe. XOR is self-inverse: if `A XOR B XOR C = 0`, then `B = A XOR C`. For N-disk RAID 5, XOR all N-1 working disks together to recover the missing one.

**Detection:** Challenge provides multiple disk images of identical size, mentions "array", "redundancy", or "parity". `file` command may identify them as filesystem images or raw data.

---

## Windows KAPE Triage Analysis (UTCTF 2026)

**Pattern (Landfall, Sherlockk, Cold Workspace):** KAPE (Kroll Artifact Parser and Extractor) triage collection ZIP containing Windows forensic artifacts. Multiple challenges reference the same triage dataset.

**KAPE triage structure:**
```text
Modified_KAPE_Triage_Files/
├── C/
│   ├── Users/<username>/
│   │   ├── AppData/Local/Microsoft/Windows/PowerShell/PSReadLine/
│   │   │   └── ConsoleHost_history.txt    # PowerShell command history
│   │   ├── NTUSER.DAT                     # User registry hive
│   │   └── AppData/Roaming/Microsoft/Windows/Recent/  # Recent files
│   ├── Windows/
│   │   ├── System32/config/
│   │   │   ├── SAM          # Password hashes
│   │   │   ├── SYSTEM       # System config + boot key
│   │   │   └── SOFTWARE     # Installed software
│   │   └── appcompat/Programs/
│   │       └── Amcache.hve  # Execution history with SHA-1 hashes
│   └── $MFT                 # Master File Table
└── ...
```

**High-value artifacts:**

1. **PowerShell history** — reveals attacker commands:
```bash
cat "C/Users/*/AppData/Local/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"
# Look for: credential access, lateral movement, data staging
```

2. **Amcache** — executed programs with timestamps and hashes:
```bash
# Parse with Eric Zimmerman's AmcacheParser or regipy
python3 -c "
from regipy.registry import RegistryHive
reg = RegistryHive('C/Windows/appcompat/Programs/Amcache.hve')
for entry in reg.recurse_subkeys(as_json=True):
    print(entry)
" | grep -i "flag\|suspicious\|malware"
```

3. **MFT resident data** — small files stored directly in MFT records:
```python
# Parse MFT for resident file data (files < ~700 bytes stored inline)
# Use analyzeMFT or python-ntfs
import struct

with open('$MFT', 'rb') as f:
    mft_data = f.read()

# Search for flag patterns in raw MFT data
import re
flags = re.findall(rb'utflag\{[^}]+\}', mft_data)
for flag in flags:
    print(f"Found: {flag.decode()}")
```

4. **Environment variables from memory dumps** (Cold Workspace pattern):
```bash
# Small .dmp files may be minidumps with environment variable blocks
strings -a cold-workspace.dmp | grep -i "flag\|password\|key\|secret"
# Environment variables survive in process memory snapshots
```

**Challenge patterns from UTCTF 2026:**
- **Landfall:** Flag hidden in PowerShell history or Amcache execution records
- **Sherlockk:** Correlate Amcache entries with MFT timestamps to identify malicious activity
- **Cold Workspace:** Flag in environment variables extracted from memory dump
- **Checkpoint A/B:** Multi-part investigation using combined artifacts

**Key insight:** KAPE triage ZIPs contain pre-collected forensic artifacts — no need for full disk imaging. Start with PowerShell history (fastest wins) → Amcache (execution timeline) → MFT (resident data for small files) → registry hives (persistence, credentials).

---

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

---

### Android Forensics

```bash
# Extract APK from device
adb pull /data/app/com.target.app/base.apk

# Analyze APK contents
apktool d base.apk -o decompiled/
# Check: AndroidManifest.xml, res/values/strings.xml, shared_prefs/

# Extract data from Android backup
adb backup -apk -shared -all -f backup.ab
java -jar abe.jar unpack backup.ab backup.tar
tar xf backup.tar

# SQLite databases (contacts, messages, browser history)
sqlite3 /data/data/com.android.providers.contacts/databases/contacts2.db ".tables"
sqlite3 /data/data/com.android.providers.telephony/databases/mmssms.db "SELECT * FROM sms"

# Parse Android filesystem image
mkdir android_mount && mount -o ro android_image.img android_mount/
# Key locations:
# /data/data/<app>/databases/     — app SQLite databases
# /data/data/<app>/shared_prefs/  — app preferences (XML)
# /data/system/packages.xml       — installed packages
# /data/misc/wifi/wpa_supplicant.conf — saved WiFi passwords
```

**Key insight:** Android stores app data in `/data/data/<package>/` with SQLite databases and XML shared preferences. `adb backup` captures the full app state. For CTFs, check `shared_prefs/` for hardcoded secrets and `databases/` for flags.

---

### Container Forensics (Docker)

```bash
# Export Docker image layers
docker save IMAGE:TAG -o image.tar
tar xf image.tar
# Each layer is a directory with layer.tar containing filesystem changes
# Check: layer.tar files for added/modified files, deleted files (.wh.* whiteout)

# Inspect image history for build commands (may contain secrets)
docker history IMAGE:TAG --no-trunc
# Shows every Dockerfile instruction including ARGs and ENV values

# Extract filesystem without running the container
docker create --name extract IMAGE:TAG
docker export extract -o container_fs.tar
docker rm extract

# Analyze with dive (layer-by-layer diff viewer)
dive IMAGE:TAG

# Common forensic targets in container images:
# /app/.env, /app/config/* — application secrets
# /root/.bash_history     — build-time commands
# /etc/shadow             — leaked credentials
# Deleted files visible in earlier layers even if removed in later ones
```

**Key insight:** Docker images are layered — a file deleted in a later layer still exists in the earlier layer's tar. Use `docker history --no-trunc` to see full Dockerfile commands including secrets passed via `ARG` or `ENV`. The `dive` tool visualizes layer diffs interactively.

---

### Cloud Storage Forensics (AWS S3 / GCP / Azure)

```bash
# Enumerate public S3 buckets
aws s3 ls s3://target-bucket/ --no-sign-request
aws s3 cp s3://target-bucket/flag.txt . --no-sign-request

# Check bucket versioning (previous versions may contain deleted flags)
aws s3api list-object-versions --bucket target-bucket --no-sign-request
aws s3api get-object --bucket target-bucket --key secret.txt --version-id VERSION_ID out.txt

# GCP Cloud Storage
gsutil ls gs://target-bucket/
gsutil cp gs://target-bucket/flag.txt .

# Azure Blob Storage
az storage blob list --container-name target --account-name storageaccount
az storage blob download --container-name target --name flag.txt --account-name storageaccount
```

**Key insight:** Cloud storage versioning preserves deleted objects. Even if a flag file is deleted from the bucket, previous versions may still be accessible via `list-object-versions`. Always check for versioning-enabled buckets.

---

## See Also

- [disk-recovery.md](disk-recovery.md) - Disk recovery and extraction patterns (LUKS master key recovery, PRNG timestamp seed brute-force, VBA macro binary recovery, FemtoZip decompression, XFS reconstruction, tar duplicate entry extraction, nested matryoshka filesystem extraction, anti-carving via null byte interleaving)
