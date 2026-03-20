# CTF Forensics - Disk Recovery and Extraction Patterns

## Table of Contents
- [LUKS Master Key Recovery from Memory Dump (Hack.lu 2015)](#luks-master-key-recovery-from-memory-dump-hacklu-2015)
- [PRNG Timestamp Seed Brute-Force for Encryption Key Recovery (CSAW 2015)](#prng-timestamp-seed-brute-force-for-encryption-key-recovery-csaw-2015)
- [VBA Macro Encoded Binary Recovery (Sharif CTF 2016)](#vba-macro-encoded-binary-recovery-sharif-ctf-2016)
- [FemtoZip Shared Dictionary Decompression (Sharif CTF 2016)](#femtozip-shared-dictionary-decompression-sharif-ctf-2016)
- [XFS Filesystem Reconstruction from Corrupted Metadata (BSidesSF 2025)](#xfs-filesystem-reconstruction-from-corrupted-metadata-bsidessf-2025)
- [Tar Archive Duplicate Entry Extraction (BSidesSF 2025)](#tar-archive-duplicate-entry-extraction-bsidessf-2025)
- [Nested Matryoshka Filesystem Extraction (BSidesSF 2025)](#nested-matryoshka-filesystem-extraction-bsidessf-2025)
- [Anti-Carving via Null Byte Interleaving (BSidesSF 2024)](#anti-carving-via-null-byte-interleaving-bsidessf-2024)

---

## LUKS Master Key Recovery from Memory Dump (Hack.lu 2015)

Recover LUKS encryption keys from VM memory dumps using AES key schedule detection:

1. **Extract memory:** Obtain memory dump from VM snapshot (.elf, .vmem, .raw)
2. **Find AES keys:** Use `aeskeyfind` to detect AES key schedules in memory

```bash
aeskeyfind memory.elf
# Output: candidate AES-256 keys (64 hex chars each)
```

3. **Write key to file:** Convert hex key to binary

```bash
echo "deadbeef..." | xxd -r -p > master.key
```

4. **Add new LUKS passphrase using master key:**

```bash
cryptsetup luksAddKey --master-key-file master.key /dev/mapper/volume
# Enter new passphrase when prompted
cryptsetup luksOpen /dev/mapper/volume decrypted
mount /dev/mapper/decrypted /mnt
```

**Key insight:** AES key schedules have a distinctive mathematical structure that `aeskeyfind` detects regardless of where they appear in memory. Works for LUKS, dm-crypt, FileVault, and BitLocker volumes.

Companion tools: `rsakeyfind` (RSA keys), `aesfix` (corrupted key recovery).

---

## PRNG Timestamp Seed Brute-Force for Encryption Key Recovery (CSAW 2015)

When encryption keys are generated from PRNG seeded with timestamps, brute-force the seed:

1. **Identify seed source:** Look for `Time.now.to_i`, `time(NULL)`, `System.currentTimeMillis()` used as PRNG seed
2. **Determine time window:** Use file metadata (creation/modification timestamps) to bound the search
3. **Brute-force seeds:** Try each second in a +/-24 hour window around the file timestamp

```python
import struct
from Crypto.Cipher import AES

# Ruby-compatible Random implementation (or use ctypes for C rand)
for seed in range(timestamp - 86400, timestamp + 86400):
    rng = RandomWithSeed(seed)
    key = bytes([rng.rand(256) for _ in range(32)])  # AES-256
    iv = bytes([rng.rand(256) for _ in range(16)])

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    # Validate: check for known file signatures
    if plaintext[:4] == b'\x89PNG' or plaintext[:2] == b'\xff\xd8':
        print(f"Found key with seed: {seed}")
        break
```

**Key insight:** Expand the time window beyond the obvious timestamp -- clock skew, timezone differences, and filesystem granularity can shift the effective seed by hours.

---

## VBA Macro Encoded Binary Recovery (Sharif CTF 2016)

Excel/Word macros may encode binary data in cell values. Extract and decode:

1. **Extract macro:** Use `olevba` or open in LibreOffice to inspect VBA code
2. **Identify encoding:** Look for cell iteration patterns like `Cells(i, j).Value`
3. **Reverse the encoding formula:**

```python
# If macro encodes as: cell_value = byte_value * 3 + 78
# Reverse: byte_value = (cell_value - 78) // 3

import openpyxl
wb = openpyxl.load_workbook('challenge.xlsx')
ws = wb.active

binary_data = bytearray()
for row in ws.iter_rows():
    for cell in row:
        if cell.value is not None:
            binary_data.append((int(cell.value) - 78) // 3)

with open('recovered.elf', 'wb') as f:
    f.write(binary_data)
```

**Key insight:** Check the recovered file with `file` command -- common outputs are ELF binaries, PE executables, or images containing the flag.

---

## FemtoZip Shared Dictionary Decompression (Sharif CTF 2016)

FemtoZip uses a shared dictionary model for compressing corpora of similar documents. When given a `.model` file and compressed data:

```bash
# Install femtozip
git clone https://github.com/gtoubassi/femtozip
cd femtozip && make

# Decompress using provided model
./fzip --model fashion.model --decompress compressed_dir/ --output decompressed_dir/
```

After decompression, search through potentially thousands of files:

```bash
# Filter by metadata fields
grep -r "category.*forensic" decompressed_dir/ | grep "year.*2016"
```

**Key insight:** FemtoZip is rare in CTFs. Identify it by the `.model` file and the presence of many small compressed files that share common structure (JSON, XML templates).

---

## XFS Filesystem Reconstruction from Corrupted Metadata (BSidesSF 2025)

When XFS superblock or allocation group metadata is corrupted but inodes are intact:

1. **Parse inode directly:** XFS inodes contain extent lists with `[startoff, startblock, blockcount]` tuples
2. **Calculate block offsets:** Multiply startblock by filesystem block size (typically 4K)
3. **Extract file data:** Copy blocks directly from the raw disk image

```bash
# Extract file from known inode extent
# startblock=104333, blockcount=256, block_size=4096
dd if=disk.img bs=4096 skip=104333 count=256 of=recovered.jpg

# Parse XFS inode structure (at known offset)
python3 -c "
import struct
with open('disk.img', 'rb') as f:
    f.seek(inode_offset)
    magic = f.read(2)  # 'IN' = 0x494e
    # Parse di_core (96 bytes): mode, uid, gid, nlink, size, etc.
    # Parse extent list: each extent = 16 bytes
    # startoff (54 bits) | startblock (52 bits) | blockcount (21 bits)
"
```

**Key insight:** XFS stores extent maps inline in the inode (up to ~4 extents). For files with more extents, follow the B+tree root in the inode. Use `xfs_db` if available: `xfs_db -r disk.img` → `inode <num>` → `print`.

---

## Tar Archive Duplicate Entry Extraction (BSidesSF 2025)

Tar format allows multiple entries with the same filename. Standard extraction overwrites earlier entries, but specific occurrences can be targeted:

```bash
# List all entries (shows duplicates)
tar -tvf archive.tar.xz | grep -c '^\.'

# Extract specific occurrence (1-indexed)
tar -Jxvf archive.tar.xz '.' --occurrence=2 -O > second_entry.bin

# Extract all occurrences via file carving
binwalk -e archive.tar
# Or iterate programmatically
python3 -c "
import tarfile
with tarfile.open('archive.tar.xz') as tf:
    for i, member in enumerate(tf.getmembers()):
        if member.name == '.':
            data = tf.extractfile(member).read()
            with open(f'entry_{i}.bin', 'wb') as f:
                f.write(data)
"
```

**Key insight:** The `--occurrence=N` flag in GNU tar selects the Nth entry with a matching name. Without it, only the last entry survives extraction. Challenges may hide flags in middle entries that normal extraction skips.

---

## Nested Matryoshka Filesystem Extraction (BSidesSF 2025)

Disk images containing nested compressed filesystem layers (potentially 10-20+ levels deep):

```bash
#!/bin/bash
# Automated layer extraction
IMG="disk.img"
for i in $(seq 1 20); do
    echo "=== Layer $i ==="
    file "$IMG"

    # Detect and decompress
    case "$(file -b "$IMG")" in
        *XZ*)     xz -d "$IMG"; IMG="${IMG%.xz}" ;;
        *gzip*)   gunzip "$IMG"; IMG="${IMG%.gz}" ;;
        *ext4*)
            mkdir -p "layer_$i"
            sudo mount -o ro,loop "$IMG" "layer_$i"
            IMG=$(find "layer_$i" -type f -name "*.img" -o -name "*.xz" | head -1)
            ;;
        *ISO*|*HFS*|*XFS*|*AmigaDOS*)
            mkdir -p "layer_$i"
            sudo mount -o ro,loop "$IMG" "layer_$i" 2>/dev/null || \
            sudo mount -t affs -o ro,loop "$IMG" "layer_$i" 2>/dev/null
            IMG=$(find "layer_$i" -type f | head -1)
            ;;
    esac
done
```

Filesystem types encountered: ext4, XFS, HFS/HFS+, AFFS (AmigaDOS), FAT. Use `losetup` with `--offset` for partitioned images. Final layer typically contains an image or text file with the flag.

**Key insight:** Install uncommon filesystem drivers (`hfsplus`, `affs`) beforehand. Some layers require manual sector offset calculation when partition tables are absent.

---

## Anti-Carving via Null Byte Interleaving (BSidesSF 2024)

Files stored with null bytes inserted at every other position defeat magic-byte-based file carving tools (binwalk, foremost, scalpel):

1. **Identify anti-carving:** File carving finds nothing, but `xfs_db` or filesystem-level tools show the file exists with correct size
2. **Extract raw blocks:** Use filesystem extent information to locate file data

```bash
# XFS: find file extents
xfs_db -r disk.img -c 'inode <inum>' -c 'print'
# Extract extent data
dd if=disk.img bs=4096 skip=<startblock> count=<blockcount> of=raw.bin
```

3. **Remove interleaved null bytes:** Keep only even-positioned (or odd-positioned) bytes

```python
with open('raw.bin', 'rb') as f:
    data = f.read()
# Remove null bytes at odd positions
cleaned = bytes(data[i] for i in range(0, len(data), 2))
with open('recovered.png', 'wb') as f:
    f.write(cleaned)
```

```perl
# Perl one-liner equivalent
perl -0777 -pe 's/(.)./\1/gs' raw.bin > recovered.png
```

**Key insight:** When file carving fails but the filesystem metadata is intact, extract via block-level access and look for byte-level obfuscation patterns. Null byte interleaving doubles the file size — compare actual size vs expected size as a detection heuristic.

---

## See Also

- [disk-and-memory.md](disk-and-memory.md) - Disk image analysis, memory forensics (Volatility), VM/OVA/VMDK, coredumps, deleted partitions, ZFS, VMware snapshots, ransomware analysis, GPT GUID encoding, VMDK sparse parsing, APFS snapshots, KAPE triage, RAID 5 XOR recovery, Android/Docker/cloud forensics
