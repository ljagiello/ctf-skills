---
name: ctf-forensics
description: Digital forensics and blockchain analysis for CTF challenges. Use when analyzing disk images, memory dumps, event logs, network captures, or cryptocurrency transactions.
license: MIT
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Forensics & Blockchain

Quick reference for forensics CTF challenges. Each technique has a one-liner here; see supporting files for full details.

## Additional Resources

- [3d-printing.md](3d-printing.md) - 3D printing forensics (PrusaSlicer binary G-code, QOIF, heatshrink)
- [windows.md](windows.md) - Windows forensics (registry, SAM, event logs, recycle bin, USN journal, PowerShell history, Defender MPLog, WMI persistence, Amcache)
- [network.md](network.md) - Network forensics (PCAP, SMB3, WordPress, credentials, NTLMv2 cracking)
- [disk-and-memory.md](disk-and-memory.md) - Disk/memory forensics (Volatility, disk mounting/carving, VM/OVA/VMDK, coredumps, deleted partitions, ZFS, VMware snapshots, ransomware analysis)
- [steganography.md](steganography.md) - Steganography (binary border stego, PDF multi-layer stego, FFT frequency domain, DTMF audio decoding)
- [linux-forensics.md](linux-forensics.md) - Linux/app forensics (log analysis, Docker image forensics, attack chains, browser credentials, Firefox history, TFTP, TLS weak RSA, USB audio)

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

See [disk-and-memory.md](disk-and-memory.md) for full Volatility plugin reference, VM forensics, and coredump analysis.

## Log Analysis

```bash
grep -iE "(flag|part|piece|fragment)" server.log     # Flag fragments
grep "FLAGPART" server.log | sed 's/.*FLAGPART: //' | uniq | tr -d '\n'  # Reconstruct
sort logfile.log | uniq -c | sort -rn | head         # Find anomalies
```

See [linux-forensics.md](linux-forensics.md) for Linux attack chain analysis and Docker image forensics.

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

See [windows.md](windows.md) for full event ID tables, registry analysis, SAM parsing, USN journal, and anti-forensics detection.

## When Logs Are Cleared

If attacker cleared event logs, use these alternative sources:
1. **USN Journal ($J)** - File operations timeline (MFT ref, timestamps, reasons)
2. **SAM registry** - Account creation from key last_modified timestamps
3. **PowerShell history** - ConsoleHost_history.txt (USN DATA_EXTEND = command timing)
4. **Defender MPLog** - Separate log with threat detections and ASR events
5. **Prefetch** - Program execution evidence
6. **User profile creation** - First login time (profile dir in USN journal)

See [windows.md](windows.md) for detailed parsing code and anti-forensics detection checklist.

## Steganography

```bash
steghide extract -sf image.jpg
zsteg image.png              # PNG/BMP analysis
stegsolve                    # Visual analysis
```

- **Binary border stego:** Black/white pixels in 1px image border encode bits clockwise
- **FFT frequency domain:** Image data hidden in 2D FFT magnitude spectrum; try `np.fft.fft2` visualization
- **DTMF audio:** Phone tones encoding data; decode with `multimon-ng -a DTMF`
- **Multi-layer PDF:** Check hidden comments, post-EOF data, XOR with keywords, ROT18 final layer

See [steganography.md](steganography.md) for full code examples and decoding workflows.

## PDF Analysis

```bash
exiftool document.pdf        # Metadata (often hides flags!)
pdftotext document.pdf -     # Extract text
strings document.pdf | grep -i flag
binwalk document.pdf         # Embedded files
```

**Advanced PDF stego (Nullcon 2026 rdctd):** Six techniques -- invisible text separators, URI annotations with escaped braces, Wiener deconvolution on blurred images, vector rectangle QR codes, compressed object streams (`mutool clean -d`), document metadata fields.

See [steganography.md](steganography.md) for full PDF steganography techniques and code.

## Disk Image Analysis

```bash
sudo mount -o loop,ro image.dd /mnt/evidence   # Mount read-only
fls -r image.dd              # List files (Sleuth Kit)
icat image.dd <inode>        # Extract by inode
photorec image.dd            # Carve deleted files
foremost -i image.dd         # Alternative carver
```

See [disk-and-memory.md](disk-and-memory.md) for VM forensics (OVA/VMDK), deleted partition recovery, and ZFS forensics.

## VM Forensics (OVA/VMDK)

```bash
tar -xvf machine.ova                                    # OVA = TAR archive
7z l disk.vmdk | head -100                               # List VMDK contents
7z x disk.vmdk -oextracted "Windows/System32/config/SAM" -r  # Extract specific files
```

See [disk-and-memory.md](disk-and-memory.md) for VMware snapshot conversion and malware hunting.

## Memory Forensics

```bash
vol3 -f memory.dmp windows.pslist     # Process list
vol3 -f memory.dmp windows.cmdline    # Command lines
vol3 -f memory.dmp windows.netscan    # Network connections
vol3 -f memory.dmp windows.dumpfiles --physaddr <addr>  # Extract files
```

- **String carving:** `strings -a -n 6 memdump.bin | grep -E "FLAG|SSH_CLIENT|SESSION_KEY"`
- **VMware snapshots:** `vmss2core -W snapshot.vmss snapshot.vmem` to get analyzable dump

See [disk-and-memory.md](disk-and-memory.md) for full plugin reference, ransomware analysis, and MFT key recovery.

## Windows Password Hashes

```python
from impacket.examples.secretsdump import LocalOperations, SAMHashes
localOps = LocalOperations('SYSTEM')
bootKey = localOps.getBootKey()
sam = SAMHashes('SAM', bootKey)
sam.dump()  # username:RID:LM:NTLM:::
```

```bash
hashcat -m 1000 hashes.txt wordlist.txt   # Crack NTLM
```

See [windows.md](windows.md) for SAM database details and [network.md](network.md) for NTLMv2 cracking from PCAP.

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

See [disk-and-memory.md](disk-and-memory.md) for more details.

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

## WMI Persistence Analysis

**Pattern (Backchimney):** Malware uses WMI event subscriptions for persistence (MITRE T1546.003).

```bash
python PyWMIPersistenceFinder.py OBJECTS.DATA
```

- Look for FilterToConsumerBindings with CommandLineEventConsumer
- Base64-encoded PowerShell in consumer commands
- Event filters triggered on system events (logon, timer)

See [windows.md](windows.md) for WMI repository analysis details.

## Network Forensics Quick Reference

- **TFTP netascii:** Binary transfers corrupted; fix with `data.replace(b'\r\n', b'\n').replace(b'\r\x00', b'\r')`
- **TLS weak RSA:** Extract cert, factor modulus, generate private key with `rsatool`, add to Wireshark
- **USB audio:** Extract isochronous data with `tshark -e usb.iso.data`, import as raw PCM in Audacity
- **NTLMv2 from PCAP:** Extract server challenge + NTProofStr + blob from NTLMSSP_AUTH, brute-force

See [network.md](network.md) for SMB3 decryption, credential extraction, and [linux-forensics.md](linux-forensics.md) for full TLS/TFTP/USB workflows.

## Browser Forensics

- **Chrome/Edge:** Decrypt `Login Data` SQLite with AES-GCM using DPAPI master key
- **Firefox:** Query `places.sqlite` -- `SELECT url FROM moz_places WHERE url LIKE '%flag%'`

See [linux-forensics.md](linux-forensics.md) for full browser credential decryption code.

## Docker Image Forensics

**Key insight:** Config JSON preserves ALL `RUN` commands in `history` array, even if later layers clean up.

```bash
tar xf app.tar
python3 -m json.tool blobs/sha256/<config_hash> | grep -A2 "created_by"
```

See [linux-forensics.md](linux-forensics.md) for detailed Docker layer analysis.

## Linux Attack Chain Forensics

Check `auth.log`, `.bash_history`, recently modified binaries, and PCAP for exfiltration. Common malware pattern: AES-ECB + XOR with same key.

See [linux-forensics.md](linux-forensics.md) for full evidence source commands.

## PowerShell Ransomware Analysis

Extract script blocks from minidump (`power_dump.py`), find AES key via regex in strings, decrypt SMTP attachment from PCAP.

See [disk-and-memory.md](disk-and-memory.md) for full analysis workflow.

## Deleted Partition Recovery

`testdisk` or `kpartx -av` to recover partition table from image. Check hidden `.dotfolders` for flag path components.

See [disk-and-memory.md](disk-and-memory.md) for full recovery workflow.

## ZFS Forensics

Corrupted ZFS pool: reconstruct labels from nvlist data, recompute Fletcher4 checksums, crack PBKDF2 encryption with GPU.

See [disk-and-memory.md](disk-and-memory.md) for Fletcher4 code and full recovery workflow.

## Common Encodings

```bash
echo "base64string" | base64 -d
echo "hexstring" | xxd -r -p
# ROT13: tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

**ROT18:** ROT13 on letters + ROT5 on digits. Common final layer in multi-stage forensics. See [linux-forensics.md](linux-forensics.md) for implementation.
