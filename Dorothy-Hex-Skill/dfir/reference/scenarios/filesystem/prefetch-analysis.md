# Windows Prefetch Analysis

## When this applies

You need program-execution evidence on a Windows system: did `mimikatz.exe` ever run, when, how many times, and what files did it open? Prefetch (`C:\Windows\Prefetch\*.pf`) is the canonical artifact for confirming execution.

## Technique

Windows creates a `.pf` file the first time an executable runs and updates it on each subsequent execution (up to 8 last-run timestamps in v30, or single timestamp in older formats). The file embeds: the program path hash, run count, last-N run times, and references to files/DLLs the program opened during initialization.

## Steps

1. Inventory:
   ```cmd
   dir C:\Windows\Prefetch\*.pf
   ```
   File name format: `EXENAME-HASHHEX.pf`. Hash is keyed on the executable path; same EXE in two paths produces two `.pf` files.
2. Parse on Windows analysis host:
   ```
   PECmd.exe -d C:\Windows\Prefetch --csv ./out
   # or:
   WinPrefetchView.exe -folder C:\Windows\Prefetch
   ```
3. Cross-platform parse (Win10 v30 with MAM compression):
   ```python
   import struct, datetime, re
   from dissect.util.compression import lzxpress_huffman
   data = open('TARGET.EXE-HASH.pf','rb').read()
   if data[:4] == b'MAM\x04':
       decomp_size = struct.unpack_from('<I', data, 4)[0]
       data = lzxpress_huffman.decompress(data[8:])
   # Last 8 run times at offset 80, 8 bytes each (FILETIME)
   epoch = datetime.datetime(1601,1,1)
   for i in range(8):
       ft = struct.unpack_from('<Q', data, 80 + i*8)[0]
       if ft:
           dt = epoch + datetime.timedelta(microseconds=ft//10)
           if 2000 < dt.year < 2030: print('Run:', dt)
   # Run count at offset 200 (v30)
   print('RunCount:', struct.unpack_from('<I', data, 200)[0])
   # File references — UTF-16LE strings inside the body
   for s in re.findall(b'(?:[\x20-\x7e]\x00){4,}', data):
       t = s.decode('utf-16-le','ignore')
       if any(k in t.upper() for k in ('\\USERS\\','\\TEMP\\','\\DOWNLOADS\\','.EXE','.DLL')):
           print('Ref:', t)
   ```
4. Cross-validate execution against MFT, EVTX 4688, and Sysmon Event 1.
5. To detect anti-forensics, look for `Prefetch\Layout.ini` deletion or `EnablePrefetcher=0`:
   ```cmd
   reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
   ```

## Verifying success

- `.pf` exists for the suspect binary and `RunCount >= 1`.
- Last-run timestamps fall within the incident window (UTC).
- File references include attacker tools' output paths or staged DLLs.

## Common pitfalls

- Modern Win10/11 have `MAM\x04` compression; pre-Win10 (v23) and Win7 (v17) are uncompressed — parser must dispatch on header.
- Server SKUs disable Prefetch by default (`EnablePrefetcher=0`); absence of `.pf` does NOT prove non-execution.
- SSD systems can disable Prefetch automatically. Check the registry value before drawing conclusions.
- `.pf` for the **same exe** at different paths (e.g. `\Users\Public\` vs `\AppData\Local\Temp\`) have different hashes — enumerate all hashes for the EXE name.
- Volume serial number is part of the hash on some Windows versions; same EXE on a different volume produces a different `.pf` even at the same path.

## Tools

- `PECmd` (Eric Zimmerman) — best in class
- `WinPrefetchView` (NirSoft)
- `prefetch-parser` (Python, Linux/Mac)
- `dissect.util.compression.lzxpress_huffman` — MAM\x04 decompressor
