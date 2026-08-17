# LNK File Analysis

## When this applies

Investigating phishing payloads, recently-opened-document trails, USB device usage, and persistence shortcuts. LNK files are present (a) as malicious payloads (`Invoice.pdf.lnk`), (b) in `%APPDATA%\Microsoft\Windows\Recent\` and Office MRU folders, and (c) in startup folders for persistence.

## Technique

LNKs are MS-SHLLINK structured records. Each contains the target path (when present), volume serial number, MAC timestamps of the target at link creation, machine NetBIOS name, MAC address, drive type, and optional command-line arguments. Malicious LNKs often carry an `IconLocation` or `RelativePath` plus a hidden `Arguments` field invoking PowerShell/cmd.

## Steps

1. Inventory user-recent LNKs:
   ```cmd
   dir /s /b "%APPDATA%\Microsoft\Windows\Recent\*.lnk"
   dir /s /b "%APPDATA%\Microsoft\Office\Recent\*.lnk"
   dir /s /b "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk"
   ```
2. Parse with LECmd:
   ```bash
   LECmd.exe -d C:\evidence\Recent --csv ./out --csvf lnk.csv
   ```
   Useful columns: `TargetCreated`, `TargetModified`, `TargetAccessed`, `TargetMftEntryNumber`, `LocalPath`, `NetworkPath`, `MachineId`, `VolumeSerialNumber`, `Arguments`, `IconLocation`.
3. Cross-platform parse:
   ```bash
   pip install pylnk3
   python3 -c "import pylnk3 as l; print(l.parse('Invoice.lnk'))"
   ```
4. Phishing-LNK red flags:
   - Target = `cmd.exe` / `powershell.exe` / `mshta.exe` / `wscript.exe` with long `Arguments`
   - `IconLocation` pointing to a non-related EXE (PDF/Word icon spoofing)
   - `RelativePath` to a hidden file in the same folder (`%TEMP%`, `~$tmp\`)
   - Working directory set to `%TEMP%` or `%PUBLIC%`
5. USB / removable-media tracking:
   ```bash
   # Drive type field: 0 (unknown), 2 (removable), 3 (fixed), 4 (remote), 5 (CDROM)
   awk -F, '$X == 2' lnk.csv      # X = column index of DriveType
   ```
   `MachineId` (NetBIOS name) reveals which machine the file was originally accessed on.
6. Recover deleted-file metadata: even after the original file is gone, the LNK retains last known size, MFT inode, and timestamps — useful for proving prior existence.

## Verifying success

- `Arguments` field decodes a malicious command (PowerShell base64, mshta http URL, scripted downloader).
- `MachineId` matches a known machine in the environment (or is foreign — implies file authored on attacker host).
- Timestamps in the LNK align with EVTX user logon and document-open events.

## Common pitfalls

- LNKs can be created without ever opening the target. Don't claim "user opened file" without corroborating execution evidence.
- For attacker-crafted LNKs, the `MachineId` and `MAC address` fields **identify the attacker's build host** — this is one of few cases where a phishing artifact directly attributes to the operator. Save these.
- `Jumplists` (`AutomaticDestinations` / `CustomDestinations`) hold richer recent-file history than the Recent folder; LECmd handles both with `JLECmd`.
- Some LNKs use IDList only (no path) — extract the IDList shell items to recover the navigation chain.
- Long arguments may be truncated in some viewers; always parse with LECmd or pylnk3 for full payload.

## Tools

- `LECmd`, `JLECmd` (Eric Zimmerman) — full-fidelity Windows parser
- `pylnk3` — Python parser
- `lnkparse3` — alternative Python implementation
- `cyberchef` — quick decode of base64/PowerShell args from LNK Arguments field
