# Shellbags and UserAssist

## When this applies

You need to prove a user opened/browsed a folder (Shellbags) or executed a GUI application (UserAssist), even if the file/folder was later deleted. Both artifacts live in `NTUSER.DAT` / `UsrClass.dat` and survive normal cleanup.

## Technique

- **Shellbags** record Explorer view-state (window size, sort order) per folder the user navigated to, including network shares and removed external drives. Stored in `HKCU\Software\Microsoft\Windows\Shell\BagMRU` and `HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`.
- **UserAssist** logs program execution from the user's GUI shell — start menu launches, taskbar pins, double-clicks. Stored ROT13-encoded under `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`.

## Steps

1. Acquire hives (live or from collected NTUSER.DAT):
   ```bash
   reg save HKCU C:\evidence\NTUSER.DAT
   # Or pull NTUSER.DAT and UsrClass.dat from %USERPROFILE% / AppData\Local\Microsoft\Windows
   ```
2. Shellbag parse:
   ```bash
   sbecmd.exe -f NTUSER.DAT --csv ./out               # Eric Zimmerman
   # or:
   shellbags.py NTUSER.DAT > shellbags.txt            # libregf-based
   ```
   Output: path, MFT inode (when local), first/last interaction times, MRU position.
3. UserAssist parse:
   ```bash
   RECmd.exe --bn UserAssist.reb -f NTUSER.DAT --csv ./out
   # Manual rot13 example:
   python3 -c "import codecs; print(codecs.decode('Z:\\Sb\\one.rkr', 'rot13'))"
   ```
4. Pivot on a target path:
   ```bash
   grep -i 'Z:\\\|\\Public\\\|\\Temp\\' shellbags.txt
   ```
5. Cross-correlate UserAssist run count + last-execution time with Prefetch and AmCache.
6. Removable media browsing — look for shellbags entries under `Computer\<drive_letter>:\` referencing volumes whose `Volume{GUID}` is unknown to the SYSTEM hive.

## Verifying success

- Shellbag entry references the suspect path, with first/last access in the incident window.
- UserAssist count > 0 for an attacker tool, ROT13-decoded to a recognizable name.
- Times correlate with Prefetch run times and EVTX logon ranges.

## Common pitfalls

- Shellbags do not require the file to currently exist. Don't claim "user accessed file X" — say "user navigated to folder containing path X at time T".
- UserAssist is GUI-only. Tools launched via cmd, scripts, services, or remote (psexec) do **not** appear. Use 4688/Sysmon-1 for those.
- ROT13 encoding only obscures the value name (the program path), not the timestamp/count blob.
- WSL-launched programs and Store apps appear with different GUIDs (`{B267E3AD-...}` vs `{F4E57C4B-...}`); enumerate all subkeys.
- On reimage / profile recreation, both artifacts are reset. Check profile creation time before concluding non-execution.

## Tools

- `sbecmd` / `RECmd` (Eric Zimmerman)
- `Registry Explorer` (GUI Registry hive viewer)
- `regripper` plugins: `userassist`, `shellbags`, `shellbags_xp`
- `python-registry`, `libregf` for scripted parsing
