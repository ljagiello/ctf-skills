# Injected Code Detection in Memory

## When this applies

You suspect a process has been hollowed, has injected shellcode, has a reflective DLL, or contains an unbacked executable region. Used to identify the implant when the parent EXE on disk is benign (Word, Outlook, browser).

## Technique

Look for memory regions whose protection, backing, and content are inconsistent with normal process layout: RWX pages, MZ/PE headers in private (non-image) regions, regions with no mapped file, and section virtual addresses that disagree with the on-disk PE. Volatility's `malfind` flags region-level anomalies; `hollowfind` (vol2) and per-process VAD enumeration confirm hollowing.

## Steps

1. Run `malfind` over the whole image:
   ```bash
   vol -f memory.raw windows.malfind > malfind.txt
   ```
   Each hit shows PID, ProcessName, virtual address, protection (typically `PAGE_EXECUTE_READWRITE`), and a hex/ASCII dump. Look for:
   - `4D 5A` (MZ) at the start → injected PE
   - `FC 48 83 E4 F0` / `FC E8 8F 00 00 00` → common shellcode prologues
   - `EB FE` (jmp $) or other infinite loops indicating unfinished payload
2. Dump the suspect region:
   ```bash
   vol -f memory.raw windows.vadinfo --pid 1234 | grep -i exec
   vol -f memory.raw windows.vaddump --pid 1234 --base 0x1A0000 -o ./out
   ```
3. Hollowing check — compare in-memory PE to on-disk PE:
   ```bash
   vol -f memory.raw windows.dlllist --pid 1234 | grep -i 'image base'
   # Dump full process image
   vol -f memory.raw windows.procdump --pid 1234 -o ./dumps
   # Compare entry point and section sizes against the file on disk
   ```
   Discrepancy in entry point, section count, or `.text` size indicates hollowing or reflective load.
4. Reflective DLL detection — look for executable VAD entries with no FileObject:
   ```bash
   vol -f memory.raw windows.vadwalk --pid 1234 | awk '$NF=="" && $4 ~ /EXECUTE/'
   ```
5. APC / thread injection — anomalous start addresses:
   ```bash
   vol -f memory.raw windows.threads --pid 1234
   # Threads whose StartAddress is in a private VAD (no module) are injected.
   ```
6. Validate by carving and triaging:
   ```bash
   file out/*.dmp
   # If MZ/PE, fix headers, then strings + capa + yara
   strings -el out/region.dmp | grep -iE 'http|cmd|powershell|cobalt|meterpreter'
   ```

## Verifying success

- `malfind` hit + corresponding `vadwalk` entry with no backing file + threads pointing into the region.
- Carved bytes are runnable in a sandbox or detected by `capa` / `yara` rules.
- Network plugin (`windows.netscan`) shows the same PID owning attacker-IP connections.

## Common pitfalls

- JIT engines (Java, .NET, V8) routinely allocate RWX pages. Filter by parent and by image — anomalies in `winword.exe` or `notepad.exe` are far more suspicious than in `chrome.exe`.
- Some packers (UPX, custom) leave benign-looking RWX regions; correlate with `procdump` + sandbox detonation.
- 32-on-64 (WoW64) processes have additional VAD layers; scan both x86 and x64 contexts.
- `malfind` only flags regions ≥ 4 KB. Tiny shellcode injected via APC may slip through; rely on `windows.threads` start-address checks.

## Tools

- `volatility3`: `windows.malfind`, `windows.vadinfo`, `windows.vaddump`, `windows.procdump`, `windows.threads`
- `volatility2`: `hollowfind`, `apihooks`, `psxview` (cross-source process visibility)
- `capa` — capability triage on dumped regions
- `yara` — IoC matching against carved bytes
- `MemProcFS` — `Files/proc/<pid>/vmemd/` mounts each VAD as a file
