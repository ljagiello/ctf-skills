# Volatility Process Analysis

## When this applies

You have a Windows or Linux memory dump (`.raw`, `.mem`, `.dmp`, `.lime`) and need to enumerate processes, find malicious children, identify hollow/injected processes, and pull command lines. Standard first step in memory forensics.

## Technique

Volatility 3 walks the kernel's process linked list (`_EPROCESS` doubly-linked) and renders trees, command lines, loaded DLLs, and injection signatures. Volatility 2 still works for older Windows kernels. The high-value plugins are `pslist`, `psscan`, `pstree`, `cmdline`, `dlllist`, and `malfind`.

## Steps

1. Identify image profile/symbols:
   ```bash
   # Volatility 3 — automatic ISF symbol resolution
   vol -f memory.raw windows.info
   # Volatility 2
   vol.py -f memory.raw imageinfo
   ```
2. Process enumeration (linked list):
   ```bash
   vol -f memory.raw windows.pslist
   ```
   Note PID, PPID, ImageFileName, CreateTime, ExitTime.
3. Detect unlinked / hidden processes — pool tag scan:
   ```bash
   vol -f memory.raw windows.psscan
   diff <(vol -f memory.raw windows.pslist | awk '{print $1,$2}' | sort) \
        <(vol -f memory.raw windows.psscan | awk '{print $1,$2}' | sort)
   # Entries in psscan but not pslist = hidden or terminated processes
   ```
4. Process tree (parent/child relationships):
   ```bash
   vol -f memory.raw windows.pstree
   # Look for cmd.exe spawned by office.exe, powershell with rare parents,
   # rundll32 with no DLL argument, conhost orphans.
   ```
5. Command lines:
   ```bash
   vol -f memory.raw windows.cmdline --pid 1234
   vol -f memory.raw windows.cmdline | grep -iE 'powershell|certutil|bitsadmin|encodedcommand'
   ```
6. Loaded DLLs:
   ```bash
   vol -f memory.raw windows.dlllist --pid 1234
   # Unsigned, unusual paths (\Users\Public\, \AppData\Local\Temp\) are suspicious
   ```
7. Injection / hollowing detection:
   ```bash
   vol -f memory.raw windows.malfind
   # Reports executable RWX pages with no backing file, MZ headers in heap regions
   vol -f memory.raw windows.hollowprocesses  # plugin or vol2 hollowfind
   ```
8. Linux equivalents: `linux.pslist`, `linux.pstree`, `linux.psaux`, `linux.bash` (recover bash history from memory).

## Verifying success

- `pslist` output is non-empty and shows expected system processes (System, smss.exe, csrss.exe, wininit.exe, services.exe, lsass.exe).
- For a finding, `psscan` discrepancy or `malfind` hit must reproduce on at least one independent indicator (cmdline, dlllist, network).
- Suspicious PID also appears in `windows.netscan` with attacker-IP connection.

## Common pitfalls

- Volatility 3 ISF symbol pack lookup hits the network on first run. Pre-cache with `vol --symbol-dirs ./symbols` for offline work.
- Profile mismatch (vol2) silently produces garbage. Always confirm `imageinfo` "Suggested Profile(s)" entropy — KDBG offset matching multiple profiles is a red flag.
- `malfind` false-positives on JIT engines (browsers, .NET CLR runtimes). Filter by parent process to remove noise.
- Windows 11 24H2 dumps require very recent vol3 + ISF symbols. Older builds will fail with "kernel symbols not found".
- Non-paged kernel pool corruption can hide processes from `psscan` too — look for orphan threads (`windows.thrdscan`) as a third source.

## Tools

- `volatility3` — `vol -f IMAGE windows.<plugin>`
- `volatility` (vol2) — fallback for very old kernels
- `MemProcFS` — filesystem-style mount of memory dump (browse `/sys/proc/<pid>/`)
- `LiME` (Linux), `winpmem` / `DumpIt` — acquisition before analysis
