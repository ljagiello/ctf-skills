# Sysmon Event Analysis

## When this applies

The host runs Sysinternals Sysmon and you need higher-fidelity process, network, and file telemetry than Security 4688 provides. Sysmon produces `Microsoft-Windows-Sysmon/Operational.evtx` with rich command-line, hash, parent, and image-load detail.

## Technique

Sysmon events are configuration-driven (default is "log nothing"). High-signal Event IDs and their purpose:

| ID | Name | Useful when |
|----|------|-------------|
| 1 | ProcessCreate | Always; primary execution timeline |
| 3 | NetworkConnect | Outbound connections per PID |
| 5 | ProcessTerminate | Pair with 1 for runtime |
| 7 | ImageLoad | Reflective DLL injection, unsigned DLL hunting |
| 8 | CreateRemoteThread | Process injection (CreateRemoteThread/QueueUserAPC) |
| 10 | ProcessAccess | LSASS access (mimikatz indicator) |
| 11 | FileCreate | Drop locations (`%TEMP%`, `\Public\`, ADS) |
| 12/13/14 | RegistryEvent | Persistence keys, RunMRU |
| 15 | FileCreateStreamHash | ADS detection (`:Zone.Identifier` and others) |
| 17/18 | PipeEvent | Named pipe creation/connect (lateral movement, IPC C2) |
| 22 | DnsQuery | Per-process DNS resolution |
| 25 | ProcessTampering | Hollowing, ImageMapping changes |

## Steps

1. Convert log:
   ```bash
   EvtxECmd.exe -f 'Microsoft-Windows-Sysmon%4Operational.evtx' --csv ./out
   ```
2. Process tree from EID 1:
   ```python
   # Build tree by ProcessGuid (stable across reboots) — not PID alone
   # Anchor on suspect parent: outlook.exe -> winword.exe -> cmd.exe -> powershell.exe
   ```
3. LOLBIN hunting (EID 1):
   ```bash
   awk -F, 'tolower($COL) ~ /certutil|bitsadmin|mshta|wmic|regsvr32|rundll32|installutil|msbuild/' sysmon.csv
   ```
4. LSASS access (EID 10):
   ```bash
   awk -F, '$ImageField ~ /lsass\.exe/ && $GrantedAccessField ~ /0x1010|0x1410|0x1438/' sysmon.csv
   # 0x1010 = PROCESS_VM_READ|QUERY_LIMITED — classic mimikatz signature
   ```
5. Outbound C2 candidates (EID 3 + EID 22):
   ```bash
   # group by Image, count distinct DestinationIP — beacons stand out
   awk -F, '$Image ~ /powershell|rundll32|svchost/ {print $Image","$DestinationIp}' sysmon.csv | sort | uniq -c | sort -rn
   ```
6. Persistence (EID 12/13/14):
   ```bash
   awk -F, '$TargetObject ~ /\\\\Run|\\\\RunOnce|\\\\Image File Execution Options|\\\\AppInit_DLLs/' sysmon.csv
   ```

## Verifying success

- Process tree built from ProcessGuid is acyclic and matches independent EVTX 4688 / Prefetch entries.
- Suspect EID 10 hit produces a process whose subsequent EID 11 file write contains LSASS dump signatures.
- EID 3/22 pairs (TCP connect + DNS query) attribute external IPs to a single PID.

## Common pitfalls

- Sysmon config dictates noise. Without a tuned config (SwiftOnSecurity, Olaf Hartong, MS) you'll either see nothing or millions of events.
- Process GUIDs are stable; Process IDs are not. Always join on ProcessGuid for parent/child reconstruction.
- EID 22 (DNS) is missing on older Sysmon builds (<10) and on hosts that use DoH (DNS-over-HTTPS) — the resolver bypasses the Sysmon hook.
- Hash fields (MD5/SHA1/SHA256/IMPHASH) help triage, but only if the config enables them per image.
- EID 25 (ProcessTampering) requires Sysmon 13+.

## Tools

- `Sysmon` + ConfigMgmt repos (SwiftOnSecurity, Olaf Hartong's `sysmon-modular`)
- `EvtxECmd` / `chainsaw` / `hayabusa` (all support Sysmon channel)
- `Sigma` rules with `winlog.channel:"Microsoft-Windows-Sysmon/Operational"` selector
- `DeepBlueCLI`, `EVTX-ATTACK-SAMPLES` for testing
