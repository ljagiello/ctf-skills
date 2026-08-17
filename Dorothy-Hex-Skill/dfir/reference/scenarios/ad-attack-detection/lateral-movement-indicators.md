# Lateral Movement Indicators

## When this applies

Reconstructing how an attacker moved between hosts after initial access. Common techniques: PsExec / paexec / smbexec, WMI (`wmiexec`), DCOM (`dcomexec`), WinRM (`evil-winrm`), RDP, scheduled tasks, and legitimate admin tools (`PsLoggedOn`, `ssh`).

## Technique

Each technique has signature event chains across Security, System, and Sysmon channels on **both** source and destination hosts. The most reliable single-source signal is `4624 LogonType=3` (network logon) on the destination, combined with technique-specific ancillary events.

## Steps

1. Network logon arrivals (destination):
   ```spl
   index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName="NTLM" OR AuthenticationPackageName="Kerberos"
   | search NOT TargetUserName="*$" NOT TargetUserName="ANONYMOUS LOGON"
   | stats count BY TargetUserName, IpAddress, host, AuthenticationPackageName
   ```
   Users (not machines) hitting many destinations from one source IP = lateral movement candidate.
2. PsExec signatures:
   - **Source**: 4688 / Sysmon-1 — `psexec.exe` / `PsExec64.exe` with `\\\\target` argument.
   - **Destination**: 7045 in System log installing service `PSEXESVC` (or attacker-renamed) with binary path `\\.\\pipe\\PSEXESVC` or service file in `\Windows\` named `*.exe`. Also 5145 (named pipe access) on `\\\\.\\pipe\\PSEXESVC`.
   ```spl
   index=wineventlog EventCode=7045
   | rex field=Message "Service File Name:\s+(?<svcfile>.*)"
   | search (svcfile="*PSEXESVC*" OR svcfile="*\\Windows\\*.exe")
   ```
3. WMI / wmiexec:
   - **Destination**: 4688 with `Image=wmiprvse.exe` `ParentImage=svchost.exe` and child `cmd.exe /Q /c <command> 1> \\\\127.0.0.1\\ADMIN$\\__<timestamp>`.
   ```spl
   index=sysmon EventCode=1 ParentImage="*wmiprvse.exe" CommandLine="*ADMIN$\\__*"
   ```
4. WinRM:
   - **Destination**: 4624 LogonType=3 with `AuthenticationPackageName=Kerberos` followed by `Microsoft-Windows-WinRM/Operational` Event 91 (server start receiving), Event 168 (received command).
5. Scheduled tasks (`schtasks`/`Register-ScheduledTask`):
   - Security: 4698 (task created), 4702 (updated), 4699 (deleted).
   - Microsoft-Windows-TaskScheduler/Operational: 106 (registered), 200 (action started), 201 (action completed).
6. RDP:
   - 4624 LogonType=10 (`RemoteInteractive`).
   - Microsoft-Windows-TerminalServices-LocalSessionManager/Operational: 21 (logon), 24 (disconnect), 25 (reconnect).
7. SMB share access trail (often the smoking gun across techniques):
   ```spl
   index=wineventlog EventCode=5145 ShareName IN ("\\\\*\\IPC$","\\\\*\\ADMIN$","\\\\*\\C$")
   | stats values(SubjectUserName) values(IpAddress) BY ShareName, host
   ```
8. Build a host-to-host edge list:
   ```python
   # For each 4624 LogonType=3, emit (src_ip, dst_host, user, time)
   # Build directed graph; nodes hit by the same user across N hosts in T minutes = lateral spread
   ```

## Verifying success

- Source-host execution event (Sysmon 1 / 4688) precedes destination-host arrival event (4624 LT=3, 7045, etc.) by < 1 minute.
- Same compromised user/credential appears across multiple destinations in a short window.
- Tool fingerprint (PSEXESVC, wmiprvse-spawned cmd, ADMIN$ writes) confirms the technique.

## Common pitfalls

- Patch / management tools (SCCM, ManageEngine, Tanium) generate identical 4624/7045/5145 patterns at scale. Pre-baseline these accounts/hosts before alerting.
- 4624 LogonType=3 with `WorkstationName` matching the destination is a *self-loop* (often boot-time service). Filter when source IP equals destination.
- Logon to `\\\\?\\c:\\` style paths shows up in 5145 with empty ShareName — easily missed.
- Time skew between source and destination (>5 minutes) breaks short-window correlation. Normalize to UTC before joining.
- "Pass-the-Hash" runs over NTLM 4624 with `AuthenticationPackageName=NTLM` and `LogonType=3` — same as benign network logons. The signal is *which* account moves *where*.

## Tools

- `chainsaw` / `hayabusa` with Sigma rules in `windows/lateral_movement/`
- `BloodHound` (post-collection) for reachability analysis
- `Velociraptor` artifacts: `Windows.EventLogs.LateralMovement`, `Windows.NTFS.MFT`
- `RITA` / `zeek` for connection-side lateral analysis when network logs exist
