# DCOM Lateral Movement Detection API Reference

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| Remote Services: DCOM | T1021.003 | Adversaries use DCOM to execute commands on remote systems |
| Lateral Movement | TA0008 | Tactic covering movement between networked systems |
| Windows Management Instrumentation | T1047 | WMI often correlated with DCOM lateral movement |

## DCOM COM Objects Abused for Lateral Movement

| COM Object | CLSID | Method | Parent Process |
|------------|-------|--------|---------------|
| MMC20.Application | {49B2791A-B1AE-4C90-9B8E-E860BA07F889} | ExecuteShellCommand | mmc.exe via svchost.exe -k DcomLaunch |
| ShellWindows | {9BA05972-F6A8-11CF-A442-00A0C90A8F39} | Document.Application.ShellExecute | explorer.exe (existing process) |
| ShellBrowserWindow | {C08AFD90-F2A1-11D1-8455-00A0C91F3880} | Document.Application.ShellExecute | explorer.exe (existing process) |
| Excel.Application | {00024500-0000-0000-C000-000000000046} | DDEInitiate / RegisterXLL | excel.exe via svchost.exe -k DcomLaunch |
| Outlook.Application | {0006F03A-0000-0000-C000-000000000046} | CreateObject | outlook.exe via svchost.exe -k DcomLaunch |

## Sysmon Event IDs for DCOM Detection

| Event ID | Name | DCOM Relevance |
|----------|------|----------------|
| 1 | Process Create | Detects DCOM parent (mmc.exe, dllhost.exe, explorer.exe) spawning suspicious children |
| 3 | Network Connection | Captures inbound RPC (port 135) and dynamic high-port DCOM connections |
| 7 | Image Loaded | Tracks loading of DCOM-related DLLs (ole32.dll, comsvcs.dll, rpcrt4.dll) |
| 10 | Process Access | Detects cross-process access patterns from DCOM processes |
| 11 | File Create | Identifies file drops from DCOM-executed commands |

## Windows Security Event IDs

| Event ID | Log | DCOM Context |
|----------|-----|-------------|
| 4624 (Type 3) | Security | Network logon preceding DCOM execution on target |
| 4672 | Security | Special privileges assigned during DCOM remote activation |
| 4688 | Security | Process creation (alternative to Sysmon EID 1 if enabled) |

## WMI-Activity Operational Event IDs

| Event ID | Description |
|----------|-------------|
| 5857 | WMI provider loaded (DCOM can trigger WMI operations) |
| 5858 | WMI query error |
| 5860 | Temporary WMI event consumer registration |
| 5861 | Permanent WMI event consumer registration |

## Network Indicators

| Protocol | Port | Description |
|----------|------|-------------|
| TCP | 135 | RPC Endpoint Mapper - all DCOM starts here |
| TCP | 49152-65535 | Dynamic RPC ports for DCOM data transfer |
| TCP | 445 | SMB - may follow DCOM for file operations |
| TCP | 139 | NetBIOS Session Service |

## Splunk SPL - DCOM Detection Queries

```spl
# MMC20.Application lateral movement
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 ParentImage="*\\mmc.exe"
(Image="*\\cmd.exe" OR Image="*\\powershell.exe")
| table _time ComputerName ParentImage Image CommandLine User

# Inbound RPC connections (DCOM prerequisite)
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3 DestinationPort=135 Initiated="false"
| stats dc(SourceIp) as sources count by ComputerName
| where sources > 3
```

## KQL - Microsoft Sentinel Queries

```kql
// DCOM process creation from mmc.exe or dllhost.exe
SysmonEvent
| where EventID == 1
| where ParentImage endswith "\\mmc.exe" or ParentImage endswith "\\dllhost.exe"
| where Image endswith "\\cmd.exe" or Image endswith "\\powershell.exe"
| project TimeGenerated, Computer, ParentImage, Image, CommandLine, User
```

## python-evtx - Parse Sysmon EVTX

```python
from Evtx.Evtx import FileHeader
from lxml import etree

NS = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}
with open("Microsoft-Windows-Sysmon%4Operational.evtx", "rb") as f:
    fh = FileHeader(f)
    for record in fh.records():
        root = etree.fromstring(record.xml().encode("utf-8"))
        eid = root.find(".//evt:System/evt:EventID", NS)
        if eid is not None and eid.text == "1":
            data = {e.get("Name"): e.text for e in root.findall(".//evt:EventData/evt:Data", NS)}
            print(data.get("ParentImage"), "->", data.get("Image"))
```

## Atomic Red Team - T1021.003 Test Cases

| Atomic Test | Description |
|-------------|-------------|
| MMC20.Application Lateral Movement | Instantiates MMC20.Application DCOM and calls ExecuteShellCommand |
| ShellWindows Lateral Movement | Uses ShellWindows CLSID for remote command execution |
| Excel DDE DCOM | Creates remote Excel instance and triggers DDE execution |

## Impacket - dcomexec.py

```bash
# Attack tool reference (for detection validation in authorized testing)
# dcomexec.py creates a DCOM connection and executes commands
# Protocol: Uses MMC20.Application, ShellWindows, or ShellBrowserWindow
python3 dcomexec.py domain/user:password@target_ip "whoami"
python3 dcomexec.py -object MMC20 domain/user:password@target_ip "cmd.exe /c ipconfig"
python3 dcomexec.py -object ShellWindows domain/user:password@target_ip "powershell -c Get-Process"
```

## References

- MITRE ATT&CK T1021.003: https://attack.mitre.org/techniques/T1021/003/
- Cybereason DCOM Research: https://www.cybereason.com/blog/dcom-lateral-movement-techniques
- MDSec DCOM Lateral Movement: https://www.mdsec.co.uk/2020/09/i-like-to-move-it-windows-lateral-movement-part-2-dcom/
- Elastic Detection Rule: https://www.elastic.co/guide/en/security/8.19/incoming-dcom-lateral-movement-with-shellbrowserwindow-or-shellwindows.html
- Atomic Red Team T1021.003: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.003/T1021.003.md
