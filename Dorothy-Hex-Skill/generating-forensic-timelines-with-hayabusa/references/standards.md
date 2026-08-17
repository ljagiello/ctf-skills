# Standards and References — Generating Forensic Timelines with Hayabusa

## MITRE ATT&CK References

| Technique ID | Name | Tactic | Rationale |
|-------------|------|--------|-----------|
| T1059.001 | Command and Scripting Interpreter: PowerShell | Execution | Sigma rules over EID 4104/4103/Sysmon flag malicious PowerShell |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Execution | Process-creation rules surface suspicious cmd usage |
| T1078 | Valid Accounts | Defense Evasion / Persistence | Logon events (4624/4625/4672) reveal anomalous auth |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Persistence | Registry-modification rules flag persistence |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Execution / Persistence | EID 4698/106 rules surface task creation |
| T1003 | OS Credential Dumping | Credential Access | Rules flag LSASS access patterns |

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| RS.AN-03 | Analysis is performed to establish what has taken place during an incident and the root cause | Hayabusa timelines reconstruct the sequence of events during IR analysis |

## Detection Standards

- Sigma generic signature format: https://github.com/SigmaHQ/sigma
- Hayabusa rules (Sigma + Hayabusa-native): https://github.com/Yamato-Security/hayabusa-rules

## Official Resources

- Hayabusa GitHub: https://github.com/Yamato-Security/hayabusa
- Usage Examples Wiki: https://github.com/Yamato-Security/hayabusa/wiki/Usage-Examples
- Timeline Output Wiki: https://github.com/Yamato-Security/hayabusa/wiki/Timeline-Output
- Takajō analyzer: https://github.com/Yamato-Security/takajo
- MITRE ATT&CK T1059.001: https://attack.mitre.org/techniques/T1059/001/

## Key Research

- Yamato Security: Hayabusa documentation and AnalysisWithJQ guide
- Timesketch integration via timesketch-minimal / timesketch-verbose profiles
