# Standards and References — Hunting EVTX with Chainsaw

## MITRE ATT&CK References

| Technique ID | Name | Tactic | Rationale |
|-------------|------|--------|-----------|
| T1059.001 | Command and Scripting Interpreter: PowerShell | Execution | Sigma rules over EID 4104/4103 and search flag malicious PowerShell |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Execution | Process-creation Sigma rules surface suspicious cmd usage |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Persistence | Registry-event Sigma rules flag persistence |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Execution / Persistence | Rules over EID 4698/106 detect task creation |
| T1070.006 | Indicator Removal: Timestomp | Defense Evasion | `analyse gaps` and shimcache reveal time tampering |
| T1204.002 | User Execution: Malicious File | Execution | Shimcache analysis shows executed binaries |

## NIST Cybersecurity Framework 2.0

| ID | Name | Rationale |
|----|------|-----------|
| DE.AE-02 | Potentially adverse events are analyzed to better understand associated activities | Chainsaw hunts/searches analyze event-log activity to characterize threats |

## Detection Standards

- Sigma generic signature format: https://github.com/SigmaHQ/sigma
- Chainsaw mappings (Sigma->EVTX): https://github.com/WithSecureLabs/chainsaw/tree/master/mappings

## Official Resources

- Chainsaw GitHub: https://github.com/WithSecureLabs/chainsaw
- WithSecure Labs research: https://labs.withsecure.com/
- MITRE ATT&CK T1059.001: https://attack.mitre.org/techniques/T1059/001/

## Key Research

- WithSecure Labs: Chainsaw release announcements (shimcache, SRUM, gaps analysers)
- SigmaHQ community detection rule corpus
