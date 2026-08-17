# API Reference: Anti-Ransomware Group Policy

## AppLocker PowerShell Cmdlets

### Get Effective Policy
```powershell
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
```

### Create AppLocker Rule
```powershell
# Deny executables from AppData paths
New-AppLockerPolicy -RuleType Path -RuleNamePrefix "DenyAppData" `
  -Path "%USERPROFILE%\AppData\*" -Action Deny -User Everyone
```

### Test AppLocker Policy
```powershell
Test-AppLockerPolicy -Path "C:\Users\test\AppData\Local\Temp\malware.exe" `
  -XmlPolicy (Get-AppLockerPolicy -Effective -Xml)
```

### AppLocker Event Log IDs
| Event ID | Log | Description |
|----------|-----|-------------|
| 8003 | AppLocker/EXE | Allowed executable |
| 8004 | AppLocker/EXE | Blocked executable |
| 8005 | AppLocker/Script | Allowed script |
| 8006 | AppLocker/Script | Blocked script |
| 8007 | AppLocker/MSI | Allowed installer |
| 8008 | AppLocker/MSI | Blocked installer |

## Controlled Folder Access (CFA)

### Enable CFA
```powershell
Set-MpPreference -EnableControlledFolderAccess Enabled
```

### CFA Modes
| Value | Mode | Description |
|-------|------|-------------|
| 0 | Disabled | No protection |
| 1 | Enabled | Block unauthorized modifications |
| 2 | Audit | Log but do not block |
| 6 | BlockDiskModificationOnly | Block disk-level changes only |

### Add Protected Folders
```powershell
Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\Finance"
```

### Add Allowed Applications
```powershell
Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Program Files\App\app.exe"
```

### CFA Event IDs
| Event ID | Log | Description |
|----------|-----|-------------|
| 1123 | Defender/Operational | Blocked file modification |
| 1124 | Defender/Operational | Audited file modification |

## Attack Surface Reduction (ASR) Rules

### Enable ASR Rule
```powershell
Add-MpPreference -AttackSurfaceReductionRules_Ids <GUID> `
  -AttackSurfaceReductionRules_Actions Enabled
```

### ASR Rule Actions
| Value | Action |
|-------|--------|
| 0 | Disabled |
| 1 | Block |
| 2 | Audit |
| 6 | Warn |

### Key Anti-Ransomware ASR Rule GUIDs
| GUID | Rule |
|------|------|
| BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 | Block executable content from email |
| D4F940AB-401B-4EFC-AADC-AD5F3C50688A | Block Office child processes |
| 3B576869-A4EC-4529-8536-B80A7769E899 | Block Office executable content creation |
| 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 | Block Office code injection |
| D3E037E1-3EB8-44C8-A917-57927947596D | Block JS/VBS downloaded executables |
| 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC | Block obfuscated scripts |
| 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B | Block Win32 API from Office macros |

### ASR Event IDs
| Event ID | Log | Description |
|----------|-----|-------------|
| 1121 | Defender/Operational | ASR rule fired in block mode |
| 1122 | Defender/Operational | ASR rule fired in audit mode |

## GPO Paths Reference

### AppLocker
```
Computer Configuration → Policies → Windows Settings →
Security Settings → Application Control Policies → AppLocker
```

### Controlled Folder Access
```
Computer Configuration → Administrative Templates →
Windows Components → Microsoft Defender Antivirus →
Microsoft Defender Exploit Guard → Controlled Folder Access
```

### Attack Surface Reduction
```
Computer Configuration → Administrative Templates →
Windows Components → Microsoft Defender Antivirus →
Microsoft Defender Exploit Guard → Attack Surface Reduction
```

### Network Restrictions
```
Computer Configuration → Administrative Templates →
Network → Lanman Workstation    (SMB settings)
Windows Components → Remote Desktop Services    (RDP settings)
Windows Components → AutoPlay Policies    (AutoPlay/AutoRun)
```

## GPResult Verification

```powershell
# Check applied GPOs
gpresult /r /scope:computer

# Generate HTML report
gpresult /h gpo_report.html

# Check specific policy RSoP
gpresult /z /scope:computer
```
