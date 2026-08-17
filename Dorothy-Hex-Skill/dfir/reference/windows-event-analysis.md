# Windows Event Log Analysis

## EVTX Parsing Pattern

```python
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

with evtx.Evtx("Security.evtx") as log:
    for record in log.records():
        try:
            root = ET.fromstring(record.xml())
            eid = root.find('.//ns:EventID', ns).text
            ts = root.find('.//ns:TimeCreated', ns).get('SystemTime')
            data = {d.get('Name',''): d.text for d in root.findall('.//ns:Data', ns)}
            # Process event...
        except Exception:
            continue  # Some records may have parsing errors (KeyError 136 for binary types)
```

**Tip**: Always wrap record parsing in try/except — some EVTX records contain binary substitution types that `python-evtx` can't handle.

## AD Attack Detection Patterns

### Kerberoasting (Event 4769)
- **Filter**: `EventID == 4769` AND `TicketEncryptionType == 0x17` (RC4)
- **Key fields**: `ServiceName` (targeted SPN), `IpAddress` (attacker workstation), `TargetUserName`
- **Normal**: DC-to-DC requests from `::1` with AES (`0x12`). **Abnormal**: User-initiated RC4 requests from workstation IPs

### AS-REP Roasting (Event 4768)
- **Filter**: `EventID == 4768` AND `PreAuthType == 0` (no pre-auth)
- **Key fields**: `TargetUserName` (victim account), `TargetSid`, `IpAddress` (attacker)
- **Correlation**: Follow up with 4769/5140 events from same `IpAddress` to identify the attacking user account

### NTDS Dump via vssadmin
1. **System log Event 7036**: `param1 == "Volume Shadow Copy"` AND `param2 == "running"` — marks VSS start
2. **Security log Event 4799**: `CallerProcessName` contains `VSSVC.exe` — VSS enumerating groups (`Administrators`, `Backup Operators`) with machine account (`DC$`)
3. **Extract PID**: From 4799 `CallerProcessId` (hex → decimal)
4. **Volume GUID**: Parse NTFS operational log for `\\?\Volume{GUID}` associated with `HarddiskVolumeShadowCopy`

### NTDS Dump via ntdsutil
1. **System log Event 7036**: VSS service "running" (most recent instance)
2. **Application log ESENT events**:
   - **Event 325**: Database created — contains dump path (e.g., `C:\Windows\Temp\dump_tmp\Active Directory\ntds.dit`)
   - **Event 330**: Database file info with page counts
   - **Event 326**: Database detach (clean shutdown)
   - **Event 327**: Database close — marks dump complete
3. **Security log Event 4799**: `CallerProcessName` contains `ntdsutil.exe` — extract `SubjectLogonId`
4. **Logon correlation**: Match `SubjectLogonId` from 4799 → Event 4624/4768 to find session start time

### NTLM Relay Detection (Event 4624)
- **Filter**: `EventID == 4624` AND `LogonType == 3` (network)
- **Detection**: `WorkstationName` does NOT match expected IP for that hostname
- **Key fields**: `IpAddress`, `IpPort` (source port), `TargetLogonId`, `WorkstationName`

### Logon Tracking
- **4624**: Successful logon — `TargetLogonId` links session across events
- **4768**: TGT request — Kerberos authentication timestamp
- **7001** (System): User Logon Notification — `UserSid` maps to account
- **5140**: Share access — tracks lateral movement with `ShareName`, `IpAddress`

## Event Source Reference

| Source | Log | Events | Purpose |
|--------|-----|--------|---------|
| Security | Security | 4624/4625/4768/4769/4799/5140 | Auth, Kerberos, shares |
| Service Control Manager | System | 7036/7045 | Service start/stop/install |
| ESENT | Application | 102/103/105/216/300/325/326/327/330 | Database operations |
| Microsoft-Windows-Ntfs | NTFS Operational | 98 | Volume mount/GUID assignment |
| Microsoft-Windows-DNS-Client | DNS Client Events | 3006/3008/3009/3010/3018 | DNS query/response logging — reveals malicious domain lookups |
| Microsoft-Windows-TaskScheduler | Task Scheduler | 106/140/141/200/201 | Scheduled task creation/execution (persistence) |
