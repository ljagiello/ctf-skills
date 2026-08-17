# API Reference: Detecting Lateral Movement with Zeek

## CLI Usage

```bash
# Analyze current Zeek logs
python agent.py /opt/zeek/logs/current/

# Analyze specific date
python agent.py /opt/zeek/logs/2026-03-18/

# Pipe JSON output for further processing
python agent.py /opt/zeek/logs/current/ 2>/dev/null | python -m json.tool
```

## Zeek Log Files Analyzed

| Log File | Fields Used | Detection Purpose |
|----------|-------------|-------------------|
| conn.log | ts, id.orig_h, id.resp_h, id.resp_p, service, orig_bytes, resp_bytes | Internal lateral-port connections (SMB 445, RDP 3389, WinRM 5985) |
| smb_mapping.log | ts, id.orig_h, id.resp_h, path, share_type | Admin share access (C$, ADMIN$, IPC$) |
| smb_files.log | ts, id.orig_h, id.resp_h, action, path, name, size | Executable file writes to network shares |
| dce_rpc.log | ts, id.orig_h, id.resp_h, endpoint, operation, named_pipe | Remote service creation (svcctl), scheduled tasks (atsvc) |
| ntlm.log | ts, id.orig_h, id.resp_h, username, domainname, success | Pass-the-Hash detection, NTLM brute force |
| kerberos.log | ts, id.orig_h, id.resp_h, request_type, client, service, error_msg | Pass-the-Ticket, Kerberos pre-auth failures |

## Lateral Movement Ports Tracked

| Port | Service | ATT&CK Technique |
|------|---------|-------------------|
| 445 | SMB | T1021.002 - SMB/Windows Admin Shares |
| 135 | DCE/RPC | T1021.003 - Distributed Component Object Model |
| 139 | NetBIOS-SSN | T1021.002 - SMB/Windows Admin Shares |
| 3389 | RDP | T1021.001 - Remote Desktop Protocol |
| 5985 | WinRM-HTTP | T1021.006 - Windows Remote Management |
| 5986 | WinRM-HTTPS | T1021.006 - Windows Remote Management |
| 22 | SSH | T1021.004 - SSH |

## Suspicious DCE/RPC Endpoints

| Endpoint | Description | Severity |
|----------|-------------|----------|
| svcctl | Service Control Manager (PsExec pattern) | CRITICAL |
| atsvc | AT Scheduler Service (at.exe / schtasks) | CRITICAL |
| ITaskSchedulerService | Task Scheduler v2 (schtasks) | CRITICAL |
| winreg | Remote Registry manipulation | HIGH |
| samr | SAM Remote Protocol (user enumeration) | HIGH |
| lsarpc | LSA Remote Protocol (policy enumeration) | HIGH |
| srvsvc | Server Service (share/session enumeration) | HIGH |
| wkssvc | Workstation Service (user enumeration) | HIGH |

## Detection Types in Output

| Finding Type | Severity | Description |
|-------------|----------|-------------|
| lateral_port_connection | INFO | Internal connection on a lateral-movement-associated port |
| admin_share_access | HIGH | Access to C$, ADMIN$, or IPC$ administrative share |
| smb_file_write | MEDIUM/CRITICAL | File write to SMB share (CRITICAL if executable) |
| suspicious_dce_rpc | HIGH/CRITICAL | DCE/RPC call to remote execution endpoint |
| multi_source_ntlm_auth | HIGH | Single user NTLM authenticating from 3+ source IPs |
| ntlm_brute_force | HIGH | 5+ failed NTLM auth attempts from same source |
| multi_source_tgt_request | HIGH | Kerberos TGT requested from 3+ source IPs |
| kerberos_preauth_failure | MEDIUM | Kerberos pre-authentication failure |
| psexec_pattern | CRITICAL | Correlated SMB exe write + svcctl service creation |

## Report Output Schema

```json
{
  "summary": {
    "total_findings": 42,
    "by_severity": {"CRITICAL": 3, "HIGH": 15, "MEDIUM": 24},
    "by_type": {"admin_share_access": 8, "suspicious_dce_rpc": 5}
  },
  "top_connection_pairs": [
    {"pair": "10.0.1.50->10.0.1.100:445", "connections": 287}
  ],
  "top_data_transfer_pairs": [
    {"pair": "10.0.1.50->10.0.1.100:445", "bytes": 104857600, "megabytes": 100.0}
  ],
  "findings": []
}
```

## Zeek CLI Commands

```bash
# Install BZAR package for ATT&CK detections
zkg install zeek/mitre-attack/bzar

# Extract SMB admin share access
zeek-cut ts id.orig_h id.resp_h path share_type < smb_mapping.log | grep -iE '(C\$|ADMIN\$)'

# Extract DCE/RPC service creation
zeek-cut ts id.orig_h id.resp_h endpoint operation < dce_rpc.log | grep -i svcctl

# Extract failed NTLM authentications
zeek-cut ts id.orig_h id.resp_h username success < ntlm.log | awk '$5 == "F"'
```

## References

- Zeek Documentation: https://docs.zeek.org/
- BZAR (ATT&CK Zeek Analysis Rules): https://github.com/mitre-attack/bzar
- MITRE ATT&CK Lateral Movement: https://attack.mitre.org/tactics/TA0008/
- Zeek Log Formats: https://docs.zeek.org/en/master/logs/index.html
- Zeek SMB Protocol Analyzer: https://docs.zeek.org/en/master/scripts/base/protocols/smb/
