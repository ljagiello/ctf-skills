# NTLM Relay Detection API Reference

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| LLMNR/NBT-NS Poisoning and SMB Relay | T1557.001 | Poisoning name resolution to capture and relay NTLM auth |
| Forced Authentication | T1187 | Coercing systems to authenticate (PetitPotam, PrinterBug) |
| Adversary-in-the-Middle | T1557 | Parent technique for relay and poisoning attacks |
| Exploitation for Credential Access | T1212 | Exploiting protocol weaknesses for credential theft |

## Windows Security Event IDs for NTLM Relay Detection

| Event ID | Log | Relay Significance |
|----------|-----|--------------------|
| 4624 (Type 3) | Security | Network logon -- primary relay detection event. Check IP vs WorkstationName |
| 4625 | Security | Failed logon -- relay failures leave traces here |
| 4648 | Security | Explicit credential logon -- may appear in some relay scenarios |
| 4776 | Security | NTLM credential validation on domain controller |
| 8001 | NTLM Operational | NTLM client blocked audit |
| 8002 | NTLM Operational | NTLM server blocked audit |
| 8003 | NTLM Operational | NTLM server blocked in domain |
| 8004 | NTLM Operational | NTLM authentication to DC audit (critical for inventory) |

## Event 4624 Key Fields for Relay Detection

| Field | Normal Value | Relay Indicator |
|-------|-------------|-----------------|
| LogonType | 3 | Always 3 for network relay |
| AuthenticationPackageName | NTLM | Must be NTLM (Kerberos cannot be relayed) |
| LmPackageName | NTLM V2 | NTLM V1 indicates downgrade attack |
| WorkstationName | Victim hostname | Name of victim machine (not the relay host) |
| IpAddress | Victim IP | Attacker/relay IP (MISMATCH = relay indicator) |
| LogonProcessName | NtLmSsp | Standard for NTLM logon |
| ImpersonationLevel | Delegation/Impersonation | High privilege relay |

## SMB Signing Registry Keys

| Registry Path | Value | Secure Setting |
|--------------|-------|---------------|
| HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature | REG_DWORD | 1 (Required) |
| HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature | REG_DWORD | 1 (Enabled) |
| HKLM\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters\RequireSecuritySignature | REG_DWORD | 1 (Required) |

## LDAP Signing Registry Keys (Domain Controllers)

| Registry Path | Value | Meaning |
|--------------|-------|---------|
| HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity | 0 | None (Vulnerable) |
| | 1 | Negotiate (Default - Vulnerable) |
| | 2 | Required (Secure) |
| HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding | 0 | Disabled (Vulnerable) |
| | 1 | When Supported |
| | 2 | Always Required (Secure) |

## NTLM Configuration Registry Keys

| Registry Path | Value | Meaning |
|--------------|-------|---------|
| HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel | 0 | Send LM & NTLM (Most Vulnerable) |
| | 1 | Send LM & NTLM, NTLMv2 session if negotiated |
| | 2 | Send NTLM only |
| | 3 | Send NTLMv2 only (Recommended minimum) |
| | 4 | Send NTLMv2 only, refuse LM |
| | 5 | Send NTLMv2 only, refuse LM & NTLM (Most Secure) |
| HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast | 0 | LLMNR Disabled (Secure) |
| | 1 | LLMNR Enabled (Vulnerable to Responder) |

## Network Indicators

| Protocol | Port | Attack Role |
|----------|------|-------------|
| UDP | 5355 | LLMNR -- Responder poisoning target |
| UDP | 137 | NBT-NS -- Responder poisoning target |
| UDP | 5353 | mDNS -- Responder poisoning target |
| TCP | 445 | SMB -- relay target (if signing not enforced) |
| TCP | 389 | LDAP -- relay target (if signing not enforced) |
| TCP | 636 | LDAPS -- relay target (if channel binding not enforced) |
| TCP | 80/443 | HTTP(S) -- relay target for AD CS enrollment |
| TCP | 135 | RPC -- used for coercion (PetitPotam, PrinterBug) |

## Coercion Methods

| Method | Protocol | Vulnerability | Target |
|--------|----------|--------------|--------|
| PetitPotam | MS-EFSRPC | CVE-2021-36942 | Domain controllers -> AD CS |
| DFSCoerce | MS-DFSNM | N/A | Domain controllers |
| PrinterBug (SpoolSample) | MS-RPRN | By design | Any host with Print Spooler |
| ShadowCoerce | MS-FSRVP | N/A | Hosts with File Server VSS Agent |

## Splunk SPL - NTLM Relay Detection Queries

```spl
# IP-hostname mismatch detection
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName="NTLM"
| where TargetUserName != "ANONYMOUS LOGON"
| lookup dns_inventory hostname AS WorkstationName OUTPUT expected_ip
| where isnotnull(expected_ip) AND IpAddress != expected_ip
| table _time ComputerName TargetUserName WorkstationName IpAddress expected_ip

# NTLMv1 downgrade detection
index=wineventlog EventCode=4624 LmPackageName="NTLM V1"
| where TargetUserName != "ANONYMOUS LOGON"
| stats count by TargetUserName IpAddress ComputerName

# Machine account relay (PetitPotam indicator)
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName="NTLM"
    TargetUserName="*$"
| stats dc(IpAddress) as source_count values(IpAddress) as sources by TargetUserName
| where source_count > 1
```

## KQL - Microsoft Sentinel Queries

```kql
// NTLM relay IP-hostname mismatch
SecurityEvent
| where EventID == 4624 and LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where TargetUserName !endswith "$" and TargetUserName != "ANONYMOUS LOGON"
| where IpAddress != "-" and IpAddress != "127.0.0.1"
| project TimeGenerated, Computer, TargetUserName, WorkstationName, IpAddress, LmPackageName

// NTLMv1 downgrade detection
SecurityEvent
| where EventID == 4624 and LmPackageName == "NTLM V1"
| where TargetUserName !endswith "$"
| summarize Count=count() by TargetUserName, IpAddress, Computer
```

## python-evtx - Parse Security EVTX

```python
from Evtx.Evtx import FileHeader
from lxml import etree

NS = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}
with open("Security.evtx", "rb") as f:
    fh = FileHeader(f)
    for record in fh.records():
        root = etree.fromstring(record.xml().encode("utf-8"))
        eid = root.find(".//evt:System/evt:EventID", NS)
        if eid is not None and eid.text == "4624":
            data = {e.get("Name"): e.text for e in root.findall(".//evt:EventData/evt:Data", NS)}
            if data.get("AuthenticationPackageName") == "NTLM" and data.get("LogonType") == "3":
                print(data.get("TargetUserName"), data.get("WorkstationName"), data.get("IpAddress"))
```

## References

- Fox-IT ntlmrelayx: https://blog.fox-it.com/2017/05/09/relaying-credentials-everywhere-with-ntlmrelayx/
- Fox-IT PetitPotam Detection: https://www.fox-it.com/nl-en/research-blog/detecting-and-hunting-for-the-petitpotam-ntlm-relay-attack/
- CrowdStrike NTLM Relay Detection: https://www.crowdstrike.com/en-us/blog/how-to-detect-domain-controller-account-relay-attacks-with-crowdstrike-identity-protection/
- NCC Group PetitPotam: https://www.nccgroup.com/research-blog/detecting-and-hunting-for-the-petitpotam-ntlm-relay-attack/
- HackTheBox NTLM Relay Detection: https://www.hackthebox.com/blog/ntlm-relay-attack-detection
- Microsoft NTLMv1 Detection: https://dirteam.com/sander/2022/06/15/howto-detect-ntlmv1-authentication/
- MITRE T1557.001: https://attack.mitre.org/techniques/T1557/001/
