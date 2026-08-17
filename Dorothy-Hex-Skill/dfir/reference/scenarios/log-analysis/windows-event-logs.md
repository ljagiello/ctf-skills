# Windows Event Log Analysis

## When this applies

Reconstructing logon, privilege use, account changes, and process execution from `*.evtx` files. The Security log carries authentication events; System carries service/driver activity; Application carries software-specific events; many providers also log to dedicated channels (`Microsoft-Windows-*/Operational`).

## Technique

EVTX is a binary, sealed-block log. Parse with `python-evtx`, `EvtxECmd`, `chainsaw`, or PowerShell `Get-WinEvent`. Anchor on a small set of high-signal IDs and pivot via correlation fields (`TargetLogonId`, `SubjectLogonId`, `SubjectUserSid`).

## Steps

1. Convert to readable form:
   ```bash
   EvtxECmd.exe -f Security.evtx --csv ./out --csvf sec.csv
   # Or via chainsaw with pre-built rules:
   chainsaw hunt evidence/ --sigma sigma_rules/ --mapping mappings/
   ```
2. Python parsing skeleton:
   ```python
   import Evtx.Evtx as evtx, xml.etree.ElementTree as ET
   ns = {'ns':'http://schemas.microsoft.com/win/2004/08/events/event'}
   with evtx.Evtx('Security.evtx') as log:
       for r in log.records():
           try:
               root = ET.fromstring(r.xml())
               eid = root.find('.//ns:EventID', ns).text
               ts  = root.find('.//ns:TimeCreated', ns).get('SystemTime')
               d   = {x.get('Name',''): x.text for x in root.findall('.//ns:Data', ns)}
               # process...
           except Exception:
               continue
   ```
3. High-signal IDs (Security log):
   - **4624** — successful logon. LogonType field is the first pivot:
     - `2` interactive, `3` network, `4` batch, `5` service, `7` unlock,
       `8` networkcleartext, `9` newcredentials, `10` remote interactive (RDP), `11` cached.
   - **4625** — failed logon. `Status` / `SubStatus` (e.g. `0xC000006A` bad password, `0xC0000234` locked).
   - **4634 / 4647** — logoff.
   - **4672** — special privileges assigned at logon (admin equivalent).
   - **4688** — process creation (requires audit subcategory + command-line auditing GPO).
   - **4720** — user account created.
   - **4728/4732/4756** — added to security-enabled global/local/universal group.
   - **4768** — TGT request (PreAuthType=0 ⇒ AS-REP roastable).
   - **4769** — TGS request (TicketEncryptionType=0x17 ⇒ RC4 / Kerberoast suspect).
   - **4776** — NTLM authentication via DC; `Status` non-zero is failure.
4. System log:
   - **7045** — service install (lateral movement via psexec/WMI/sc).
   - **7036** — service started/stopped.
   - **104** — log cleared (anti-forensics indicator).
5. Application log:
   - **1000/1001** — app/Windows Error Reporting (often shows malware crashes).
   - **ESENT 325/326/327/330** — DB create/detach/close/file-info (NTDS dump tells).
6. Pivot example — full session reconstruction:
   ```python
   # find target user's logon, then everything they did under that LogonId
   target_user = 'admin'
   logon_ids = set()
   # parse 4624: if d['TargetUserName']==target_user, add d['TargetLogonId']
   # then parse 4688/5140/4663: keep events where d['SubjectLogonId'] in logon_ids
   ```

## Verifying success

- LogonId-based correlation reproduces the same event chain on independent runs.
- Suspect IPs in 4624 match attacker IPs in network artifacts.
- 4688 process tree corroborates Sysmon-1 / Prefetch / AmCache findings.

## Common pitfalls

- 4688 with command-line content requires Group Policy `Process Creation` + `Include command line in process creation events`. Default Windows: empty CommandLine.
- Time skew between DC and member servers: trust DC clocks for Kerberos events; member-server clocks for local 4688/4624.
- `LogonType=3` to `\\\\<localhost>\\IPC$` is normal (idle scheduled tasks). Don't flag unless source IP is external.
- Attacker may clear logs (System 104). Check archived/forwarded copies (WEC, SIEM) before declaring evidence destruction.
- 4672 follows 4624 in the same session and is the single most reliable "this was admin" indicator — easier than inspecting group memberships.

## Tools

- `EvtxECmd`, `Timeline Explorer` (Zimmerman)
- `chainsaw` — Sigma-rule based hunting over EVTX
- `python-evtx` — direct XML access
- `hayabusa` — fast Sigma-rule scanner
- `DeepBlueCLI` — PowerShell, signature-based analysis
