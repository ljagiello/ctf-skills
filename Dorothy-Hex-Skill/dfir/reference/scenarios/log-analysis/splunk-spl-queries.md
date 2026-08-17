# Splunk SPL Detection Queries

## When this applies

Logs are centralized in Splunk and you need to express common detections (logon anomalies, Kerberoasting, lateral movement, exfil) in SPL. Same patterns translate to Elastic KQL/EQL or Sentinel KQL with field renames.

## Technique

Anchor each query on a small set of CIM-mapped fields where possible: `index`, `sourcetype`, `host`, `user`, `src`, `dest`, `process`, `parent_process`. Use `tstats` against datamodels for speed; use `stats` for ad-hoc fields. Always end with sufficient grouping fields to enable triage.

## Steps

1. Failed-then-successful logon (brute force success):
   ```spl
   index=wineventlog source="*Security*"
     (EventCode=4625 OR EventCode=4624)
   | bin _time span=10m
   | stats count(eval(EventCode=4625)) AS failed
           count(eval(EventCode=4624)) AS success
           BY user, src_ip, _time
   | where failed > 20 AND success > 0
   ```
2. New service install (lateral movement via psexec/sc):
   ```spl
   index=wineventlog EventCode=7045
   | rex field=Message "Service Name:\s+(?<svc>\S+)"
   | rex field=Message "Service File Name:\s+(?<svcfile>.*)"
   | stats values(svc) values(svcfile) BY host, _time
   ```
3. Kerberoast indicator (RC4 TGS to a user SPN):
   ```spl
   index=wineventlog EventCode=4769 TicketEncryptionType=0x17
   | search NOT ServiceName="*$"
   | stats count BY ClientAddress, ServiceName, TargetUserName
   | where count > 0
   ```
4. AS-REP roastable accounts (PreAuthType=0):
   ```spl
   index=wineventlog EventCode=4768 PreAuthType=0
   | stats count BY TargetUserName, IpAddress
   ```
5. LSASS access from non-system processes (Sysmon EID 10):
   ```spl
   index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
     GrantedAccess IN ("0x1010","0x1410","0x1438","0x143a")
   | stats count BY host, SourceImage, GrantedAccess
   ```
6. Suspicious PowerShell:
   ```spl
   index=sysmon EventCode=1 Image="*\\powershell.exe"
     (CommandLine="*-enc*" OR CommandLine="*EncodedCommand*"
      OR CommandLine="*FromBase64String*" OR CommandLine="*DownloadString*")
   | table _time host User CommandLine ParentImage
   ```
7. Outbound beacon detection (regular intervals):
   ```spl
   index=firewall action=allowed dest_port IN (80,443,8080)
   | bin _time span=1m
   | stats count BY src, dest, _time
   | streamstats current=f window=1 last(_time) AS prev_time BY src, dest
   | eval delta = _time - prev_time
   | stats stdev(delta) AS stdev avg(delta) AS avg count BY src, dest
   | where avg < 600 AND stdev < 20 AND count > 30
   ```
8. New admin group membership:
   ```spl
   index=wineventlog (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
   | rex field=Message "Group Name:\s+(?<grp>\S+)"
   | search grp IN ("Domain Admins","Enterprise Admins","Administrators","Schema Admins")
   | table _time host SubjectUserName MemberName grp
   ```

## Verifying success

- Each detection returns at most a handful of high-fidelity rows in a clean environment, not thousands.
- Drill-down from the row into raw events (`| return`) yields the expected EventCode and original message.
- Independent runs over the same time window are deterministic.

## Common pitfalls

- Field extraction depends on the TA (Splunk Add-on for Windows / Sysmon). If `EventCode` is missing, search by `signature_id` or extract via `rex` from `_raw`.
- `tstats` requires accelerated datamodels; ad-hoc `stats` is slower but always works.
- Time-bin choice (`bin _time span=...`) materially affects beacon detection sensitivity. Start with 1m, widen for low-and-slow.
- 4769 with `TicketEncryptionType=0x12` (AES-256) is normal; only 0x17/0x18 (RC4) is suspicious. Service accounts using RC4 due to legacy compat is the main false positive.
- Time skew between data sources will scatter related events across bins. Use `eval _time = strptime(...)` to normalize from raw fields when needed.

## Tools

- Splunk SPL editor and `Search Job Inspector`
- `splunk-sdk-python` for batch query export
- Elastic / Sentinel equivalents — the same pivots work, swap field names (`event.code`, `winlog.event_id`)
- `Sigma` repository — most queries above have Sigma equivalents that compile to SPL via `sigmac -t splunk`
