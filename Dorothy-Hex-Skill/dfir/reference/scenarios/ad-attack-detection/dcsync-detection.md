# DCSync Detection

## When this applies

Investigating, or hunting for, replication-rights abuse where an attacker (mimikatz `lsadump::dcsync`, impacket `secretsdump.py -just-dc`) requests password material for arbitrary accounts from a DC over the directory-replication API (DRSUAPI / `IDL_DRSGetNCChanges`).

## Technique

DCSync is performed by accounts with the `DS-Replication-Get-Changes` (`{1131f6aa-...}`) and `DS-Replication-Get-Changes-All` (`{1131f6ad-...}`) extended rights. Domain Controllers and a tiny set of replication-trust principals legitimately use this. Any other principal exercising it is suspicious. The DC logs an Object Access event (4662) referencing the relevant `Properties` GUID.

## Steps

1. Enable the audit policy on DCs (one-time):
   ```
   auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
   ```
   And ensure the domain naming context's SACL audits `DS-Replication-Get-Changes*` for `Everyone`.
2. Hunt 4662 with the replication GUIDs:
   ```spl
   index=wineventlog EventCode=4662
     (Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*"
      OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*")
   | search NOT (SubjectUserName="*$" OR SubjectUserName="MSOL_*")
   | stats count BY SubjectUserName, SubjectDomainName, SubjectLogonId, ObjectName
   ```
   Whitelist: DC machine accounts (`DC01$`), `Azure AD Connect` sync account (`MSOL_*`), and any documented replication service.
3. Python parse:
   ```python
   if eid == '4662' and any(g in (data.get('Properties','') or '') for g in (
       '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
       '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')):
       u = data.get('SubjectUserName','')
       if not u.endswith('$') and not u.startswith('MSOL_'):
           print(ts, u, data.get('IpAddress',''), data.get('ObjectName',''))
   ```
4. Pivot to logon source — link `SubjectLogonId` to the originating 4624 to identify workstation/IP.
5. ACL-side hunting — enumerate principals that have replication rights:
   ```powershell
   # On a domain-joined host with AD module
   Get-Acl "AD:DC=corp,DC=local" |
     Select-Object -ExpandProperty Access |
     Where-Object { $_.ObjectType -in @(
         "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
         "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2") } |
     Select IdentityReference, AccessControlType
   ```
   Anyone outside `Domain Controllers`, `Enterprise Domain Controllers`, `Administrators`, `Read-Only Domain Controllers` is investigation-worthy.
6. Network-side artifact — DRSUAPI runs over RPC dynamic high port; not a useful network signature on its own. Logon traffic to the DC from a non-DC source preceding 4662 hits is the better pivot.

## Verifying success

- 4662 with the replication GUIDs from a non-DC, non-allowlisted SubjectUserName.
- Same SubjectLogonId in a 4624 originating from a workstation that should not be a DC peer.
- ACL audit confirms the principal had `Replicating Directory Changes` rights at the time.

## Common pitfalls

- Properties field is verbose; the GUID may appear anywhere in it. Substring match is correct.
- 4662 is **noisy** without focused filtering — millions of events per day on a busy DC. Always filter by GUID before alerting.
- Azure AD Connect (`MSOL_*`) and Microsoft Identity Manager use these rights legitimately. Catalog them before tuning.
- Some attackers use `DCShadow` (registers a fake DC and replicates *out*) rather than DCSync — those leave 4742/5137 instead of 4662.
- Replication GUIDs are well-known; do not omit `Get-Changes-All`, which is required for password attribute replication.

## Tools

- DC `Security.evtx` (4662) parsed by `chainsaw`, `EvtxECmd`, `python-evtx`
- `BloodHound` highlights principals with replication rights via `GetChanges`/`GetChangesAll` edges
- `Invoke-Mimikatz` / `secretsdump.py` for *authorized* validation of the privilege path
- `Sigma`: `win_security_dcsync.yml`
