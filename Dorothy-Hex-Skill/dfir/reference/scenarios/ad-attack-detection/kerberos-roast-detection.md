# Kerberos Roast Detection (Kerberoasting / AS-REP Roasting)

## When this applies

You're hunting for, or investigating, attacker harvesting of Kerberos-derived hashes for offline cracking. Two variants:

- **Kerberoasting** — attacker requests TGS for a service principal (SPN) and crackss the returned `enc-part` of the ticket.
- **AS-REP Roasting** — accounts with "Do not require Kerberos preauthentication" send back an `AS-REP` whose `enc-part` is encrypted with the user's password key — crackable.

## Technique

Both attacks leave canonical trails on the DC's Security log: 4769 for Kerberoasting, 4768 for AS-REP roasting. Detection focuses on (a) ticket encryption type (RC4 = 0x17 / 0x18) which is the cracking target of choice, and (b) PreAuthType=0 for AS-REP roastable accounts.

## Steps

1. Kerberoast (4769):
   ```python
   # Filter Security.evtx for 4769 with RC4 against user SPNs
   if eid == '4769':
       enc = data.get('TicketEncryptionType','')
       svc = data.get('ServiceName','')
       if enc == '0x17' and not svc.endswith('$') and svc != 'krbtgt':
           print(ts, data['IpAddress'], data['TargetUserName'], svc)
   ```
   Splunk equivalent:
   ```spl
   index=wineventlog EventCode=4769 TicketEncryptionType="0x17"
   | search NOT ServiceName="*$" NOT ServiceName="krbtgt"
   | stats count BY ClientAddress, TargetUserName, ServiceName
   ```
   `ClientAddress` reveals the attacker workstation; `TargetUserName` is the requesting account; `ServiceName` is the SPN.
2. AS-REP Roast (4768):
   ```spl
   index=wineventlog EventCode=4768 PreAuthType=0
   | stats count BY IpAddress, TargetUserName
   ```
   Validate by enumerating accounts with `DONT_REQUIRE_PREAUTH` UAC bit:
   ```bash
   # On a triage workstation with creds:
   GetNPUsers.py domain/user -dc-ip <DC> -no-pass -request
   ```
3. Burst detection — many SPNs requested by one user inside a short window:
   ```spl
   index=wineventlog EventCode=4769 TicketEncryptionType="0x17"
   | bin _time span=5m
   | stats dc(ServiceName) AS spn_count BY TargetUserName, ClientAddress, _time
   | where spn_count > 5
   ```
4. Verify cracking activity vs legitimate service starts:
   - Legit: same `TargetUserName` repeatedly hitting same `ServiceName` (running app), often AES (0x12).
   - Roast: one `TargetUserName` hitting many distinct `ServiceName` in seconds, RC4.
5. Cross-correlate the attacker workstation's 4624 logon events to attribute to a domain user.

## Verifying success

- `TargetUserName` and `ClientAddress` in 4769 match a known account/IP that does **not** legitimately consume those services.
- Encryption type is RC4 (0x17/0x18). Modern AES default is 0x12 (AES-256) or 0x11 (AES-128).
- 4769 burst aligns with later 4624 from a foreign IP under a service account whose hash was crackable.

## Common pitfalls

- Many legacy services run AES-incompatible Java/SQL builds, generating constant-rate 0x17 traffic. Baseline first; alert on **change**.
- `TicketEncryptionType=0xffffffff` indicates `KERB_VALIDATION_FAILURE`; not a successful roast.
- 4768 PreAuthType=0 is **also** logged for legitimate accounts with the flag — the signal is *which* user account, not whether the event fires.
- Service accounts that register their own SPNs (SQL Server, ADFS) generate 4769 to themselves at boot; filter by user-vs-machine.
- Domain Controllers themselves request TGS at startup — SubjectUserName ending in `$` is normal.

## Tools

- `python-evtx` parsing of `Security.evtx`
- Splunk / Elastic / Sentinel queries above
- `Sigma`: `proc_creation_win_kerberoasting.yml`, `win_security_kerberoast_spn_request.yml`
- Detection-as-code: `chainsaw hunt evidence/ --sigma rules/`
