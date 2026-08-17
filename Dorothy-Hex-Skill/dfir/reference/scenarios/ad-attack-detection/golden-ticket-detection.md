# Golden Ticket Detection

## When this applies

Hunting forged Kerberos TGTs minted by an attacker who has the krbtgt account's NT hash or AES key. A Golden Ticket lets the attacker authenticate as any account, with arbitrary group memberships, for the configured ticket lifetime.

## Technique

Forged TGTs bypass the AS exchange entirely — there is no `4768` for the user. Instead, they appear as `4769` (TGS request) and `4624` (logon) anomalies. Detection focuses on:

1. **Missing AS-REQ**: `4769` without a preceding `4768` for the same `TargetUserName` in the relevant lifetime window.
2. **Anomalous TGT lifetime**: default Windows TGT is 10 hours, max-renew 7 days. Attackers typically forge 10-year tickets for persistence.
3. **Off-domain SIDs / mismatched domain**: ticket claims membership in a domain that doesn't match the user's actual home domain.
4. **Username anomalies**: legacy mimikatz forges `Administrator` even if RID 500 was renamed; the SID may not match.

## Steps

1. Build per-user 4768/4769 timeline:
   ```spl
   index=wineventlog (EventCode=4768 OR EventCode=4769)
   | stats count(eval(EventCode=4768)) AS asreq
           count(eval(EventCode=4769)) AS tgs
           min(_time) AS first last(_time) AS last
       BY TargetUserName
   | where asreq=0 AND tgs>0
   ```
   Users with TGS but zero AS-REQ over the audit window are golden-ticket suspects (or cached-ticket users — verify lifetime).
2. Detect 10-hour-violating ticket lifetimes — requires an extended auditing system (e.g., DC-side packet capture) since 4769 alone does not record TGT lifetime. Alternative: monitor 4634 logoff vs 4624 logon delta on workstations using the ticket.
3. Username/SID mismatch (4624 LogonType=3, network):
   ```spl
   index=wineventlog EventCode=4624 LogonType=3
   | search TargetUserSid=*
   | rex field=TargetUserSid "S-1-5-21-(?<dom>\d+-\d+-\d+)-(?<rid>\d+)$"
   | search NOT dom IN ("<your-domain-sid-1>","<your-domain-sid-2>")
   ```
   Foreign domain SIDs accessing local resources without an inter-domain trust suggest a forged ticket.
4. Mimikatz fingerprint — some mimikatz versions leave `Group Membership SIDs` containing `S-1-5-21-...-519` (Enterprise Admins) on accounts that should not have it. Pair 4624 with `Authentication Package = Kerberos` and a high-privilege group attribution that doesn't match the directory.
5. krbtgt password rotation telemetry — after rotation, all valid tickets are invalidated within the next TGS request cycle. Sudden burst of 4624 failures from previously-active sessions correlates with golden-ticket revocation.

## Verifying success

- 4769 events for a user with no preceding 4768 inside the TGT lifetime window, on the same DC.
- Ticket lifetime / renewal duration extracted from packet capture exceeds the domain max (10 hours / 7 days).
- 4624 LogonType=3 with a SID belonging to a domain not in the local trust list.

## Common pitfalls

- Cached tickets cause false positives: a workstation TGT obtained before the audit window can yield 4769 without 4768 in the window. Extend the lookback or compare against ticket cache (`klist`).
- "Ticket lifetime" is not in 4769 — stop trying to extract it from there. Use Kerberos packet capture or endpoint event 4770 (renewal) plus correlation.
- Mimikatz forgeries since 2.2 use proper SID structures. Don't depend on SID malformation alone.
- After krbtgt rotation, normal tickets break too — you may see widespread 4624 failures unrelated to attack. Communicate with admins before alerting.

## Tools

- `python-evtx` and Splunk/Elastic queries above
- DC packet capture (`netsh trace`) decoded via Wireshark Kerberos dissector for lifetime extraction
- `mimikatz` `kerberos::tickets /export` (on suspect endpoints, with authorization) to inspect ticket structure
- `Sigma`: `win_security_susp_eventcode_4769_no_4768.yml`, `win_admin_user_logon_anomaly.yml`
- `BloodHound` to validate group-membership claims in 4624 against actual AD
