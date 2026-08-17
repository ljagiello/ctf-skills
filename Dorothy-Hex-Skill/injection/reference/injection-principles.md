# Injection Principles

This file is the entry point for SQL/NoSQL injection scenarios. It contains decision logic for picking the right scenario and cross-cutting gotchas. Specific techniques live under `scenarios/<family>/<scenario>.md`. Use `INDEX.md` to pick a scenario by trigger.

## Decision tree

Pick the scenario family from the database / context fingerprint, then read the matching file from INDEX.md.

| Fingerprint | Family | Where to start |
|---|---|---|
| Login form / WHERE clause + visible response | `scenarios/sql/auth-bypass.md`, `scenarios/sql/union-based.md` | Tautology + UNION column count |
| Verbose SQL errors visible in HTTP response | `scenarios/sql/error-based.md` | CAST/CONVERT to leak data |
| Response differs based on injected boolean (no errors) | `scenarios/sql/boolean-blind.md` | Boolean oracle + char-by-char extraction |
| No boolean diff, no errors, no UNION | `scenarios/sql/time-based-blind.md` | `SLEEP`/`pg_sleep`/`WAITFOR` timing oracle |
| Async query / no in-band channel | `scenarios/sql/out-of-band.md` | DNS/HTTP exfil via Collaborator |
| Stored input later concatenated unsafely | `scenarios/sql/second-order.md` | Register payload + trigger second path |
| Multiple statement support (MSSQL/PG) | `scenarios/sql/stacked-queries.md` | `;`-stacked INSERT/UPDATE/EXEC |
| WAF blocks straightforward payloads | `scenarios/sql/waf-bypass.md` | Encoding, comments, keyword nesting |
| Hidden filter (e.g. `published=1`) appended | `scenarios/sql/where-clause-filter-bypass.md` | OR-tautology to negate filter |
| Headers (User-Agent, X-Forwarded-For) flow into queries | `scenarios/sql/header-injection.md` | Spray markers across all custom headers |
| MongoDB JSON body `db.users.find(req.body)` | `scenarios/nosql/mongo-operator-injection.md` | `$ne`, `$gt`, `$regex` |
| MongoDB `$where` JavaScript predicate | `scenarios/nosql/mongo-where-jsinjection.md` | Boolean blind with `||'a'=='b` closing |
| MongoDB string-concat into query | `scenarios/nosql/mongo-syntax-injection.md` | Tautology mirrors SQLi `' OR '1'='1` |
| MongoDB aggregate / pipeline endpoints | `scenarios/nosql/mongo-aggregation-pipeline.md` | `$lookup` cross-collection, `$function` JS |
| URL-encoded `[bracket]` form parser | `scenarios/nosql/mongo-type-confusion.md` | `password[$ne]=` becomes `{$ne:""}` |
| SSRF that allows `gopher://` | `scenarios/nosql/redis-ssrf-gopher.md` | Gopherus → webshell / SSH key / cron |
| Apache Cassandra reachable on 9042 | `scenarios/nosql/cassandra-cql.md` | Default creds + UDF Java RCE |

## Per-DBMS reference

After identifying the family, read the matching DBMS reference for syntax variants:

| DBMS | File |
|---|---|
| MySQL / MariaDB | `scenarios/sql/per-dbms-mysql.md` |
| PostgreSQL | `scenarios/sql/per-dbms-postgres.md` |
| Microsoft SQL Server | `scenarios/sql/per-dbms-mssql.md` |
| Oracle | `scenarios/sql/per-dbms-oracle.md` |

## Sequencing principles

1. **Detect first, then pick a class.** Spray `'`, `"`, `1+1`, `{"$ne":""}`, `' OR '1'='1`. Observe the response shape change before committing to one technique.
2. **In-band before out-of-band.** UNION/error-based reveal data in one request; blind requires hundreds. Always confirm whether output is visible before falling back to time-based.
3. **DBMS fingerprint before extraction.** `@@version`, `version()`, `banner FROM v$version` — knowing the dialect saves dozens of failed payloads.
4. **Test ALL parameters, including headers.** Hidden filters (`published=1`) and analytics-logged headers (User-Agent → DB) are the highest-yield overlooked surfaces.
5. **Read source code before exploitation.** If accessible, the query string and surrounding context are worth more than 100 blind probes.
6. **Single-thread time-based attacks.** Burp Intruder's default concurrency destroys timing oracles — always create a new resource pool with max concurrent = 1.
7. **Encoding mutates bytes; libinjection inspects shape.** Modern WAFs use semantic parsers — encoding tricks fail. Mutate the QUERY's structure (e.g. `SE/**/LECT`, `&&` aliases) when bytes alone aren't enough.
8. **Operator injection is more common than syntax injection on MongoDB.** Modern Mongoose/Node code uses object queries (operator injection works) more than string queries (syntax injection works).

## Cross-cutting gotchas

- **MySQL `--` requires a trailing space** (`-- `) or use `#` instead. The bare `--` is the subtraction operator.
- **Oracle SELECT requires `FROM dual`** for literal queries. `SELECT 'abc'` raises `ORA-00923: FROM keyword not found where expected`.
- **Stacked queries are usually disabled on MySQL/Oracle.** Only MSSQL and PostgreSQL natively support `;`-separated statements. Test before relying on `;`.
- **`secure_file_priv` blocks MySQL `INTO OUTFILE`** even with FILE privilege. Read `SHOW VARIABLES LIKE 'secure_file_priv';` to confirm.
- **`xp_cmdshell` requires sysadmin or sp_configure rights** on MSSQL, and is disabled by default. Need to enable before use:
  ```sql
  EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
  EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
  ```
- **PostgreSQL `COPY ... TO PROGRAM` requires SUPERUSER** (or `pg_execute_server_program` role on PG13+). Permission denied fails silently.
- **MongoDB `$where` is disabled** on MongoDB ≥ 4.4 by default (`security.javascriptEnabled: false`). Operator injection (`$ne`, `$regex`) still works.
- **`mongo-sanitize` strips `$`-prefixed keys.** Operator injection blocked at middleware. Switch to syntax injection inside string contexts (rare).
- **Schema validation libraries (Joi, Yup, Zod) catch type mismatches before the query runs.** Operator injection blocked — look for unvalidated routes (admin APIs, internal endpoints).
- **Some apps use `String(input)`** which coerces objects to `[object Object]`, breaking operator injection. Confirm runtime behavior, not just source.
- **Time-based blind requires single-threaded attack.** Concurrent requests destroy timing accuracy. Burp Intruder resource pool max concurrent = 1.
- **WAFs increasingly use libinjection (semantic parser).** Encoding tricks fool regex but not libinjection — when stuck, mutate query structure (keyword nesting, function aliases).
- **`secure_file_priv` and similar restrictions** apply to file-write primitives (LOAD_FILE, INTO OUTFILE, COPY ... TO). Always check privileges/config before attempting.
- **Default credentials are still a thing** — `cassandra:cassandra`, `redis:` (no auth), `mongo` (no auth on early versions). Always try defaults before injection.
