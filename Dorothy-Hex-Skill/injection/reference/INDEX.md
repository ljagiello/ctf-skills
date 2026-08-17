# Injection — Scenario Index

Read `injection-principles.md` first for the decision tree and sequencing principles. This index maps fingerprints to scenario files.

## SQL Injection

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Login form / WHERE clause concat | `scenarios/sql/auth-bypass.md` | `admin'--`, `' OR '1'='1` tautology |
| Visible response, need to extract | `scenarios/sql/union-based.md` | UNION SELECT for column count + data |
| Verbose DB errors visible | `scenarios/sql/error-based.md` | CAST/CONVERT to leak data in errors |
| Boolean response diff, no errors | `scenarios/sql/boolean-blind.md` | Boolean oracle + char-by-char extraction |
| No diff, no errors, no UNION | `scenarios/sql/time-based-blind.md` | `SLEEP`/`pg_sleep`/`WAITFOR` timing oracle |
| Async / no in-band channel | `scenarios/sql/out-of-band.md` | DNS/HTTP exfil via Burp Collaborator |
| Stored input concatenated later | `scenarios/sql/second-order.md` | Register payload + trigger second path |
| Multi-statement support (MSSQL/PG) | `scenarios/sql/stacked-queries.md` | `;`-stacked INSERT/UPDATE/EXEC |
| WAF blocks straightforward payloads | `scenarios/sql/waf-bypass.md` | Encoding, comments, keyword nesting |
| Hidden filter (`published=1`) appended | `scenarios/sql/where-clause-filter-bypass.md` | OR-tautology to negate filter |
| Headers flow into queries | `scenarios/sql/header-injection.md` | Spray markers across all custom headers |

## Per-DBMS Reference

| DBMS | Scenario file | Quick fingerprint |
|---|---|---|
| MySQL / MariaDB | `scenarios/sql/per-dbms-mysql.md` | `SELECT @@version`, `SLEEP(N)`, `#` comment |
| PostgreSQL | `scenarios/sql/per-dbms-postgres.md` | `SELECT version()`, `pg_sleep(N)`, `||` concat |
| Microsoft SQL Server | `scenarios/sql/per-dbms-mssql.md` | `SELECT @@version`, `WAITFOR DELAY`, `+` concat |
| Oracle | `scenarios/sql/per-dbms-oracle.md` | `SELECT banner FROM v$version`, `dbms_pipe`, `FROM dual` |

## NoSQL Injection

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| MongoDB JSON body `db.find(req.body)` | `scenarios/nosql/mongo-operator-injection.md` | `$ne`, `$gt`, `$regex` for auth bypass |
| MongoDB `$where` JS predicate | `scenarios/nosql/mongo-where-jsinjection.md` | `||'a'=='b` boolean blind extraction |
| MongoDB string-concat into query | `scenarios/nosql/mongo-syntax-injection.md` | Tautology mirrors SQLi `' OR '1'='1` |
| MongoDB aggregation pipeline | `scenarios/nosql/mongo-aggregation-pipeline.md` | `$lookup` cross-collection, `$function` JS |
| URL-encoded `[bracket]` form parser | `scenarios/nosql/mongo-type-confusion.md` | `password[$ne]=` → `{$ne:""}` |
| SSRF + gopher to Redis | `scenarios/nosql/redis-ssrf-gopher.md` | Gopherus → webshell / SSH key / cron |
| Cassandra on 9042 | `scenarios/nosql/cassandra-cql.md` | Default creds + Java UDF RCE |
| Elasticsearch inline-script proxy | `scenarios/nosql/elasticsearch-script-injection.md` | Raw `'` survives quote-strip → Rhino breakout (`'x'||true||''`); ES ≤5.x scripting RCE |

## Server-Side Template Injection (SSTI)

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| `render_template_string(stored_value)` (input rendered twice) + substring blocklist for `__`/`file`/`write` + autoescape entitizes quotes | `scenarios/ssti/double-render-quote-free-bypass.md` | Build `__` from `(config\|list)[5][6]` + identifier strings from `dict(name=1)\|first`, command via hex in `?c=` query |

See also: `ssti-quickstart.md`, `ssti-cheat-sheet.md`, `ssti-advanced.md` for engine-fingerprint and per-engine sandbox-escape primitives.
