# GraphQL Endpoint Discovery

## When this applies

- Target exposes an API surface that may include GraphQL alongside REST.
- You need to enumerate every GraphQL endpoint (some apps host multiple) before any testing.
- Application uses non-standard paths or content-types.

## Technique

Probe a wordlist of GraphQL paths with `{__typename}`. Confirm via `{"data":{"__typename":"query"}}`. Try GET, POST JSON, POST form, POST `application/graphql` — apps may accept multiple variants and CSRF testing depends on which.

## Steps

### Common GraphQL endpoints

```
/graphql
/api
/api/graphql
/graphql/api
/v1/graphql
/v2/graphql
/gql
/query
/graph
/graphql/console
/graphql.php
/api/v1/graphql
/api/v2/graphql
```

### Discovery requests

**Universal Query:**
```http
POST /graphql HTTP/1.1
Content-Type: application/json

{"query":"{__typename}"}
```

**Expected Response:**
```json
{"data":{"__typename":"query"}}
```

**GET Method:**
```http
GET /graphql?query={__typename} HTTP/1.1
```

**Alternative Content-Types:**
```http
# JSON (standard)
Content-Type: application/json

# URL-encoded (CSRF-vulnerable)
Content-Type: application/x-www-form-urlencoded

# GraphQL-specific
Content-Type: application/graphql

# Form data
Content-Type: multipart/form-data
```

### Automated discovery script

```bash
#!/bin/bash
# graphql-discover.sh

DOMAIN=$1
PATHS=("graphql" "api" "api/graphql" "v1/graphql" "gql" "query" "graph")

for path in "${PATHS[@]}"; do
  echo "[*] Testing: https://$DOMAIN/$path"

  response=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d '{"query":"{__typename}"}' \
    "https://$DOMAIN/$path")

  if [[ $response == *"__typename"* ]]; then
    echo "[+] FOUND: https://$DOMAIN/$path"
  fi
done
```

**Usage:**
```bash
chmod +x graphql-discover.sh
./graphql-discover.sh target.com
```

## Verifying success

- Endpoint returns `{"data":{"__typename":"query"}}` (or `Mutation`/`Subscription`).
- Multiple content-types succeed (CSRF surface if `application/x-www-form-urlencoded` is accepted).
- GET method works (cache poisoning surface).

## Common pitfalls

- Some apps return `200` with an HTML page for unknown paths — check for the `data.__typename` pattern, not just status code.
- Apollo Server returns `{"errors":[...]}` even on partial responses — endpoint is still confirmed.
- WAFs may rewrite the path; test both `/graphql` and `/api/graphql`.

## Tools

- curl, ffuf
- Burp Suite Repeater
- Burp InQL Scanner BApp
- graphql-cop, Clairvoyance
