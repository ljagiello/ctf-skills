# API Reconnaissance — Endpoint, Parameter, Method Discovery

## When this applies

- Initial recon stage on a target with a REST/GraphQL API.
- You need to enumerate the full API surface before targeted attacks.
- Multiple API versions / shadow APIs expected.

## Technique

Combine passive (JS/HTML/mobile traffic) and active (brute-force, OPTIONS, OpenAPI) recon. Map all endpoints, methods, parameters, and content-types before testing for logic flaws.

## Steps

### Passive reconnaissance

- HTML source code analysis for API references
- JavaScript file examination for API calls
- Browser DevTools network tab monitoring
- Mobile app traffic analysis
- Documentation and support pages
- Google dorking for exposed APIs

### Active reconnaissance

- Burp Suite crawling and spidering
- Directory brute-forcing with API wordlists
- Subdomain enumeration
- Port scanning for API services
- Common API path testing

### Common API documentation paths

```
/api
/api/v1, /api/v2
/swagger, /swagger-ui, /swagger-ui.html
/api-docs, /api/docs, /docs
/openapi.json, /swagger.json
/api/swagger.json
/v1/api-docs
/__docs__
/redoc
/graphql, /graphiql, /playground
```

### Finding hidden endpoints — Burp Intruder

1. Identify base path: `/api/users/update`
2. Replace segments with function names
3. Wordlists:
   - REST operations: create, read, update, delete, list, get, post, put, patch
   - CRUD: add, remove, edit, modify, fetch, retrieve
   - Admin: admin, manage, configure, settings

```
Base: PUT /api/user/update
Test: PUT /api/user/§delete§
Payloads: delete, remove, admin, list, get, create
```

### JS Link Finder BApp

- Auto-extracts endpoints from JavaScript
- Processes minified/bundled code
- Discovers undocumented endpoints

### Finding hidden parameters

**1. Param Miner BApp**
- Guesses up to 65,536 parameter names
- Context-aware intelligent guessing
- Tests GET, POST, headers, cookies

**2. Burp Intruder Parameter Discovery**

Common parameter names:
```
id, user_id, userid, username, email
token, access_token, api_key, key
role, admin, isAdmin, is_admin
price, discount, amount, total
password, new_password, current_password
page, limit, offset, count, size
format, type, content_type
callback, redirect, url, next
debug, verbose, trace
```

### ffuf for fuzzing

```bash
# Endpoint discovery
ffuf -u https://api.target.com/v1/FUZZ -w api-endpoints.txt

# Parameter discovery
ffuf -u https://api.target.com/user?FUZZ=value -w params.txt

# Method fuzzing
ffuf -u https://api.target.com/api -w methods.txt -X FUZZ
```

### Arjun

```bash
# Basic discovery
arjun -u https://api.target.com/endpoint

# Custom wordlist
arjun -u https://api.target.com/endpoint -w params.txt

# POST testing
arjun -u https://api.target.com/api -m POST
```

### Kiterunner

```bash
# Quick scan
kr scan https://api.target.com -w routes-large.kite

# Swagger discovery
kr brute https://api.target.com -w swagger-wordlist.txt

# With authentication
kr scan https://api.target.com -w routes.kite -H "Authorization: Bearer TOKEN"
```

### Nuclei

```bash
# API security scanning
nuclei -u https://api.target.com -t api/

# Custom templates
nuclei -u https://api.target.com -t my-api-templates/

# With rate limiting
nuclei -u https://api.target.com -rl 10 -t api/
```

### Wordlists

**SecLists Collection:**
```
Discovery/Web-Content/api/
- api-endpoints.txt
- api-endpoints-res.txt
- graphql.txt
- swagger.txt

Fuzzing/
- api-parameters.txt
- http-methods.txt
- content-types.txt
```

**Custom wordlist creation:**
```bash
# Extract endpoints from JavaScript
cat *.js | grep -oP '(?<=")\/api[^"]*' | sort -u > api-endpoints.txt

# Extract parameters from Burp history
jq -r '.[] | .request.url' burp-history.json | grep -oP '\?[^&]+' > params.txt

# Common patterns
/api/v{1..5}/{users,products,orders,admin}/{create,read,update,delete,list}
```

## Verifying success

- A complete map of endpoints with supported methods, request schemas, and authentication requirements.
- Multiple API versions discovered (v1, v2, internal).
- Hidden / undocumented operations (admin, debug, batch endpoints) identified.

## Common pitfalls

- Some endpoints respond identically for valid/invalid paths — use response timing or size differential.
- Mobile apps often expose richer APIs than web — hook the app traffic via Frida/proxy.
- API versions may live on different subdomains/ports — full recon includes DNS + port scanning.
- A discovery/allowlist endpoint (`/tools/list`, `/_catalog`, swagger) is **not** the full surface — servers often dispatch undocumented operations the listing omits. Guess hidden names (`admin_`/`_admin_`/`debug_`/`dump`/`exec` variants) and read source when reachable; see [scenarios/mcp/inspector-stdio-rce.md](../mcp/inspector-stdio-rce.md) Part 2.

## Tools

- ffuf, Arjun, Kiterunner, Nuclei
- Burp Suite (Spider, Intruder, OpenAPI Parser, Param Miner, JS Link Finder)
- mitmproxy / Frida (mobile)
- ZAP, OWASP ZAP scripts
