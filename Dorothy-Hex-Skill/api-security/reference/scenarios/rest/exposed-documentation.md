# Exposed API Documentation (Swagger / OpenAPI)

## When this applies

- Application uses an API server that auto-publishes Swagger/OpenAPI/ReDoc documentation.
- Documentation endpoint is reachable without authentication.
- Documentation includes operations (DELETE, ADMIN routes) that the regular UI never exercises.

## Technique

Walk back parent paths from a known API endpoint until you find the documentation index. Use the doc page's "Try it out" buttons (or the `openapi.json` directly) to discover privileged operations. Submit them with your existing authenticated session.

## Steps

### Discovery walk-back

```http
PATCH /api/user/wiener HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[token]

GET /api/user HTTP/1.1
→ Error: Missing user identifier

GET /api HTTP/1.1
→ Returns API documentation
```

Then in documentation, find DELETE operation, enter "carlos" as username, submit:
```http
DELETE /api/user/carlos HTTP/1.1
→ Success
```

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

### Workflow

1. Login with credentials and update profile to generate API traffic
2. In Burp Proxy → HTTP history, locate the auto-generated PATCH/PUT
3. Send to Repeater and remove the trailing identifier
4. Walk back through parent paths to find the documentation index
5. Right-click response → "Show response in browser"
6. In documentation, find the DELETE operation, enter target username
7. Submit deletion request

### Key vulnerabilities exploited

- API documentation exposed without authentication
- DELETE operations accessible to regular users
- No authorization checks on administrative operations

### Common mistakes (failures to avoid)

- Not checking parent paths of discovered endpoints
- Overlooking interactive documentation features
- Failing to test different HTTP methods

## Verifying success

- The doc page renders with all endpoints listed (queryable via the doc UI).
- Privileged operations (DELETE /api/user/{id}) succeed with your auth session.
- The target resource is gone / changed after submission.

## Common pitfalls

- Some apps gate `/api` (the doc) but leave `/openapi.json` or `/swagger.json` open — try both.
- The doc may list endpoints that require admin auth but your session is regular — you find the SHAPE of the API, not necessarily privileged access.
- WAFs may block `/swagger-ui.html` but not `/swagger.json`.

## Tools

- Burp Suite Repeater
- Burp OpenAPI Parser BApp
- ffuf with `Discovery/Web-Content/api/` wordlists
