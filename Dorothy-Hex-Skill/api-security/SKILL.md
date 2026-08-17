---
name: api-security
description: API security testing - GraphQL, REST API, WebSocket, and Web-LLM attack techniques.
---

# API Security

Test API endpoints for security vulnerabilities across REST, GraphQL, WebSocket, and LLM-integrated APIs.

## Techniques

| Type | Key Vectors |
|------|-------------|
| **GraphQL** | Introspection, batching attacks, nested query DoS, field suggestion |
| **REST API** | BOLA/IDOR, mass assignment, rate limiting, auth bypass, versioning |
| **WebSocket** | Cross-site hijacking, message manipulation, auth flaws |
| **Web-LLM** | Prompt injection via API, excessive agency, data exfiltration |

## Workflow

1. Discover API endpoints and documentation (Swagger, GraphQL schema)
2. Map authentication and authorization mechanisms
3. Test per API type using appropriate techniques
4. Validate data exposure and access control flaws
5. Capture evidence with HTTP request/response logs

## Reference

- `reference/graphql*.md` - GraphQL attack techniques and labs
- `reference/scenarios/rest/*.md` - REST API security testing (BOLA/BOPLA, mass assignment, SSPP, content-type confusion)
- `reference/websockets*.md` - WebSocket vulnerability testing
- `reference/web-llm*.md` - Web-LLM attack techniques and labs
