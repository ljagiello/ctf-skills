# GraphQL — Resources

## OWASP & Standards

- OWASP API Security Top 10 (2023) — https://owasp.org/API-Security/
- OWASP Cheat Sheet — GraphQL — https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- GraphQL Specification — https://spec.graphql.org/
- RFC 6749 (OAuth 2.0) for GraphQL auth
- GraphQL over HTTP — https://github.com/graphql/graphql-over-http

## Notable CVEs

- CVE-2024-37292 — GraphQL Java introspection bypass via whitespace
- CVE-2023-44366 — Apollo Sandbox CSRF
- CVE-2022-23806 — graphql-go-tools query depth bypass
- CVE-2021-23358 — GraphQL.js — DoS via deep query
- CVE-2020-28924 — Hasura GraphQL Engine — auth bypass
- CVE-2019-18377 — GraphiQL stored XSS
- Apollo Server CSRF prevention bypasses (multiple)

## Testing tools

### Burp extensions

- **InQL Scanner** — auto-introspection, query template generation, scanner checks
- **GraphQL Raider** — schema visualization, query builder, mutation testing
- **Autorize** — cross-role authorization testing
- **HTTP Request Smuggler** — covers GraphQL-over-HTTP smuggling
- **Param Miner** — find unkeyed params

### Standalone

- **Clairvoyance** — schema reconstruction when introspection blocked — https://github.com/nikitastupin/clairvoyance
- **graphql-cop** — security audit (introspection, alias DoS, batch attack) — https://github.com/dolevf/graphql-cop
- **GraphQL Voyager** — visualize schema — https://github.com/IvanGoncharov/graphql-voyager
- **GraphQL Playground / Altair / GraphiQL** — interactive clients
- **graphql-shield** — declarative permission layer (defensive)
- **graphql-armor** — depth/cost limits middleware (defensive)
- **gleeQL / batchql** — alias-based brute-force tools

## Frameworks (vulnerability landscape)

- Apollo Server (Node) — historical CSRF / introspection issues
- graphql-java — JVM, depth/cost limits required
- graphql-ruby — schema directives, authorization checks
- Hasura — auth bypass class CVEs
- PostGraphile — type-coercion paths
- Strawberry / Ariadne (Python)
- Lighthouse / WPGraphQL (PHP)

## Attack technique writeups

- "GraphQL Common Vulnerabilities" — https://github.com/righettod/graphql-attack-tools
- "Hacking GraphQL Endpoints" — Doyensec, Synopsys
- "GraphQL Batching Attack" — escape.tech blog
- HackerOne disclosed reports tagged `graphql`
- Bishop Fox / NCC Group GraphQL whitepapers
- `swisskyrepo/PayloadsAllTheThings/GraphQL Injection`

## Detection / SIEM

- Apollo Server logging plugins
- DataDog / NewRelic GraphQL APM
- ModSecurity rules tagged GraphQL (block `__schema`, large alias batches)
- AWS WAF custom rules

## Research papers

- Stuttard, "Server-Side Parameter Pollution"
- Doyensec — "Authentication Issues in GraphQL"
- 42Crunch — "GraphQL Security in Practice"
- "GraphQL: A Critical Review" (NCC Group)
- HackerOne — "How to Find Your First Bug in GraphQL"

## Practice / labs

- TryHackMe — GraphQL rooms
- PortSwigger Web Security Academy — https://portswigger.net/web-security/graphql
- DVGA (Damn Vulnerable GraphQL Application) — https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application

## Wordlists

- SecLists `Discovery/Web-Content/graphql.txt`
- SecLists `Fuzzing/api-parameters.txt`
- Custom names from JS bundle extraction

## Bug bounty programs (GraphQL scope)

- HackerOne / GitHub / Shopify / GitLab / Twitter (X) / Slack / Asana — all run GraphQL APIs

## Defensive references

- Apollo Server hardening — https://www.apollographql.com/docs/apollo-server/security/
- graphql-armor middleware — depth, cost, alias, directive, token limits
- graphql-shield — permission rules
- Persisted queries — eliminate arbitrary-query DoS
- Disable introspection in production

## Tools archive (one-liners)

```bash
# Introspection probe
curl -X POST https://target/graphql -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}'

# Field enumeration
clairvoyance -o schema.json -w wordlist.txt https://target/graphql

# Audit
graphql-cop -t https://target/graphql --csrf --dos --dirb
```
