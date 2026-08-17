# NoSQL Injection — Resources and References

## OWASP

- **WSTG NoSQL Injection** — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection
- **NoSQL Security Cheat Sheet** — https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html
- **NodeGoat Tutorial** — https://ckarande.gitbooks.io/owasp-nodegoat-tutorial/content/tutorial/a1_-_sql_and_nosql_injection.html
- **OWASP Top 10:2025 — A05 Injection** — https://owasp.org/Top10/2025/A05_2025-Injection/

Key recommendations: disable client-controlled operators (`mongo-sanitize`); use ODM/ORM (Mongoose, Spring Data); allowlist input validation; type-check inputs; disable JavaScript execution server-side (`--noscripting`).

## Standards

- **MongoDB Security Checklist** — https://www.mongodb.com/docs/manual/administration/security-checklist/
- **CWE-943** — Improper Neutralization of Special Elements in Data Query Logic.
- **CWE-89** — SQL Injection (parent class; NoSQL is a subset).
- **NIST SP 800-53 SI-10** — Information Input Validation.

## Notable CVEs

| CVE | Component | Issue |
|---|---|---|
| CVE-2024-37032 | Ollama | NoSQL injection in chat history |
| CVE-2024-2912 | OpenWebUI | MongoDB injection |
| CVE-2023-45290 | Go encoding/json | JSON parsing bypass |
| CVE-2022-39328 | Grafana | NoSQL injection |
| CVE-2021-32820 | express-fileupload | NoSQL injection chain |
| CVE-2021-39134 | Ghost | Mongoose ODM bypass |
| CVE-2020-9394 | RouterOS | NoSQL bypass |
| CVE-2019-13497 | Yaws web server | CouchDB injection |
| CVE-2017-15945 | Express middleware | NoSQL injection |
| CVE-2016-2079 | Bagisto | Cassandra CQL injection |

Always run `python3 tools/nvd-lookup.py <CVE>` for current scoring.

## Tools

- **NoSQLMap** — https://github.com/codingo/NoSQLMap (sqlmap analog for NoSQL)
- **Nosql-MongoDB-injection-username-password-enumeration** — username enumeration via $regex
- **mongo-sanitize** — defense (server-side input sanitization)
- **Burp Suite Intruder** — operator/character extraction
- **MongoDB Compass** — DB introspection during testing
- **Gopherus** — Redis SSRF payload generator
- **redis-rogue-server** — Redis 4.x/5.x RCE via slave replication

## Wordlists

- **SecLists / Discovery / Web-Content / NoSQL-Injection.txt**
- **PayloadsAllTheThings / NoSQL Injection** — comprehensive payload reference.

## Implementation reference

| Database | Driver | Notes |
|---|---|---|
| MongoDB | mongoose (Node) | Schema-defined; auto-casts inputs |
| MongoDB | pymongo (Python) | Lower-level; manual input handling |
| MongoDB | mongo-go-driver (Go) | Type-safe; safe by default |
| Redis | redis-py / ioredis / lettuce | Plain-text protocol; SSRF risk |
| CouchDB | nano (Node), couchdb-python | HTTP-based; SQL-like view queries |
| Cassandra | cassandra-driver (Python/Node/Java) | CQL syntax |
| DynamoDB | boto3 (Python), aws-sdk (Node) | Largely safe by API design |
| Firebase Realtime DB | firebase-admin SDK | Custom rule-based access control |
| Elasticsearch | elasticsearch-py | Query DSL injection possible |

## Research / Reading

- **NoSQL Injection by Petko Petkov (2010)** — original taxonomy.
- **MongoDB Injection (PortSwigger Research)**.
- **Hacking NoSQL** — Sergio Ortega.
- **PortSwigger Web Security Academy — NoSQL Injection** (free labs).
- **Synack research blog** — periodic NoSQL writeups.
- **Aqua Security blog** — container/K8s NoSQL exposures.

## Bug bounty / Lab

- **HackerOne** — common in MongoDB-backed apps.
- **PortSwigger labs** — free NoSQL injection exercises.
- **DVWA** — local lab (some NoSQL modules).
- **OWASP NodeGoat** — Node.js + MongoDB lab.

## Database-specific docs

- **MongoDB Operators Reference** — https://www.mongodb.com/docs/manual/reference/operator/
- **CouchDB Mango / Selector Syntax** — https://docs.couchdb.org/en/stable/api/database/find.html
- **Cassandra CQL Reference** — https://cassandra.apache.org/doc/latest/cassandra/cql/
- **Redis Commands** — https://redis.io/commands/
- **Elasticsearch Query DSL** — https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html

## Compliance

- **PCI DSS v4.0.1** — applies to NoSQL holding cardholder data.
- **HIPAA** — NoSQL holding PHI must enforce access control.
- **GDPR Art. 32** — security of processing.
- **NIST SP 800-53 SI-10** — input validation.

## Defense reference

- **mongo-sanitize** (Node) — strips `$`-prefixed keys.
- **Mongoose schema validation** — type enforcement.
- **NoSQL drivers' parameterized queries** — equivalent of prepared statements.
- **`--noscripting` startup flag** (MongoDB) — disables server-side JS.
- **`security.javascriptEnabled: false`** in mongod.conf — same as `--noscripting`.
- **Redis ACLs** (Redis 6+) — restrict commands.
- **Redis `protected-mode yes`** — block external connections.

## Key takeaways

1. Server-side input validation; never trust JSON structure.
2. Disable JavaScript execution (`$where`) when not needed.
3. Use ODM/ORM with strict schemas (Mongoose, Spring Data).
4. Strip `$`-prefixed keys (mongo-sanitize).
5. Block private-IP egress to prevent SSRF → Redis chains.
6. Cassandra default credentials are common — change them.
7. Redis must be bound to localhost or behind ACLs.
8. Audit every endpoint that accepts JSON bodies for operator injection.
9. Test BOTH JSON content-type and URL-encoded form parsers.
10. Combine NoSQL injection with secondary attacks (XSS, SSRF, type confusion).
