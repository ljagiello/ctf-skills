---
name: injection
description: Injection vulnerability testing - SQL, NoSQL, OS Command, SSTI, XXE, and LDAP/XPath injection techniques.
---

# Injection

Test for injection vulnerabilities across all input vectors. Covers SQL, NoSQL, Command, SSTI, XXE, and LDAP injection.

## Techniques

| Type | Key Vectors |
|------|-------------|
| **SQL Injection** | In-band (union, error), Blind (boolean, time), Out-of-band |
| **NoSQL Injection** | Operator injection, JavaScript injection, aggregation pipeline |
| **Command Injection** | OS command separators, blind techniques, out-of-band |
| **SSTI** | Template engine detection, sandbox escape, RCE chains |
| **XXE** | Entity expansion, SSRF via XXE, blind XXE, parameter entities |
| **LDAP/XPath** | Filter manipulation, authentication bypass |

## Workflow

1. Identify injection points (parameters, headers, cookies, JSON fields)
2. Detect injection type with minimal probes
3. Exploit with context-appropriate payloads
4. Escalate (data extraction, RCE, file read)
5. Capture evidence and write PoC

## Reference

- `reference/sql-injection*.md` - SQL injection techniques
- `reference/nosql-injection*.md` - NoSQL injection techniques
- `reference/os-command-injection*.md` - OS command injection
- `reference/ssti*.md` - Server-side template injection
- `reference/xxe*.md` - XML external entity injection
- `reference/ldap-injection-quickstart.md` - LDAP filter injection: detection, auth bypass, blind boolean extraction via `(description=PREFIX*)` chaining
- `reference/xpath-injection-quickstart.md` - XPath injection (CWE-643): lxml/Java/Node sinks, `' or '1'='1' or 'a'='b` boolean oracle, blind char-by-char extraction recipe
