# Standards and References — Auditing MCP Servers for Tool Poisoning

## MITRE ATLAS References

| Technique ID | Name | Tactic | Rationale |
|--------------|------|--------|-----------|
| AML.T0010 | ML Supply Chain Compromise | Initial Access | A poisoned third-party MCP server compromises the agent supply chain |
| AML.T0051.001 | LLM Prompt Injection: Indirect | Initial Access | Poisoned tool descriptions are indirect injection into agent context |
| AML.T0053 | LLM Plugin Compromise | Execution | MCP tools are the agent's plugins; poisoning compromises them |
| AML.T0057 | LLM Data Leakage | Exfiltration | Poisoned tools commonly exfiltrate files/secrets |

## NIST AI RMF References

| ID | Name | Rationale |
|----|------|-----------|
| MANAGE-2.2 | Mechanisms are in place and applied to sustain the value of deployed AI systems | Auditing third-party MCP tools manages/sustains safe agent operation |

## OWASP MCP Top 10 (2025)

| ID | Name | Rationale |
|----|------|-----------|
| MCP03:2025 | Tool Poisoning | Primary risk this skill audits |
| MCP01:2025 | Prompt Injection | Poisoned descriptions inject the agent |

## Official Resources

- mcp-scan (Invariant Labs): https://github.com/invariantlabs-ai/mcp-scan
- Invariant Labs tool-poisoning disclosure: https://invariantlabs.ai/blog/introducing-mcp-scan
- OWASP MCP Top 10: https://owasp.org/www-project-mcp-top-10/
- Model Context Protocol spec: https://modelcontextprotocol.io/
- MITRE ATLAS: https://atlas.mitre.org/
- NIST AI RMF: https://www.nist.gov/itl/ai-risk-management-framework
