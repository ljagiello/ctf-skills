---
name: ai-threat-testing
description: Offensive AI security testing and exploitation framework. Systematically tests LLM applications for OWASP Top 10 vulnerabilities including prompt injection, model extraction, data poisoning, and supply chain attacks. Integrates with pentest workflows to discover and exploit AI-specific threats.
---

# AI Threat Testing

Test LLM applications for OWASP LLM Top 10 vulnerabilities using 10 specialized agents. Use for authorized AI security assessments.

## Quick Start

```
1. Specify target (LLM app URL, API endpoint, or local model)
2. Select scope: Full OWASP Top 10 | Specific vulnerability | Supply chain
3. Agents deploy, test, capture evidence
4. Professional report with PoCs generated
```

## Primary Agents

Each agent targets one OWASP LLM vulnerability:

1. **Prompt Injection** (LLM01): Direct/indirect injection, system prompt extraction
2. **Output Handling** (LLM02): Code/XSS injection, unsafe deserialization
3. **Training Poisoning** (LLM03): Membership inference, backdoors, data extraction
4. **Resource Exhaustion** (LLM04): Token flooding, DoS, cost impact
5. **Supply Chain** (LLM05): Dependency scanning, plugin security
6. **Excessive Agency** (LLM06): Privilege escalation, unauthorized actions
7. **Model Extraction** (LLM07): Query-based theft, data reconstruction
8. **Vector Poisoning** (LLM08): RAG injection, retrieval manipulation
9. **Overreliance** (LLM09): Hallucination testing, confidence manipulation
10. **Logging Bypass** (LLM10): Monitoring evasion, forensic gaps

See `reference/llm0X-*.md` for attack playbooks.

## Workflows

**Full Assessment** (4-8 hours):
```
- [ ] Reconnaissance
- [ ] Deploy all 10 agents
- [ ] Execute exploits
- [ ] Capture evidence
- [ ] Generate report
```

**Focused Testing** (1-3 hours):
```
- [ ] Select vulnerability (LLM01-10)
- [ ] Deploy agent
- [ ] Execute techniques
- [ ] Document findings
```

**Supply Chain Audit** (2-4 hours):
```
- [ ] Inventory dependencies
- [ ] Scan CVEs
- [ ] Test plugins/APIs
- [ ] Verify model provenance
```

## Integration

Enhances `/pentest` with AI-specific testing:
- Traditional pentesting + AI threat testing = complete security assessment
- Chain vulnerabilities across traditional and AI vectors
- Unified reporting with CVSS scores

## Key Techniques

**Prompt Injection**: Instruction override, system prompt extraction, filter evasion
**Model Extraction**: Query sampling, token analysis, membership inference
**Data Poisoning**: Behavioral anomalies, backdoor triggers, bias analysis
**DoS**: Token flooding, recursive expansion, context exhaustion
**Supply Chain**: CVE scanning, plugin audit, model verification
**MCP Tool Abuse**: MCP server inspectors/debuggers often expose `/api/mcp/connect` or similar endpoints that accept `serverConfig` with arbitrary `command` parameters — unauthenticated RCE. Check for MCP Inspector, MCP Playground, or any MCP debugging UI on non-standard ports (6274, 3000, etc.).

## Evidence Capture

All agents collect: screenshots, network logs, API responses, errors, console output, execution metrics.

## Reporting

Automated reports include: executive summary, detailed findings (CVSS scores), PoC scripts, evidence, remediation guidance.

## Critical Rules

- Written authorization REQUIRED before testing
- Never exceed defined scope
- Test in isolated environments when possible
- Document all findings with reproducible PoCs
- Follow responsible disclosure practices

## Integration

- Integrates with `/pentest` skill for comprehensive security testing
- AI-specific vulnerability knowledge in `/AGENTS.md`
- Attack playbooks in `reference/llm0X-*.md`
