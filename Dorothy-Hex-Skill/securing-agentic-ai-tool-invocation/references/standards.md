# Standards and References — Securing Agentic AI Tool Invocation

## MITRE ATLAS References

| Technique ID | Name | Tactic | Rationale |
|--------------|------|--------|-----------|
| AML.T0053 | LLM Plugin Compromise | Execution | Agent tools/plugins are the asset these controls protect |
| AML.T0051 | LLM Prompt Injection | ML Attack Staging | Injection is the primary vector that abuses tool invocation |
| AML.T0051.001 | LLM Prompt Injection: Indirect | Initial Access | Indirect injection via tool results drives unauthorized calls |
| AML.T0057 | LLM Data Leakage | Exfiltration | Excessive agency leads to leakage that these controls prevent |

## NIST AI RMF References

| ID | Name | Rationale |
|----|------|-----------|
| GOVERN-1.3 | Processes, procedures, and practices are in place to determine and manage AI risks and benefits | Governance of autonomous tool invocation (allowlisting, approvals, audit) |

## OWASP Agentic AI Top 10

| Class | Name | Rationale |
|-------|------|-----------|
| Tool Misuse | Agent abuses available tools | Allowlist + argument validation mitigates |
| Excessive Agency | Agent acts beyond intended scope | Policy gate + HITL mitigates |
| Privilege Compromise | Agent escalates via broad credentials | Scoped identity binding mitigates |

## Official Resources

- NVIDIA NeMo Guardrails: https://github.com/NVIDIA/NeMo-Guardrails
- OWASP Agentic AI threats & mitigations: https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/
- MITRE ATLAS: https://atlas.mitre.org/
- AWS STS session policies: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#policies_session
- NIST AI RMF: https://www.nist.gov/itl/ai-risk-management-framework
