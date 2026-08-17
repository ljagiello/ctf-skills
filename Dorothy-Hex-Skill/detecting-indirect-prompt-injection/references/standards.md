# Standards and References — Detecting Indirect Prompt Injection

## MITRE ATLAS References

| Technique ID | Name | Tactic | Rationale |
|--------------|------|--------|-----------|
| AML.T0051.001 | LLM Prompt Injection: Indirect | Initial Access | The precise technique detected — injection via ingested artifacts |
| AML.T0051 | LLM Prompt Injection | ML Attack Staging | Parent technique for all prompt-injection variants |
| AML.T0057 | LLM Data Leakage | Exfiltration | Common objective of indirect injection that detection prevents |
| AML.T0053 | LLM Plugin Compromise | Execution | Injected instructions frequently target agent tools/plugins |

## NIST AI RMF References

| ID | Name | Rationale |
|----|------|-----------|
| MEASURE-2.7 | AI system security and resilience are evaluated and documented | Content scanning measures/maintains agent resilience to injection |

## OWASP Top 10 for LLM Applications (2025)

| ID | Name | Rationale |
|----|------|-----------|
| LLM01:2025 | Prompt Injection | The risk this skill detects (indirect variant) |
| LLM02:2025 | Sensitive Information Disclosure | Prevented outcome of a successful indirect injection |

## Official Resources

- MITRE ATLAS: https://atlas.mitre.org/
- OWASP LLM01:2025: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- LLM Guard: https://llm-guard.com/
- Meta Prompt Guard 2: https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M
- ProtectAI prompt-injection classifier: https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2
- NIST AI RMF: https://www.nist.gov/itl/ai-risk-management-framework
