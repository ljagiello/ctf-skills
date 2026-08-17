# Standards and References — Continuous LLM Red Teaming with Promptfoo

## MITRE ATLAS Techniques

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| AML.T0051 | LLM Prompt Injection | LLM Attack | Core class of attack generated and regression-tested by the suite. |
| AML.T0051.000 | Direct Prompt Injection | LLM Attack | Injection delivered directly in the user prompt. |
| AML.T0051.001 | Indirect Prompt Injection | LLM Attack | Injection delivered via retrieved/external content. |
| AML.T0054 | LLM Jailbreak | LLM Attack | Jailbreak strategies (jailbreak, composite, crescendo) test guardrail bypass. |

## NIST AI RMF

| ID | Function | Rationale |
|----|----------|-----------|
| MANAGE-4.1 | Post-deployment monitoring plans are implemented; AI risks are tracked and managed | Continuous CI/CD red-teaming is the post-deployment monitoring control for LLM risk. |

## Official Resources

- Promptfoo red-team docs: https://www.promptfoo.dev/docs/red-team/
- Promptfoo configuration: https://www.promptfoo.dev/docs/red-team/configuration/
- Promptfoo CI/CD: https://www.promptfoo.dev/docs/integrations/ci-cd/
- Promptfoo GitHub: https://github.com/promptfoo/promptfoo
- DeepTeam GitHub: https://github.com/confident-ai/deepteam
- DeepTeam docs: https://www.trydeepteam.com/docs/getting-started
- OWASP Top 10 for LLM Applications: https://genai.owasp.org/

## Frameworks Tracked

- OWASP LLM Top 10 (`owasp:llm` preset)
- OWASP Agentic threats (`owasp:agentic` preset)
- MITRE ATLAS (Promptfoo ATLAS mapping)
