# Standards and Framework Mapping — Red-Teaming LLMs with garak

## MITRE ATLAS (Adversarial Threat Landscape for AI Systems)

| ID | Name | Rationale |
|----|------|-----------|
| AML.T0051 | LLM Prompt Injection | garak's `promptinject` and `latentinjection` probes craft inputs that override intended model instructions; the scanner measures how often the target obeys the injected directive. |
| AML.T0054 | LLM Jailbreak | garak's `dan` and related probes attempt to push the model past its safety guardrails so it produces restricted output; the detector verdict measures jailbreak success. |

Reference: https://atlas.mitre.org/

## NIST AI Risk Management Framework (AI RMF 1.0)

| ID | Function/Subcategory | Rationale |
|----|----------------------|-----------|
| MEASURE-2.7 | AI system security and resilience are evaluated and documented | garak produces repeatable, quantitative measurements (per-probe hit rates) of an LLM's resistance to injection, jailbreak, and leakage, directly evidencing this subcategory. |

Reference: https://www.nist.gov/itl/ai-risk-management-framework

## OWASP Top 10 for LLM Applications (cross-reference)

| OWASP ID | Risk | garak probe family |
|----------|------|--------------------|
| LLM01:2025 | Prompt Injection | promptinject, latentinjection, encoding, dan |
| LLM02:2025 | Sensitive Information Disclosure | leakreplay, xss |
| LLM07:2025 | System Prompt Leakage | leakreplay |

Reference: https://genai.owasp.org/
