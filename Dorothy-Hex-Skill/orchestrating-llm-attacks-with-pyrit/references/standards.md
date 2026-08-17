# Standards and Framework Mapping — Orchestrating LLM Attacks with PyRIT

## MITRE ATLAS (Adversarial Threat Landscape for AI Systems)

| ID | Name | Rationale |
|----|------|-----------|
| AML.T0051 | LLM Prompt Injection | PyRIT orchestrators inject crafted instructions across conversation turns to make the target act against its intended constraints. |
| AML.T0054 | LLM Jailbreak | Crescendo and TAP iteratively defeat safety guardrails; the scorer confirms the moment restrictions are bypassed. |

Reference: https://atlas.mitre.org/

## NIST AI Risk Management Framework (AI RMF 1.0)

| ID | Subcategory | Rationale |
|----|-------------|-----------|
| MEASURE-2.7 | AI system security and resilience are evaluated and documented | PyRIT yields repeatable, scorer-graded measurements of an LLM's resistance to multi-turn adversarial pressure, evidencing this subcategory. |

Reference: https://www.nist.gov/itl/ai-risk-management-framework

## OWASP Top 10 for LLM Applications (cross-reference)

| OWASP ID | Risk | PyRIT relevance |
|----------|------|-----------------|
| LLM01:2025 | Prompt Injection | RedTeaming/Crescendo/TAP orchestrators automate injection. |
| LLM02:2025 | Sensitive Information Disclosure | Objective scorers can target data/secret leakage. |
| LLM07:2025 | System Prompt Leakage | Objectives can be set to extract the system prompt. |

Reference: https://genai.owasp.org/
