# Standards and Framework Mapping

## NIST AI Risk Management Framework (AI RMF 1.0 / GenAI Profile NIST AI 600-1)

| ID | Name | Rationale |
|----|------|-----------|
| MEASURE-2.7 | AI system security and resilience are evaluated and documented | Assessing inversion, membership, isolation, and poisoning weaknesses measures the security/resilience of the RAG vector layer. |

## MITRE ATLAS

| ID | Name | Rationale |
|----|------|-----------|
| AML.T0024 | Exfiltration via ML Inference API | Parent technique: query/embedding access is abused to exfiltrate source data. |
| AML.T0024.000 | Infer Training Data Membership | Membership-inference probe determines whether a record is in the corpus. |
| AML.T0024.001 | Invert ML Model | Embedding inversion reconstructs source text from vectors. |
| AML.T0020 | Poison Training Data | Knowledge-base poisoning inserts adversarial chunks into the corpus. |
| AML.T0051.001 | LLM Prompt Injection: Indirect | Injection payloads surviving in retrieved chunks. |

## OWASP Top 10 for LLM Applications (2025)

| ID | Name | Rationale |
|----|------|-----------|
| LLM08 | Vector and Embedding Weaknesses | The core risk class under test (inversion, leakage, poisoning). |
| LLM02 | Sensitive Information Disclosure | Inversion/membership leakage discloses sensitive source data. |
| LLM01 | Prompt Injection | Indirect injection delivered through poisoned retrieval. |

## Weakness class to control mapping

| Weakness | Control |
|----------|---------|
| Embedding inversion | Authenticate + rate-limit embedding endpoint; avoid exposing raw scores. |
| Membership inference | Restrict similarity-score exposure; add query auditing. |
| Cross-tenant leakage | Server-side tenant filters or per-tenant collections/namespaces. |
| Knowledge-base poisoning | Provenance tagging, content validation, per-source retrieval caps. |
| Indirect injection in chunks | Sanitize retrieved text; apply output guardrails. |
