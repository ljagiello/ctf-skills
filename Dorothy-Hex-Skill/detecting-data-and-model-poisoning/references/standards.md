# Standards and References — Detecting Data and Model Poisoning

## MITRE ATLAS References

| Technique ID | Name | Tactic | Rationale |
|--------------|------|--------|-----------|
| AML.T0020 | Poison Training Data | ML Attack Staging | Injection of manipulated samples into the training corpus |
| AML.T0018 | Backdoor ML Model | Persistence | Trigger-activated hidden behavior in the trained model |
| AML.T0010 | ML Supply Chain Compromise | Initial Access | Poisoned public datasets / trojaned downloaded weights |
| AML.T0024 | Exfiltration via ML Inference API | Exfiltration | Some poisoning leaks data via model responses |

## NIST AI RMF References

| ID | Name | Rationale |
|----|------|-----------|
| MEASURE-2.7 | AI system security and resilience are evaluated and documented | Poisoning detection measures the integrity/resilience of the ML pipeline |

## OWASP Top 10 for LLM Applications (2025)

| ID | Name | Rationale |
|----|------|-----------|
| LLM04:2025 | Data and Model Poisoning | Primary risk this skill detects |
| LLM03:2025 | Supply Chain | Trojaned weights/datasets entry path |

## Official Resources

- Adversarial Robustness Toolbox: https://github.com/Trusted-AI/adversarial-robustness-toolbox
- ART poisoning defenses docs: https://adversarial-robustness-toolbox.readthedocs.io/en/latest/modules/defences/detector_poisoning.html
- Cleanlab: https://github.com/cleanlab/cleanlab
- safetensors: https://github.com/huggingface/safetensors
- OWASP LLM04:2025: https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/
- MITRE ATLAS: https://atlas.mitre.org/
- NIST AI RMF: https://www.nist.gov/itl/ai-risk-management-framework
