# Standards and References — Detecting Model Extraction Attacks

## MITRE ATLAS Techniques

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| AML.T0024 | Exfiltration via AI Inference API | Exfiltration | Parent technique: abusing the inference API to steal model value or training data. |
| AML.T0024.000 | Infer Training Data Membership | Exfiltration | Membership inference — determine if a record was in the training set (privacy leak). |
| AML.T0024.001 | Invert AI Model | Exfiltration | Model inversion — reconstruct training inputs from confidence scores. |
| AML.T0024.002 | Extract ML Model | Exfiltration | Model stealing — train a surrogate from query/response pairs to clone the model. |

## NIST AI RMF

| ID | Function | Rationale |
|----|----------|-----------|
| MEASURE-2.6 | AI system security and resilience are evaluated and documented | Extraction/inference testing measures and documents the model's resilience to inference-API abuse. |

## Official Resources

- MITRE ATLAS AML.T0024: https://atlas.mitre.org/techniques/AML.T0024
- MITRE ATLAS Matrix: https://atlas.mitre.org/matrices/ATLAS
- Adversarial Robustness Toolbox (Trusted-AI): https://github.com/Trusted-AI/adversarial-robustness-toolbox
- NIST AI Risk Management Framework: https://www.nist.gov/itl/ai-risk-management-framework

## Key Research

- Tramèr et al., "Stealing Machine Learning Models via Prediction APIs" (USENIX Security 2016)
- Shokri et al., "Membership Inference Attacks Against Machine Learning Models" (IEEE S&P 2017)
- Orekondy et al., "Knockoff Nets: Stealing Functionality of Black-Box Models" (CVPR 2019)
