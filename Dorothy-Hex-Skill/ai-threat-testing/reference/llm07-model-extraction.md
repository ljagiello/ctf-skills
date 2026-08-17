# Agent: LLM07 Model Extraction / Model Theft Testing

## Core Responsibilities

- Test query-based model extraction attacks
- Perform membership inference attacks
- Attempt model property inference
- Test training data reconstruction
- Evaluate model information leakage

## Methodology

### Phase 1: Reconnaissance
- Profile model behavior patterns
- Identify output information leakage
- Test confidence/probability access
- Analyze response characteristics
- Measure query cost/limitations

### Phase 2: Membership Inference
- Design targeted queries
- Test if specific data was in training set
- Analyze model certainty variations
- Measure information leakage
- Extract training data boundaries

### Phase 3: Model Extraction
- **Query sampling**: Repeated queries for behavior mapping
- **Confidence extraction**: Access token probabilities
- **Logit analysis**: Analyze score distributions
- **Decision boundary mapping**: Map decision boundaries
- **Behavior cloning**: Replicate model behavior

### Phase 4: Model Property Inference
- **Architecture detection**: Infer model architecture
- **Training approach inference**: Detect training method
- **Hyperparameter estimation**: Estimate training parameters
- **Fine-tuning detection**: Identify fine-tuned models
- **Capability profiling**: Map model capabilities

### Phase 5: Data Reconstruction
- **Prompt injection for data**: Extract training examples
- **Model inversion**: Reconstruct training data
- **Memorization testing**: Identify memorized content
- **Exact match detection**: Find exact training data
- **Privacy violation**: Demonstrate data leakage

### Phase 6: Adversarial Inputs Against Classifier-Backed Endpoints
- L0-bounded pixel attacks when the user controls a small number of input dimensions and the server gates a decision on the predicted class — see [adversarial-pixel-attacks.md](adversarial-pixel-attacks.md). Always inspect the model's final-layer activation before computing gradients (softmax-fused heads silently break gradient-based attacks).

## Tools & Techniques

**Query-Based Extraction**:
- Sequential API queries to reconstruct behavior
- Black-box distillation (creating student model)
- Decision boundary exploration
- Systematic capability mapping
- Budget-aware querying (minimize cost)

**Membership Inference**:
- Confidence/loss measurement on suspect data
- Threshold-based membership testing
- Shadow model training
- Membership probability estimation
- Privacy metric evaluation

**Extraction Attacks**:
- Token probability extraction
- Logit access and analysis
- Attention weight exposure
- Gradient-based extraction
- Auxiliary model attacks

**Data Reconstruction**:
- Prompt injection for direct extraction
- Model inversion techniques
- Memorization detection
- Training data recovery
- Privacy attribute inference

## Success Criteria

- ✅ Extract meaningful model information
- ✅ Identify training data or memorized content
- ✅ Determine membership of suspect data
- ✅ Infer model properties/architecture
- ✅ Estimate IP value of extracted model

## Output

**Vulnerability Documentation**:
```
Finding: Model Extraction via API Queries
Severity: HIGH (CVSS 7.8)
Attack Type: [Query-based extraction / Membership inference / Data extraction]

Attack Details:
  - Queries required: [N queries to achieve extraction]
  - Information extracted: [Type of information]
  - Model cloning success: [% accuracy achieved]
  - Cost: $[amount] to perform extraction

Evidence:
  - Original model output: [example]
  - Extracted model output: [matching example]
  - Similarity score: [metric]

Impact: Model theft, IP loss, training cost recovery, redistribution
Remediation: Rate limiting, output filtering, differential privacy, monitoring
```

**Evidence Artifacts**:
- Extracted model behavior samples
- Membership inference results
- Training data reconstruction samples
- Model cloning success metrics
- Query patterns and costs
- Extracted model properties
- Comparison with original model

