# Model Extraction Detection — API / Library Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| adversarial-robustness-toolbox | `pip install adversarial-robustness-toolbox` | Extraction, inversion, and membership-inference attacks + defenses |
| scikit-learn | `pip install scikit-learn` | Surrogate / attack model training |
| numpy | `pip install numpy` | Confidence-vector math, perturbation |

## ART Extraction Attacks (`art.attacks.extraction`)

| Class | Key params | Purpose |
|-------|-----------|---------|
| `KnockoffNets` | `nb_stolen`, `batch_size_query`, `nb_epochs`, `sampling_strategy` | Train surrogate from black-box queries (Knockoff Nets) |
| `CopycatCNN` | `nb_stolen`, `batch_size_fit`, `batch_size_query` | Copycat surrogate extraction for neural nets |
| `attack.extract(x, thief_classifier=...)` | — | Run extraction; returns trained surrogate classifier |

## ART Inference Attacks (`art.attacks.inference.membership_inference`)

| Class | Key methods | Purpose |
|-------|-------------|---------|
| `MembershipInferenceBlackBox` | `.fit(...)`, `.infer(x, y)` | Black-box membership inference (AML.T0024.000) |
| `MembershipInferenceBlackBoxRuleBased` | `.infer(x, y)` | Rule-based MIA baseline (no shadow training) |

## ART Defenses (postprocessors)

| Class | Purpose |
|-------|---------|
| `art.defences.postprocessor.ReverseSigmoid` | Perturb output probabilities to hinder extraction |
| `art.defences.postprocessor.Rounded` | Round confidence values to reduce leaked precision |
| `art.defences.postprocessor.HighConfidence` | Suppress low-confidence outputs |

## Estimator Wrappers

| Class | Purpose |
|-------|---------|
| `art.estimators.classification.SklearnClassifier` | Wrap a scikit-learn model as an ART victim |
| `art.estimators.classification.KerasClassifier` / `PyTorchClassifier` | Wrap DL models |

## Detection Signals (custom)

| Signal | Heuristic |
|--------|-----------|
| Query volume | Queries/principal/window above baseline |
| Unique-input ratio | `unique(input_hash)/queries` → ~1.0 |
| Confidence-request ratio | Fraction of calls demanding full probability vectors |

## External References

- ART docs: https://adversarial-robustness-toolbox.readthedocs.io/
- MITRE ATLAS AML.T0024: https://atlas.mitre.org/techniques/AML.T0024
