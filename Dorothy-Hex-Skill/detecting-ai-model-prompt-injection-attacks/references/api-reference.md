# API Reference: Prompt Injection Detection Tools

## PromptInjectionDetector (agent.py)

The primary detection class combining three layers of prompt injection analysis.

### Constructor

```python
PromptInjectionDetector(
    mode: str = "full",       # "regex", "heuristic", or "full"
    threshold: float = 0.85,  # Classifier confidence threshold (0.0-1.0)
    device: str = "cpu",      # "cpu" or "cuda" for GPU inference
)
```

### Methods

#### `analyze(text: str) -> DetectionResult`

Runs the configured detection layers against the input text and returns a structured result.

**Parameters:**
- `text` (str): The user prompt to analyze for injection attempts.

**Returns:** `DetectionResult` dataclass with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `input_text` | str | The original input text |
| `injection_detected` | bool | Final boolean verdict |
| `composite_score` | float | Weighted score from all active layers (0.0 - 1.0) |
| `regex_matches` | list[str] | Names of matched regex patterns |
| `regex_score` | float | Regex layer score (0.0 - 1.0) |
| `heuristic_score` | float | Heuristic layer score (0.0 - 1.0) |
| `classifier_score` | float | DeBERTa classifier injection probability (0.0 - 1.0) |
| `classifier_label` | str | "INJECTION", "SAFE", "SKIPPED", or "ERROR" |
| `detection_time_ms` | float | Total detection time in milliseconds |
| `layer_details` | dict | Detailed breakdown from each layer |

---

## RegexDetector

Fast pattern-matching layer using compiled regular expressions.

### `scan(text: str) -> tuple[float, list[str]]`

Scans input against 20+ compiled regex patterns for known injection signatures.

**Returns:** Tuple of (score, matched_pattern_names). Score is min(1.0, match_count * 0.25).

**Pattern Categories:**
- `system_prompt_override` -- "ignore previous instructions" and variants
- `role_play_escape` -- "you are now", "act as", "pretend to be"
- `instruction_hijack` -- "do not follow", "new instructions", "instead do"
- `delimiter_escape` -- Markdown code fences with system/assistant roles, XML instruction tags
- `data_exfiltration` -- Attempts to extract system prompts, keys, credentials
- `encoding_obfuscation` -- Base64/ROT13/hex encoding references
- `sql_injection_via_prompt` -- SQL payloads embedded in prompts
- `command_injection_via_prompt` -- Shell command payloads
- `developer_mode` -- "DAN mode", "developer mode", "god mode"
- `prompt_leaking` -- "what are your instructions", "repeat your prompt"
- `token_smuggling` -- Zero-width Unicode characters and control characters
- `base64_payload` -- Long Base64-encoded strings that may contain hidden instructions

---

## HeuristicScorer

Structural anomaly detection using weighted feature analysis.

### `score(text: str) -> tuple[float, dict]`

Computes an anomaly score from seven structural features.

**Features and Weights:**

| Feature | Weight | Description |
|---------|--------|-------------|
| `instruction_density` | 0.30 | Ratio of instruction keywords to total words |
| `special_char_ratio` | 0.10 | Ratio of non-alphanumeric characters |
| `delimiter_presence` | 0.15 | Count of delimiter sequences (```, ---, ###) |
| `capitalization_ratio` | 0.10 | Proportion of uppercase alphabetic characters |
| `line_structure_anomaly` | 0.10 | Many short lines indicating structured payloads |
| `unicode_anomaly` | 0.15 | Zero-width and control character presence |
| `repetition_score` | 0.10 | Low unique-word ratio indicating repetitive overrides |

---

## ClassifierDetector

Transformer-based binary classifier using ProtectAI's DeBERTa-v3 model.

### Constructor

```python
ClassifierDetector(
    threshold: float = 0.85,  # Confidence threshold for INJECTION label
    device: str = "cpu",      # Inference device
)
```

### `predict(text: str) -> tuple[float, str]`

Runs the DeBERTa model on the input (truncated to 512 tokens) and returns the injection probability and label.

**Model Details:**
- **Model**: `protectai/deberta-v3-base-prompt-injection-v2`
- **Architecture**: microsoft/deberta-v3-base fine-tuned for binary classification
- **Labels**: INJECTION (class 1) / SAFE (class 0)
- **Max Input Length**: 512 tokens
- **Accuracy**: 99.1% on holdout test set
- **Size**: ~700 MB (downloaded from Hugging Face Hub on first use)

---

## CLI Reference

```
usage: agent.py [-h] [--input INPUT] [--file FILE]
                [--mode {regex,heuristic,full}]
                [--threshold THRESHOLD]
                [--output {text,json}]
                [--device {cpu,cuda}]

Arguments:
  --input, -i      Single prompt string to analyze
  --file, -f       Path to file with one prompt per line
  --mode, -m       Detection mode: regex | heuristic | full (default: full)
  --threshold, -t  Classifier confidence threshold (default: 0.85)
  --output, -o     Output format: text | json (default: text)
  --device         Inference device: cpu | cuda (default: cpu)
```

**Exit Codes:**
- `0` -- No injections detected
- `1` -- Error (file not found, model load failure)
- `2` -- One or more injections detected

---

## External Resources

- OWASP LLM01:2025 Prompt Injection: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- OWASP Prompt Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html
- ProtectAI DeBERTa Model: https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2
- Deepset Prompt Injection Dataset: https://huggingface.co/datasets/deepset/prompt-injections
- Rebuff Framework: https://github.com/protectai/rebuff
- Simon Willison's Prompt Injection Tag: https://simonwillison.net/tags/prompt-injection/
- Meta Prompt Guard 86M: https://huggingface.co/meta-llama/Prompt-Guard-86M
