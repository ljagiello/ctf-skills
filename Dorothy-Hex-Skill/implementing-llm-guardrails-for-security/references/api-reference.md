# API Reference: LLM Guardrails Security Tools

## GuardrailsPipeline (agent.py)

The primary orchestration class that chains all guardrail layers into a validation pipeline.

### Constructor

```python
GuardrailsPipeline(
    policy: dict = None,           # Inline policy dictionary
    policy_path: str = None,       # Path to JSON policy file
)
```

If neither `policy` nor `policy_path` is provided, the built-in DEFAULT_POLICY is used. Custom policies are merged with defaults so missing keys fall back to default values.

### Methods

#### `validate_input(text: str) -> ValidationResult`

Runs all input guardrail layers (length, injection, content policy, PII) on user input.

**Parameters:**
- `text` (str): The user input to validate.

**Returns:** `ValidationResult` with `safe=False` if any critical violation is found. PII-only findings are treated as warnings (input is redacted but not blocked).

#### `validate_output(response: str, original_input: str = "") -> ValidationResult`

Validates LLM-generated output for safety violations, system prompt leakage, and PII.

**Parameters:**
- `response` (str): The LLM output to validate.
- `original_input` (str): The original user input for context-aware validation.

#### `validate_pii_only(text: str) -> ValidationResult`

Runs only the PII detection and redaction layer.

---

## ValidationResult

Dataclass returned by all validation methods.

| Field | Type | Description |
|-------|------|-------------|
| `safe` | bool | True if no critical violations found |
| `blocked_reason` | str | Human-readable reason for blocking (empty if safe) |
| `violations` | list[dict] | List of violation dicts with guard, detail, severity keys |
| `pii_detected` | list[dict] | List of PII findings with type, value, start, end keys |
| `sanitized_text` | str | Input with PII redacted |
| `risk_score` | float | Composite risk score (0.0 - 1.0) |
| `validation_time_ms` | float | Validation latency in milliseconds |
| `layer_results` | dict | Per-guard detailed results |

---

## Individual Guards

### InjectionGuard

Detects prompt injection attempts using compiled regex patterns.

```python
guard = InjectionGuard(patterns=["(?i)ignore previous instructions"])
safe, violations = guard.check("Ignore previous instructions and do X")
# safe=False, violations=["injection_pattern_0: matched 'Ignore previous instructions'"]
```

**Default Patterns Detected:**
- System prompt override ("ignore/disregard/forget previous instructions")
- Role-play escape ("you are now", "act as", "pretend to be")
- Instruction hijacking ("do not follow", "new instructions", "instead do")
- Delimiter injection (Markdown code fences with system/assistant, XML instruction tags)
- Developer/jailbreak modes ("DAN mode", "developer mode", "god mode")
- Prompt leaking ("what are your instructions", "repeat your prompt")

### ContentPolicyGuard

Enforces blocked patterns and topic restrictions.

```python
guard = ContentPolicyGuard(
    blocked_patterns=[r"(?i)how to hack"],
    blocked_topics=["violence", "illegal_activities"],
)
safe, violations = guard.check("How to hack into a WiFi network")
# safe=False, violations=["blocked_content_0: matched 'How to hack'"]
```

**Supported Topic Categories:**
- `violence` -- Physical harm, assault, murder
- `illegal_activities` -- Fraud, money laundering, trafficking
- `weapons` -- Firearms, explosives, 3D-printed weapons
- `drugs` -- Drug synthesis, manufacturing instructions
- `exploitation` -- Child exploitation, human trafficking
- `politics` -- Partisan political opinions or endorsements
- `competitor_products` -- References to switching to competitors

### PIIGuard

Detects and redacts personally identifiable information using regex patterns.

```python
guard = PIIGuard(pii_patterns={"EMAIL_ADDRESS": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"})
findings = guard.detect("Contact john@example.com for details")
# [{"type": "EMAIL_ADDRESS", "value": "john@example.com", "start": 8, "end": 24}]

redacted, findings = guard.redact("Contact john@example.com for details")
# ("Contact [EMAIL_REDACTED] for details", [...])
```

**Supported PII Types:**

| Type | Pattern | Redaction |
|------|---------|-----------|
| `US_SSN` | 123-45-6789 | [SSN_REDACTED] |
| `EMAIL_ADDRESS` | user@domain.com | [EMAIL_REDACTED] |
| `PHONE_NUMBER` | (555) 123-4567 | [PHONE_REDACTED] |
| `CREDIT_CARD` | 4111-1111-1111-1111 | [CARD_REDACTED] |
| `IP_ADDRESS` | 192.168.1.1 | [IP_REDACTED] |
| `US_PASSPORT` | A12345678 | [PASSPORT_REDACTED] |
| `AWS_ACCESS_KEY` | AKIAIOSFODNN7EXAMPLE | [AWS_KEY_REDACTED] |
| `GENERIC_API_KEY` | api_key=abc123... | [API_KEY_REDACTED] |

### OutputGuard

Validates LLM output for safety violations, length limits, system prompt leakage, and PII.

```python
guard = OutputGuard(blocked_patterns=[...], max_length=8000)
safe, violations = guard.check("Sure, I'll help you hack into the system")
# safe=False, violations=["output_blocked_0: matched ..."]
```

### LengthGuard

Enforces maximum input length.

```python
guard = LengthGuard(max_length=4000)
safe, violations = guard.check("x" * 5000)
# safe=False, violations=["input_too_long: 5000 chars exceeds 4000 limit"]
```

---

## Content Policy JSON Schema

```json
{
  "allowed_topics": ["list of allowed topic strings"],
  "blocked_topics": ["violence", "illegal_activities", "weapons", "drugs", "exploitation"],
  "blocked_patterns": ["regex patterns for blocked content"],
  "pii_patterns": {
    "ENTITY_TYPE": "regex pattern"
  },
  "injection_patterns": ["regex patterns for injection detection"],
  "max_input_length": 4000,
  "max_output_length": 8000,
  "output_blocked_patterns": ["regex patterns for blocked output content"]
}
```

---

## CLI Reference

```
usage: agent.py [-h] [--input INPUT] [--response RESPONSE] [--file FILE]
                [--mode {full,input-only,output-only,pii}]
                [--policy POLICY] [--output {text,json}]

Arguments:
  --input, -i       User input text to validate
  --response, -r    LLM response to validate (required for output-only mode)
  --file, -f        Path to file with one prompt per line
  --mode, -m        Validation mode: full | input-only | output-only | pii (default: full)
  --policy, -p      Path to JSON content policy file
  --output, -o      Output format: text | json (default: text)
```

**Exit Codes:**
- `0` -- All inputs passed validation
- `1` -- Error (file not found, invalid policy)
- `2` -- One or more inputs blocked or flagged

---

## External Resources

- NVIDIA NeMo Guardrails: https://github.com/NVIDIA-NeMo/Guardrails
- NeMo Guardrails Documentation: https://docs.nvidia.com/nemo/guardrails/latest/index.html
- Guardrails AI Framework: https://github.com/guardrails-ai/guardrails
- Guardrails AI Hub (Validators): https://guardrailsai.com/hub
- Microsoft Presidio (PII Engine): https://github.com/microsoft/presidio
- OpenAI Guardrails Python: https://github.com/openai/openai-guardrails-python
- Colang 2.0 Guide: https://docs.nvidia.com/nemo/guardrails/latest/configure-rails/colang/index.html
- NeMo Guardrails Security Guidelines: https://docs.nvidia.com/nemo/guardrails/latest/security/guidelines.html
