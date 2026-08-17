# API and Command Reference

## LLM Guard

### Pipeline functions
| Function | Signature | Returns |
|----------|-----------|---------|
| `scan_prompt` | `scan_prompt(scanners, prompt)` | `(sanitized_prompt, results_valid: dict, results_score: dict)` |
| `scan_output` | `scan_output(scanners, prompt, output)` | `(sanitized_output, results_valid: dict, results_score: dict)` |

### Input scanners (15)
`Anonymize`, `BanCode`, `BanCompetitors`, `BanSubstrings`, `BanTopics`, `Code`, `Gibberish`, `InvisibleText`, `Language`, `PromptInjection`, `Regex`, `Secrets`, `Sentiment`, `TokenLimit`, `Toxicity`

### Output scanners (20)
`BanCode`, `BanCompetitors`, `BanSubstrings`, `BanTopics`, `Bias`, `Code`, `Deanonymize`, `JSON`, `Language`, `LanguageSame`, `MaliciousURLs`, `NoRefusal`, `ReadingTime`, `FactualConsistency`, `Gibberish`, `Regex`, `Relevance`, `Sensitive`, `Sentiment`, `Toxicity`, `URLReachability`

### Common scanner parameters
| Scanner | Key params |
|---------|-----------|
| `PromptInjection` | `threshold=0.5`, `match_type=MatchType.FULL\|SENTENCE` |
| `Toxicity` | `threshold=0.5` |
| `Secrets` | `redact_mode="all"\|"partial"\|"hash"` |
| `Anonymize` | `vault`, `entity_types`, `hidden_names` |
| `Sensitive` | `entity_types`, `redact=True` |
| `TokenLimit` | `limit=4096`, `encoding_name="cl100k_base"` |

## Llama Guard 3 (transformers)

| Operation | Call |
|-----------|------|
| Load tokenizer | `AutoTokenizer.from_pretrained("meta-llama/Llama-Guard-3-8B")` |
| Load model | `AutoModelForCausalLM.from_pretrained(model_id, torch_dtype=torch.bfloat16, device_map="auto")` |
| Build prompt | `tokenizer.apply_chat_template(chat, return_tensors="pt")` |
| Classify | `model.generate(input_ids=..., max_new_tokens=100, pad_token_id=0)` |
| Output | `safe` OR `unsafe\nS<n>` where S1–S14 are MLCommons categories |

Role of last message determines mode: last turn `user` = prompt classification; last turn `assistant` = response classification.

## NeMo Guardrails

### Config structure
```
config/
  config.yml      # models, rails, prompts
  *.co            # Colang flows (dialog/input/output rails)
  actions.py      # optional custom Python actions
```

### config.yml key sections
| Section | Purpose |
|---------|---------|
| `models:` | list of `{type, engine, model}`; `type: main` is the app LLM, `type: content_safety` for Llama Guard |
| `rails.input.flows` | input-stage flows e.g. `self check input`, `content safety check input $model=content_safety` |
| `rails.output.flows` | output-stage flows e.g. `self check output` |
| `prompts:` | task templates (`self_check_input`, `self_check_output`) |

### Python API
| Call | Purpose |
|------|---------|
| `RailsConfig.from_path("./config")` | Load configuration |
| `LLMRails(config)` | Instantiate rails engine |
| `rails.generate(messages=[...])` | Run input rails → LLM → output rails |
| `rails.generate_async(...)` | Async variant |

### CLI
| Command | Purpose |
|---------|---------|
| `nemoguardrails chat --config=./config` | Interactive chat with rails applied |
| `nemoguardrails server --config=./config` | Start REST server |
