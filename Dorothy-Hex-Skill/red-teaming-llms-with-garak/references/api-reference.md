# garak CLI Reference

Source: https://github.com/NVIDIA/garak and https://reference.garak.ai/en/latest/cliref.html

## Invocation

```bash
python -m garak <options>
# or the console script
garak <options>
```

## Core flags

| Flag | Description | Example |
|------|-------------|---------|
| `--target_type` (alias `--model_type`) | Generator family / interface | `--target_type openai` |
| `--target_name` (alias `--model_name`) | Specific model name | `--target_name gpt-4o-mini` |
| `--probes`, `-p` | Comma-separated probe spec; module or `module.Class` | `--probes promptinject,dan.Dan_11_0` |
| `--detectors`, `-d` | Override detectors | `--detectors mitigation.MitigationBypass` |
| `--generations`, `-g` | Completions generated per prompt | `--generations 5` |
| `--parallel_attempts` | Parallel probe attempts (throughput) | `--parallel_attempts 8` |
| `--report_prefix` | Prefix for output report files | `--report_prefix baseline` |
| `--config` | Load a YAML/JSON run config | `--config assessment.yaml` |
| `-G` / `--generator_option_file` | JSON file with generator options (REST etc.) | `-G rest.json` |
| `--generator_options` | Inline JSON generator options | |
| `--list_probes` | Print all probes and exit | |
| `--list_detectors` | Print all detectors and exit | |
| `--list_generators` | Print all generator types and exit | |
| `--list_buffs` | Print prompt-mutating buffs | |
| `--version` | Print version | |
| `--verbose`, `-v` | Increase logging | |

## Common target_type values

| Value | Target |
|-------|--------|
| `huggingface` | Local Hugging Face model |
| `openai` | OpenAI / OpenAI-compatible API (uses `OPENAI_API_KEY`) |
| `rest` | Arbitrary HTTP endpoint via JSON spec |
| `ggml` / `nim` / `replicate` / `cohere` / `bedrock` | Other hosted/local backends |

## REST generator JSON spec keys

| Key | Meaning |
|-----|---------|
| `uri` | Endpoint URL |
| `method` | HTTP method (`post`) |
| `headers` | Request headers (supports `$ENV_VAR`) |
| `req_template_json_object` | Request body with `$INPUT` placeholder |
| `response_json` | `true` if response is JSON |
| `response_json_field` | JSONPath to extract the model output |

## Output artifacts

| File | Content |
|------|---------|
| `<prefix>.report.jsonl` | Line-delimited record of every attempt, generation, and detector verdict |
| `<prefix>.report.html` | Human-readable scorecard |
| `<prefix>.hitlog.jsonl` | Confirmed successful attacks (evidence) |
| `garak.log` | Debug log |

## Example runs

```bash
# Enumerate
garak --list_probes

# Local HF model, single jailbreak probe
python -m garak --target_type huggingface --target_name gpt2 --probes dan.Dan_11_0

# Hosted API, injection + leakage suite
export OPENAI_API_KEY="sk-..."
python -m garak --target_type openai --target_name gpt-4o-mini \
  --probes promptinject,latentinjection,leakreplay \
  --generations 5 --parallel_attempts 8 --report_prefix assessment

# Arbitrary REST endpoint
python -m garak --target_type rest -G rest.json --probes promptinject,dan
```
